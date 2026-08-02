"""Pipeline orchestrator — monta o canvas Celery completo.

Sequência (decisão #1 Semana 12):

    group(tier1: trufflehog + semgrep_changed)
      → gate1_check         (Ignore se secret verificado)
      → _bridge_t1_into_gate1_output  ← helper: combina T1 findings com identidade da PR
      → run_tier2_scan      (Trivy + Semgrep expanded + Prowler condicional)
      → _bridge_t1t2        ← helper: une T1+T2 findings + injeta commit_sha em tier2_analyze
      → tier2_analyze       (Claude Sonnet — chain_of_events)
      → post_tier2_report   (Haiku — markdown; retorna analysis com _post_meta)
      → tier3_gate          (Ignore se severidade < high)
      → _bridge_to_t3_scan  ← helper: dispara tier3_scan_worker com cve_ids/target_url
      → run_tier3_scan      (ZAP + OpenCTI + Caldera)
      → _bridge_t2_t3       ← helper: combina dados T2 com payload T3 para deep_analysis
      → tier3_deep_analysis (Claude Sonnet — attack_path)
      → post_tier3_deep_report (Haiku — markdown final)

Por que helpers explícitos: o Celery canvas passa o resultado da
task anterior como **primeiro argumento posicional** da próxima.
Para misturar com argumentos fixos (`commit_sha`, `repo_full_name`,
etc.) usamos ``.s(kw=...)``. Quando precisamos COMBINAR o resultado
da task anterior com state acumulado, criamos helpers — tasks
internas mínimas no ``orchestrator`` que fazem essa combinação.

Idempotência: nenhuma task da chain modifica side state sem que o
caller possa replay. ``acks_late=True`` (config global) garante
re-execução em caso de crash.
"""
from __future__ import annotations

import re
from typing import Any

import structlog
from celery import chain, group

from app.core.celery_app import celery_app
from app.presentation.workers import (
    analysis_worker,
    reporting_worker,
    tier1_scan_worker,
    tier2_scan_worker,
    tier3_scan_worker,
)

logger = structlog.get_logger()


# ---------------------------------------------------------------- bridges
#
# Tasks internas do orquestrador que combinam o resultado da task
# anterior com state contextual (commit_sha, repo info, etc.). Cada
# uma é JSON-serializável e idempotente.


#: `T1059` ou `T1059.007`. O valor vem de um LLM, então extrair com regex em vez
#: de confiar no formato: `"T1059 - Command and Scripting"` era aceito inteiro e
#: não casava com ability nenhuma — zero abilities sem nenhum erro visível.
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _id_mitre(valor: Any) -> str | None:
    achado = _MITRE_ID.search(str(valor or "").upper())
    return achado.group(0) if achado else None


def _tecnicas_da_cadeia(tier2_analysis: dict[str, Any]) -> list[str]:
    """Extrai os IDs MITRE do `event_chain`, sem repetir e na ordem dos passos.

    O schema do Tier 2 define `technique` como opcional, então passos sem
    técnica identificada são normais e simplesmente não entram.

    Preferimos sempre a técnica MAIS específica: é ela que descreve o achado, e
    é contra ela que `caldera_validated` faz sentido. O `technique_parent` só
    entra como resgate, quando `technique` vem vazia ou ilegível — ele **não** é
    somado à lista, porque pedir o pai explicitamente faria o casamento parecer
    exato e apagaria a distinção entre "emulei o seu problema" e "emulei um
    parente dele" (ver `MapeamentoAbilities`).
    """
    tecnicas: list[str] = []
    for passo in tier2_analysis.get("event_chain", []) or []:
        if not isinstance(passo, dict):
            continue
        tecnica = _id_mitre(passo.get("technique")) or _id_mitre(
            passo.get("technique_parent")
        )
        if tecnica and tecnica not in tecnicas:
            tecnicas.append(tecnica)
    return tecnicas


@celery_app.task(
    name="app.core.orchestrator._prepare_tier3_payload",
    bind=True,
    queue="tier3",
)
def _prepare_tier3_payload(
    self,
    tier2_analysis: dict[str, Any] | None,
    *,
    target_url: str | None,
    commit_sha: str,
    repo_url: str,
) -> dict[str, Any] | None:
    """Bridge entre tier3_gate (escalou — passou analysis adiante) e
    run_tier3_scan. Roda o tier3 scan e devolve dict combinado para o
    deep_analysis.

    Em chains Celery eager, ``Ignore`` levantado por tasks anteriores
    NÃO interrompe a chain automaticamente — recebemos ``None`` como
    primeiro argumento. Cada bridge propaga essa interrupção
    retornando ``None`` quando ``tier2_analysis`` é falsy, evitando
    side effects downstream.

    Importante: ``tier3_scan_worker.run_tier3_scan`` lê
    ``t2_findings`` para descobrir CVEs distintas — passamos
    ``tier2_analysis["findings"]`` aqui.
    """
    if not tier2_analysis or not isinstance(tier2_analysis, dict):
        return None
    t2_findings = tier2_analysis.get("findings", []) or []

    # As técnicas MITRE da cadeia de ataque do Tier 2 são a fonte primária para
    # a emulação. Antes o Tier 3 só conhecia as técnicas vindas do
    # enriquecimento CTI — que depende do OpenCTI (fora do ar) e de haver CVEs
    # nos findings. Sem CVE e sem CTI, `mitre_techniques` era SEMPRE vazio: o
    # Caldera recebia um adversário sem abilities e não executava nada.
    #
    # O Tier 2 já mapeia MITRE ATT&CK em cada passo do `event_chain` — é
    # literalmente a correlação que o produto promete. Ignorá-la e depender de
    # uma fonte externa opcional era desperdiçar o dado mais relevante.
    tecnicas_do_tier2 = _tecnicas_da_cadeia(tier2_analysis)

    t3_result = tier3_scan_worker.run_tier3_scan.run(
        target_url=target_url,
        t2_findings=t2_findings,
        commit_sha=commit_sha,
        repo_url=repo_url,
        mitre_techniques=tecnicas_do_tier2,
    )
    return {
        "tier2_analysis": tier2_analysis,
        "tier3_scan": t3_result,
    }


@celery_app.task(
    name="app.core.orchestrator._deep_analysis_bridge",
    bind=True,
    queue="analysis",
)
def _deep_analysis_bridge(
    self,
    combined: dict[str, Any] | None,
    *,
    commit_sha: str,
) -> dict[str, Any] | None:
    """Chama ``tier3_deep_analysis`` com o payload combinado T2+T3.

    Usamos um bridge porque ``tier3_deep_analysis`` precisa do scan
    T3 como primeiro arg + ``tier2_analysis`` como kwarg — o canvas
    Celery não permite mapear o output anterior em múltiplas slots.

    ``None`` (propagação de Ignore upstream) → no-op.
    """
    if not combined or not isinstance(combined, dict):
        return None
    return analysis_worker.tier3_deep_analysis.run(
        combined["tier3_scan"],
        commit_sha=commit_sha,
        tier2_analysis=combined["tier2_analysis"],
    )


# ---------------------------------------------------------------- canvas


def build_pipeline_canvas(
    *,
    commit_sha: str,
    repo_url: str,
    pr_number: int | None,
    installation_id: int,
    repo_full_name: str,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    target_url: str | None = None,
) -> chain:
    """Monta a Celery ``chain`` do pipeline completo.

    Não dispara — apenas retorna o canvas. O caller usa
    ``canvas.delay()`` ou ``canvas.apply_async()`` para iniciar.

    ``pr_number=None`` é um scan de branch (manual): o canvas é idêntico, só
    não há PR onde comentar — os workers de report pulam o post e mantêm o
    relatório apenas na projeção consumível via API.

    O canvas **não** carrega ``repo_path``: cada task que precisa dos arquivos
    faz o próprio checkout efêmero a partir de ``repo_full_name`` +
    ``commit_sha`` + ``installation_id``, porque os workers de T1 e T2 rodam em
    containers sem filesystem comum (ver ``infrastructure/git/repo_checkout``).
    """
    tier1_group = group(
        tier1_scan_worker.run_trufflehog.s(
            repo_full_name=repo_full_name,
            installation_id=installation_id,
            base_sha=base_sha,
            head_sha=head_sha,
            commit_sha=commit_sha,
            repo_url=repo_url,
        ),
        tier1_scan_worker.run_semgrep_changed.s(
            repo_full_name=repo_full_name,
            installation_id=installation_id,
            changed_files=changed_files,
            base_sha=base_sha,
            commit_sha=commit_sha,
            repo_url=repo_url,
        ),
    )

    # gate1_check recebe a lista de listas do group e retorna
    # {"findings": [...], "blocked": False} (ou raise Ignore).
    pipeline = chain(
        tier1_group
        | analysis_worker.gate1_check.s(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            commit_sha=commit_sha,
            installation_id=installation_id,
        )
        # Gate1 passou — agora roda Tier 2 (Trivy + Semgrep expanded + Prowler)
        | _t1_to_t2_scan_bridge.s(
            repo_full_name=repo_full_name,
            installation_id=installation_id,
            changed_files=changed_files,
            base_sha=base_sha,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
        # tier2_analyze precisa de gate1_output como pos arg → bridge.
        | _bridge_t1_findings_into_analyze.s(commit_sha=commit_sha)
        | reporting_worker.post_tier2_report.s(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            commit_sha=commit_sha,
            installation_id=installation_id,
        )
        | analysis_worker.tier3_gate.s()
        | _prepare_tier3_payload.s(
            target_url=target_url,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
        | _deep_analysis_bridge.s(commit_sha=commit_sha)
        | reporting_worker.post_tier3_deep_report.s(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            commit_sha=commit_sha,
            installation_id=installation_id,
        )
    )
    return pipeline


# Bridges adicionais que dependem dos workers já definidos acima
# (declarados aqui para manter a ordem de imports clara).


@celery_app.task(
    name="app.core.orchestrator._t1_to_t2_scan_bridge",
    bind=True,
    queue="tier2",
)
def _t1_to_t2_scan_bridge(
    self,
    gate1_output: dict[str, Any] | None,
    *,
    repo_full_name: str,
    installation_id: int,
    changed_files: list[str],
    base_sha: str,
    commit_sha: str,
    repo_url: str,
) -> dict[str, Any] | None:
    """Recebe ``gate1_output``, dispara T2 scan, devolve dict com
    findings combinados de T1 + T2 para o ``tier2_analyze``.

    Quando Gate 1 bloqueou (raise Ignore), ``gate1_output`` chega
    como ``None`` em modo eager. Propagamos a interrupção
    retornando ``None`` — bridges downstream também são defensivos.
    """
    if not gate1_output or not isinstance(gate1_output, dict):
        return None
    t1_findings = gate1_output.get("findings", []) or []
    t2_findings = tier2_scan_worker.run_tier2_scan.run(
        repo_full_name=repo_full_name,
        installation_id=installation_id,
        changed_files=changed_files,
        base_sha=base_sha,
        commit_sha=commit_sha,
        repo_url=repo_url,
    )
    return {"t1_findings": t1_findings, "t2_findings": t2_findings}


@celery_app.task(
    name="app.core.orchestrator._bridge_t1_findings_into_analyze",
    bind=True,
    queue="analysis",
)
def _bridge_t1_findings_into_analyze(
    self,
    scan_state: dict[str, Any] | None,
    *,
    commit_sha: str,
) -> dict[str, Any] | None:
    """Combina findings T1+T2 e chama ``tier2_analyze``.

    ``None`` (propagação de Ignore) → no-op.
    """
    if not scan_state or not isinstance(scan_state, dict):
        return None
    combined = (scan_state.get("t1_findings") or []) + (
        scan_state.get("t2_findings") or []
    )
    return analysis_worker.tier2_analyze.run(
        {"findings": combined},
        commit_sha=commit_sha,
    )


# ---------------------------------------------------------------- entrada


def start_pipeline(
    *,
    commit_sha: str,
    repo_url: str,
    pr_number: int | None,
    installation_id: int,
    repo_full_name: str,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    target_url: str | None = None,
    user_id: Any = None,
    repository_id: Any = None,
) -> Any:
    """Entry point chamado pelo webhook.

    Retorna o ``AsyncResult`` do canvas — útil em testes para
    inspecionar state. Em produção o webhook ignora o retorno.
    """
    from app.core.exceptions import ScanDispatchError
    from app.infrastructure.persistence import scan_job_writer

    # ORDEM IMPORTA. O canvas é montado ANTES de a linha do ``ScanJob`` existir.
    #
    # Era o contrário, e o resultado aparecia direto na cara do usuário: o
    # canvas estourava (chord sem result backend), a API devolvia 500 dizendo
    # "não foi possível iniciar o scan", e o scan aparecia no dashboard "em
    # execução" — porque a linha já tinha sido gravada pelo passo anterior.
    # Erro e evidência se contradiziam.
    #
    # Montar primeiro faz a falha acontecer enquanto ainda não há nada para
    # desfazer: nenhuma linha é criada, e o dashboard não mostra um scan que
    # nunca foi enfileirado.
    canvas = build_pipeline_canvas(
        commit_sha=commit_sha,
        repo_url=repo_url,
        pr_number=pr_number,
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        base_sha=base_sha,
        head_sha=head_sha,
        changed_files=changed_files,
        target_url=target_url,
    )

    # Projeção consumível via API (GET /scans): cria o ScanJob com o Tier 1
    # já em "running". Best-effort — falha de banco não impede o pipeline.
    scan_job_writer.create_scan_job(
        commit_sha=commit_sha,
        repo_url=repo_url,
        installation_id=installation_id,
        pr_number=pr_number,
        repo_full_name=repo_full_name,
        user_id=user_id,
        repository_id=repository_id,
    )

    try:
        resultado = canvas.apply_async()
    except Exception as exc:
        # A linha já existe neste ponto. Deixá-la ``running`` recriaria o
        # órfão: nada a concluiria, e a guarda de concorrência bloquearia
        # aquele commit com 409 até a varredura de jobs travados.
        logger.error(
            "pipeline_dispatch_falhou",
            commit_sha=commit_sha,
            repo=repo_full_name,
            error=str(exc),
        )
        scan_job_writer.fail_pending_tiers(commit_sha, motivo=f"dispatch: {exc}")
        raise ScanDispatchError(
            f"nao foi possivel enfileirar o pipeline do commit {commit_sha}: {exc}"
        ) from exc

    logger.info(
        "pipeline_dispatched",
        commit_sha=commit_sha,
        pr_number=pr_number,
        repo=repo_full_name,
    )
    return resultado
