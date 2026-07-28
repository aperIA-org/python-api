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
    t3_result = tier3_scan_worker.run_tier3_scan.run(
        target_url=target_url,
        t2_findings=t2_findings,
        commit_sha=commit_sha,
        repo_url=repo_url,
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
    pr_number: int,
    installation_id: int,
    repo_full_name: str,
    repo_path: str,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    target_url: str | None = None,
) -> chain:
    """Monta a Celery ``chain`` do pipeline completo.

    Não dispara — apenas retorna o canvas. O caller usa
    ``canvas.delay()`` ou ``canvas.apply_async()`` para iniciar.
    """
    tier1_group = group(
        tier1_scan_worker.run_trufflehog.s(
            repo_path=repo_path,
            base_sha=base_sha,
            head_sha=head_sha,
            commit_sha=commit_sha,
            repo_url=repo_url,
        ),
        tier1_scan_worker.run_semgrep_changed.s(
            repo_path=repo_path,
            changed_files=changed_files,
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
            repo_path=repo_path,
            changed_files=changed_files,
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
    repo_path: str,
    changed_files: list[str],
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
        repo_path=repo_path,
        changed_files=changed_files,
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
    pr_number: int,
    installation_id: int,
    repo_full_name: str,
    repo_path: str,
    base_sha: str,
    head_sha: str,
    changed_files: list[str],
    target_url: str | None = None,
) -> Any:
    """Entry point chamado pelo webhook.

    Retorna o ``AsyncResult`` do canvas — útil em testes para
    inspecionar state. Em produção o webhook ignora o retorno.
    """
    # Projeção consumível via API (GET /scans): cria o ScanJob com o Tier 1
    # já em "running". Best-effort — falha de banco não impede o pipeline.
    from app.infrastructure.persistence import scan_job_writer

    scan_job_writer.create_scan_job(
        commit_sha=commit_sha,
        repo_url=repo_url,
        installation_id=installation_id,
        pr_number=pr_number,
        repo_full_name=repo_full_name,
    )

    canvas = build_pipeline_canvas(
        commit_sha=commit_sha,
        repo_url=repo_url,
        pr_number=pr_number,
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        repo_path=repo_path,
        base_sha=base_sha,
        head_sha=head_sha,
        changed_files=changed_files,
        target_url=target_url,
    )
    logger.info(
        "pipeline_dispatched",
        commit_sha=commit_sha,
        pr_number=pr_number,
        repo=repo_full_name,
    )
    return canvas.apply_async()
