"""Worker de análise — Gate 1 + análise Claude no Tier 2.

Gate 1:
- Recebe a lista agregada de findings T1.
- Se houver ``secret_verified=True``, sinaliza bloqueio do PR
  (status check ``failure`` + comment) e levanta ``Ignore`` para
  interromper o chain Celery — Tier 2 e Tier 3 não rodam.
- Zero chamadas Claude — economia de token + latência.

Tier 2 análise:
- Constrói o user prompt via ``chain_of_events.build()`` com dados
  CTI / Caldera opcionais (vazios na Semana 6).
- Chama ``ClaudeClient.call_json`` com modelo ``REASONING``.
- Trata ``CircuitOpenError`` / ``GuardBlockedError`` retornando o
  payload bruto (modo degradado) — pipeline continua.
"""
from __future__ import annotations

from typing import Any

import structlog
from celery.exceptions import Ignore

from app.core.celery_app import celery_app
from app.domain.finding import validation
from app.infrastructure.ai import prompts
from app.infrastructure.ai.claude_client import (
    CircuitOpenError,
    ClaudeClient,
    ClaudeClientError,
    GuardBlockedError,
)
from app.infrastructure.ai.models import REASONING
from app.infrastructure.git.github_client import GitHubClient
from app.infrastructure.persistence import scan_job_writer

logger = structlog.get_logger()


def _has_verified_secret(findings: list[dict[str, Any]]) -> bool:
    return any(f.get("secret_verified") is True for f in findings)


@celery_app.task(
    name="app.presentation.workers.analysis_worker.gate1_check",
    bind=True,
    queue="analysis",
)
def gate1_check(
    self,
    tier1_results: list[list[dict[str, Any]]],
    *,
    repo_full_name: str,
    pr_number: int | None,
    commit_sha: str,
    installation_id: int,
) -> dict[str, Any]:
    """Avalia o Gate 1 e bloqueia o PR se há secret verificado.

    ``tier1_results`` é uma lista de listas (uma por worker T1).

    ``pr_number=None`` (scan manual de branch): o status check no commit
    continua sendo criado; só o comentário no PR é pulado.
    """
    flattened: list[dict[str, Any]] = [
        item for sub in tier1_results for item in sub
    ]
    if _has_verified_secret(flattened):
        logger.warning(
            "gate1_blocked_secret_verified",
            commit_sha=commit_sha,
            findings_count=len(flattened),
        )
        try:
            client = GitHubClient(installation_id=installation_id)
            client.create_status_check(
                repo_full_name=repo_full_name,
                commit_sha=commit_sha,
                state="failure",
                description="aperIA: secret verificado detectado — PR bloqueado",
            )
            if pr_number is not None:
                client.post_pr_comment(
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                    body=(
                        "## 🚨 aperIA — Gate 1 bloqueou este PR\n\n"
                        "Foi detectada credencial **verificada** no commit. "
                        "Rote a credencial imediatamente e remova do histórico "
                        "antes de prosseguir."
                    ),
                )
        except Exception as exc:  # noqa: BLE001 — não derrubar pipeline por erro de GitHub
            logger.warning(
                "gate1_github_post_failed",
                commit_sha=commit_sha,
                error=str(exc),
            )
        # Registra o bloqueio na projeção do scan (best-effort). Tier 2 e
        # Tier 3 nunca vão rodar para este commit — gravamos "skipped" em vez
        # de deixar NULL, que na API/dashboard é indistinguível de "ainda não
        # chegou nesse tier".
        scan_job_writer.mark_tier(commit_sha, 1, "done")
        scan_job_writer.mark_blocked(commit_sha, 1)
        scan_job_writer.mark_tier_skipped(commit_sha, 2)
        scan_job_writer.mark_tier_skipped(commit_sha, 3)
        # Interrompe o chain Celery — Tier 2 e Tier 3 não rodam.
        raise Ignore()

    logger.info(
        "gate1_passed",
        commit_sha=commit_sha,
        findings_count=len(flattened),
    )
    scan_job_writer.mark_tier(commit_sha, 1, "done")
    return {"findings": flattened, "blocked": False}


@celery_app.task(
    name="app.presentation.workers.analysis_worker.tier2_analyze",
    bind=True,
    queue="analysis",
)
def tier2_analyze(
    self,
    gate1_output: dict[str, Any],
    *,
    commit_sha: str,
    cti_data: dict | None = None,
    caldera_results: dict | None = None,
) -> dict[str, Any]:
    findings = gate1_output.get("findings", [])
    scan_job_writer.mark_tier(commit_sha, 2, "running")
    user_prompt = prompts.chain_of_events.build(
        findings=findings,
        cti_data=cti_data,
        caldera_results=caldera_results,
        context={"commit": commit_sha},
    )

    # Constrói o client aqui (em vez de aceitar como arg) porque tasks
    # Celery só recebem args JSON-serializáveis. Testes mockam via
    # ``patch("...analysis_worker.ClaudeClient")``.
    client = ClaudeClient()
    try:
        analysis = client.call_json(
            system=prompts.chain_of_events.SYSTEM,
            user=user_prompt,
            model=REASONING,
            commit_sha=commit_sha,
        )
    except (CircuitOpenError, GuardBlockedError, ClaudeClientError) as exc:
        logger.warning(
            "tier2_analysis_degraded",
            commit_sha=commit_sha,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        # Modo degradado: retorna findings brutos sem narrativa.
        scan_job_writer.mark_tier(commit_sha, 2, "done")
        return {
            "degraded": True,
            "reason": type(exc).__name__,
            # Identidade do scan viaja no payload — ver comentário no
            # caminho normal, logo abaixo.
            "commit_sha": commit_sha,
            "findings": findings,
            "cti_status": "available" if cti_data else "unavailable",
            "caldera_status": "available" if caldera_results else "unavailable",
        }

    analysis.setdefault("cti_status", "available" if cti_data else "unavailable")
    analysis.setdefault(
        "caldera_status", "available" if caldera_results else "unavailable"
    )
    analysis["degraded"] = False
    analysis["findings"] = findings
    # A identidade do scan viaja NO PAYLOAD, não só nos kwargs do canvas: o
    # ``tier3_gate`` recebe apenas o resultado da task anterior (primeiro arg
    # posicional) e precisa do commit para logar e persistir a decisão. Ler o
    # commit de dentro dos findings não serve — com 0 findings (caso mais
    # comum hoje) não há de onde ler.
    analysis["commit_sha"] = commit_sha
    scan_job_writer.mark_tier(commit_sha, 2, "done")
    scan_job_writer.set_final_risk_from_analysis(commit_sha, analysis)
    return analysis


# Severities que escalam o pipeline para Tier 3. Decisão da Semana 9:
# HIGH + CRITICAL escalam; INFO + LOW + MEDIUM encerram em T2.
# Embora MEDIUM seja um "meio termo", o guia explicitamente diz
# "high ou critical" — manter o threshold conservador para custo.
_TIER3_ESCALATION_SEVERITIES = {"high", "critical"}


def _nivel_de_risco(analysis: dict[str, Any]) -> str:
    """Nível agregado calculado pelo Tier 2 (``"info"`` se ausente).

    Aceita os dois shapes usados no pipeline: ``risk_score_adjusted`` (Tier 3)
    tem precedência sobre ``risk_score`` (Tier 2), mesma ordem que
    ``scan_job_writer`` usa para gravar ``final_risk_level`` — as duas leituras
    precisam concordar, senão o dashboard mostraria um nível e o gate teria
    decidido por outro.
    """
    risco = analysis.get("risk_score_adjusted") or analysis.get("risk_score") or {}
    if not isinstance(risco, dict):
        return "info"
    return str(risco.get("level") or "info").lower()


def _max_severity(findings: list[dict[str, Any]]) -> str:
    """Maior severidade ponderada na lista de findings.

    Retorna a string lowercase ("critical" | "high" | "medium" | "low"
    | "info"). Findings sem severidade conhecida contam como "info".
    """
    rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    if not findings:
        return "info"
    return max(
        (str(f.get("severity", "info")).lower() for f in findings),
        key=lambda s: rank.get(s, 0),
    )


@celery_app.task(
    name="app.presentation.workers.analysis_worker.tier3_gate",
    bind=True,
    queue="analysis",
)
def tier3_gate(
    self,
    analysis: dict[str, Any],
    *,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    """Gate 2 — decide se o pipeline escala para Tier 3.

    Escala se **qualquer** um dos dois critérios valer:

    1. ``high``/``critical`` em algum finding — um problema grave isolado;
    2. ``high``/``critical`` no **risco agregado** do Tier 2
       (``risk_score.level``) — o conjunto é grave mesmo sem nenhum item
       individualmente grave.

    O critério 2 foi acrescentado depois: sozinho, o 1 ignora volume e
    correlação, que é exatamente o que o Tier 2 calcula. O caso que expôs a
    lacuna foram 57 possíveis secrets num repositório, todos ``medium``
    individualmente, somando risco ``high`` (74/100) — o pipeline descartava a
    análise profunda justamente onde ela seria mais útil.

    Escalando, retorna o ``analysis`` inalterado para a próxima task no chain.
    O log registra qual critério disparou: severidade aponta para UM finding,
    risco agregado aponta para o conjunto — investigações diferentes.

    - Nenhum dos dois → ``raise Ignore()`` para interromper o chain
      sem executar Tier 3. Decisão explícita: **não retornar dict
      de skip** — o Celery não deve passar adiante quando o Gate
      decide encerrar. Antes do ``Ignore``, a decisão é gravada na
      projeção (``tier3_status = 'skipped'``).

    Quando ``analysis`` é ``None`` (Gate 1 raised Ignore antes), o
    Gate 2 propaga a interrupção também com ``raise Ignore()`` —
    nada downstream deve rodar.

    ``commit_sha`` é opcional porque o canvas passa o ``analysis`` como
    primeiro arg posicional e não injeta kwargs neste ponto; quando vier
    explícito, ele ganha de qualquer coisa lida do payload.
    """
    from celery.exceptions import Ignore as _Ignore

    if not analysis or not isinstance(analysis, dict):
        raise _Ignore()
    findings = analysis.get("findings", []) or []
    max_severity = _max_severity(findings)

    commit_sha = commit_sha or _extract_commit(analysis)
    if not commit_sha:
        # A decisão mais cara do pipeline não pode ficar anônima no log.
        logger.warning("tier3_gate_sem_commit", findings_count=len(findings))

    nivel_risco = _nivel_de_risco(analysis)

    # Dois critérios, em OR. Antes só existia o primeiro, e ele ignora volume e
    # correlação — justamente o que o Tier 2 acabou de calcular.
    #
    # O caso real que motivou: 57 possíveis secrets num repositório, todos
    # `medium` individualmente (não verificados não travam merge por suspeita),
    # somando risco agregado `high` 74/100. Nenhum finding sozinho cruzava a
    # barra, então o Tier 3 era pulado — descartando a análise profunda no
    # cenário em que ela é mais útil.
    por_severidade = max_severity in _TIER3_ESCALATION_SEVERITIES
    por_risco_agregado = nivel_risco in _TIER3_ESCALATION_SEVERITIES

    if por_severidade or por_risco_agregado:
        logger.info(
            "tier3_escalated",
            commit_sha=commit_sha,
            max_severity=max_severity,
            nivel_risco=nivel_risco,
            # Qual critério disparou muda o que investigar: severidade aponta
            # para UM finding grave, risco agregado aponta para o conjunto.
            criterio=(
                "severidade_e_risco"
                if por_severidade and por_risco_agregado
                else "severidade_individual"
                if por_severidade
                else "risco_agregado"
            ),
            findings_count=len(findings),
            degraded=bool(analysis.get("degraded")),
        )
        scan_job_writer.mark_tier(commit_sha, 3, "running")
        return analysis

    logger.info(
        "tier3_skipped",
        commit_sha=commit_sha,
        max_severity=max_severity,
        nivel_risco=nivel_risco,
        findings_count=len(findings),
        reason="below_threshold",
    )
    # Persiste a DECISÃO antes de interromper o chain: sem isso o
    # ``tier3_status`` fica NULL e o dashboard não distingue "pulado por
    # severidade baixa" de "ainda não chegou nesse tier".
    scan_job_writer.mark_tier_skipped(commit_sha, 3)
    raise Ignore()


def _extract_commit(analysis: dict[str, Any]) -> str:
    """Best-effort: tenta achar o commit_sha no payload da análise.

    A ordem importa. ``tier2_analyze`` injeta ``commit_sha`` no payload de
    propósito — é a fonte confiável, e a única que existe quando o pipeline
    produz **zero findings** (hoje, o caso mais comum). A varredura dos
    findings continua só como rede de segurança para payloads antigos.
    """
    sha = analysis.get("commit_sha")
    if sha:
        return str(sha)
    for f in analysis.get("findings", []) or []:
        sha = f.get("commit_sha")
        if sha:
            return str(sha)
    return ""


@celery_app.task(
    name="app.presentation.workers.analysis_worker.tier3_deep_analysis",
    bind=True,
    queue="analysis",
)
def tier3_deep_analysis(
    self,
    tier3_data: dict[str, Any],
    *,
    commit_sha: str,
    tier2_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Análise profunda Tier 3 — attack path via Sonnet.

    Recebe o output de ``tier3_scan_worker.run_tier3_scan`` (com
    ``findings`` ZAP, ``cti_data`` e ``caldera_results``) e o
    ``tier2_analysis`` da etapa anterior (para agregar findings).

    Constrói o user prompt via ``attack_path.build()`` (blindado
    contra alucinação) e chama Claude no modelo de reasoning.

    Modo degradado para ``CircuitOpenError`` / ``GuardBlockedError``:
    retorna payload com ``degraded=True`` preservando os findings —
    o reporting worker decide como formatar a saída.
    """
    findings: list[dict] = []
    if tier2_analysis:
        findings.extend(tier2_analysis.get("findings", []) or [])
    findings.extend(tier3_data.get("findings", []) or [])
    cti_data = tier3_data.get("cti_data") or {}
    caldera_results = tier3_data.get("caldera_results") or {}
    # Validacao POR FINDING, deterministica: separa o que a cadeia de
    # ferramentas confirmou contra o alvo do que e' so sinalizacao estatica.
    # Independe do Caldera (que valida por passo do attack path) e do modelo.
    validacao = validation.resumo(findings)

    user_prompt = prompts.attack_path.build(
        findings=findings,
        cti_data=cti_data,
        caldera_results=caldera_results,
        validacao=validacao,
        context={"commit": commit_sha},
    )

    client = ClaudeClient()
    try:
        analysis = client.call_json(
            system=prompts.attack_path.SYSTEM,
            user=user_prompt,
            model=REASONING,
            commit_sha=commit_sha,
        )
    except (CircuitOpenError, GuardBlockedError, ClaudeClientError) as exc:
        logger.warning(
            "tier3_deep_analysis_degraded",
            commit_sha=commit_sha,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        scan_job_writer.mark_tier(commit_sha, 3, "done")
        return {
            "degraded": True,
            "reason": type(exc).__name__,
            "findings": findings,
            "cti_data": cti_data,
            "caldera_results": caldera_results,
            "cti_status": "available" if cti_data else "unavailable",
            "caldera_status": (
                "available"
                if caldera_results and caldera_results.get("status") != "failed"
                else "unavailable"
            ),
            "validacao_evidencia": validacao,
        }

    # Determinístico, NÃO `setdefault`: o modelo emite `cti_status`/
    # `caldera_status` no JSON dele e, com `setdefault`, o valor DELE vencia — o
    # modelo marcava `cti_status: unavailable` ao ver sinal fraco (EPSS baixo,
    # sem KEV), mesmo com o CTI tendo respondido e `cti_data` populado. Esses
    # flags são um fato — "a fonte respondeu?" —, não interpretação de ameaça, e
    # quem sabe isso é o código, não o LLM.
    analysis["cti_status"] = "available" if cti_data else "unavailable"
    analysis["caldera_status"] = (
        "available"
        if caldera_results and caldera_results.get("status") != "failed"
        else "unavailable"
    )
    analysis["degraded"] = False
    analysis["findings"] = findings
    analysis["cti_data"] = cti_data
    analysis["caldera_results"] = caldera_results
    analysis["validacao_evidencia"] = validacao
    scan_job_writer.mark_tier(commit_sha, 3, "done")
    scan_job_writer.set_final_risk_from_analysis(commit_sha, analysis)
    return analysis
