"""Worker de reporting — formata e posta o relatório no PR.

Usa Haiku via ``ClaudeClient.call`` (não ``call_json`` — saída é
markdown livre, não JSON). Em modo degradado (análise sem Claude),
gera um relatório textual fixo a partir dos findings brutos.
"""
from __future__ import annotations

from typing import Any

import structlog

from app.core.celery_app import celery_app
from app.infrastructure.ai import prompts
from app.infrastructure.ai.claude_client import (
    CircuitOpenError,
    ClaudeClient,
    ClaudeClientError,
    GuardBlockedError,
)
from app.infrastructure.ai.models import FORMATTING
from app.infrastructure.git.github_client import GitHubClient
from app.infrastructure.persistence import scan_report_writer

logger = structlog.get_logger()


def _fallback_markdown(analysis: dict[str, Any]) -> str:
    findings = analysis.get("findings", [])
    reason = analysis.get("reason", "unknown")
    lines = [
        "## aperIA — Análise em modo degradado",
        "",
        f"Não foi possível gerar a narrativa Claude (motivo: `{reason}`). "
        "Lista bruta de findings:",
        "",
    ]
    for f in findings[:20]:
        lines.append(
            f"- [{str(f.get('severity', '?')).upper()}] "
            f"{f.get('source', '?')}: {f.get('title', '?')} "
            f"({f.get('file_path', 'N/A')}:{f.get('line_number', '?')})"
        )
    if len(findings) > 20:
        lines.append(f"- ... (+{len(findings) - 20} findings)")
    return "\n".join(lines)


@celery_app.task(
    name="app.presentation.workers.reporting_worker.post_tier2_report",
    bind=True,
    queue="reporting",
)
def post_tier2_report(
    self,
    analysis: dict[str, Any] | None,
    *,
    repo_full_name: str,
    pr_number: int | None,
    commit_sha: str,
    installation_id: int,
) -> dict[str, Any] | None:
    # Workers Celery só aceitam args JSON-serializáveis. Clients são
    # construídos aqui; testes mockam via
    # ``patch("...reporting_worker.ClaudeClient")``.
    # Propagação de Ignore upstream → no-op (Gate 1 bloqueou).
    if not analysis or not isinstance(analysis, dict):
        return None
    report_degraded = bool(analysis.get("degraded"))
    if analysis.get("degraded"):
        body = _fallback_markdown(analysis)
        logger.info("tier2_report_degraded", commit_sha=commit_sha)
    else:
        user_prompt = prompts.pr_report.build(
            analysis=analysis,
            context={
                "repo": repo_full_name,
                "pr_number": pr_number,
                "commit": commit_sha,
            },
        )
        try:
            response = ClaudeClient().call(
                system=prompts.pr_report.SYSTEM,
                user=user_prompt,
                model=FORMATTING,
                commit_sha=commit_sha,
            )
            body = response.text
        except (CircuitOpenError, GuardBlockedError, ClaudeClientError) as exc:
            logger.warning(
                "tier2_report_claude_failed",
                commit_sha=commit_sha,
                error=str(exc),
            )
            report_degraded = True
            body = _fallback_markdown(
                {**analysis, "degraded": True, "reason": type(exc).__name__}
            )

    post_meta: dict[str, Any]
    if pr_number is None:
        # Scan manual (de branch): não há PR onde comentar. O relatório fica
        # apenas na projeção consumível via API — evita um POST que falharia.
        logger.info("tier2_report_sem_pr", commit_sha=commit_sha)
        post_meta = {"posted": False, "reason": "sem_pr"}
    else:
        try:
            comment_id = GitHubClient(installation_id=installation_id).post_pr_comment(
                repo_full_name=repo_full_name, pr_number=pr_number, body=body
            )
            logger.info(
                "tier2_report_posted",
                commit_sha=commit_sha,
                comment_id=comment_id,
            )
            post_meta = {"comment_id": comment_id, "posted": True}
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "tier2_report_post_failed",
                commit_sha=commit_sha,
                error=str(exc),
            )
            post_meta = {"posted": False, "error": str(exc)}
    # Persiste o relatório na projeção consumível via API (best-effort).
    scan_report_writer.persist_report(
        commit_sha=commit_sha,
        tier=2,
        report_markdown=body,
        analysis_json=analysis,
        degraded=report_degraded,
        comment_id=post_meta.get("comment_id"),
        posted=bool(post_meta.get("posted")),
    )
    # Retorna a análise inalterada (com metadado do post anexado) — o
    # canvas Celery precisa continuar com o ``analysis`` para o
    # ``tier3_gate`` a seguir.
    return {**analysis, "_post_meta": post_meta}


# ---------------------------------------------------------------- Tier 3


_T3_REPORT_SYSTEM = """Você é um redator técnico que transforma análises profundas de segurança (attack path completo) em relatórios markdown para desenvolvedores e líderes técnicos.

REGRAS:
1. Reflita EXATAMENTE os campos fornecidos. NÃO infira conclusões adicionais.
2. Se "cti_status" == "unavailable", NÃO mencione campanhas, atores ou grupos.
3. Se "caldera_status" == "unavailable", NÃO afirme exploração bem-sucedida.
4. Para CADA passo do attack_path, mostre fase + TTP MITRE + descrição + se foi validado pelo Caldera.
5. Liste as prioritized_actions em ordem (1, 2, 3...).
6. Tom: técnico, direto, acionável; máximo 40 linhas de markdown.
7. NÃO use emojis nem ícones — o relatório é documento técnico e vai para PR, dashboard e export.

Formato:
## aperIA — Análise Profunda (Tier 3)

**Risk Score (ajustado):** <score>/100 (<level>) — kill chain <completa|incompleta>

**Attack path:**
1. [<phase>] [<TTP>] <descrição> · validado por Caldera: <sim|nao>
2. ...

**Ações priorizadas:**
1. <action> — <rationale>
2. ...

**Status de inteligência:**
- CTI: <available|unavailable>
- Caldera: <available|unavailable>"""


def _fallback_t3_markdown(analysis: dict[str, Any]) -> str:
    reason = analysis.get("reason", "unknown")
    lines = [
        "## aperIA — Análise Profunda em modo degradado",
        "",
        f"Não foi possível gerar a narrativa Tier 3 (motivo: `{reason}`).",
        "",
        "Lista bruta dos findings agregados:",
        "",
    ]
    for f in (analysis.get("findings", []) or [])[:30]:
        lines.append(
            f"- [{str(f.get('severity', '?')).upper()}] "
            f"{f.get('source', '?')}: {f.get('title', '?')} "
            f"({f.get('file_path', 'N/A')}:{f.get('line_number', '?')})"
        )
    cti = analysis.get("cti_data") or {}
    caldera = analysis.get("caldera_results") or {}
    if cti:
        ttps = cti.get("mitre_techniques", [])
        if ttps:
            lines.append("")
            lines.append(f"**TTPs do CTI:** {', '.join(map(str, ttps))}")
    if caldera and caldera.get("status") != "failed":
        lines.append("")
        lines.append(
            f"**Caldera success_rate:** {caldera.get('success_rate', 0.0):.0%}"
        )
    return "\n".join(lines)


@celery_app.task(
    name="app.presentation.workers.reporting_worker.post_tier3_deep_report",
    bind=True,
    queue="reporting",
)
def post_tier3_deep_report(
    self,
    deep_analysis: dict[str, Any] | None,
    *,
    repo_full_name: str,
    pr_number: int | None,
    commit_sha: str,
    installation_id: int,
) -> dict[str, Any] | None:
    """Gera relatório PR Tier 3 e posta como comentário.

    Usa Haiku para formatar — não é reasoning novo, é tradução do
    JSON estruturado para markdown amigável. Caminho degradado usa
    ``_fallback_t3_markdown`` sem chamar Claude.

    ``None`` (Ignore upstream — Gate 1 ou Gate 2 interrompeu) → no-op.
    """
    if not deep_analysis or not isinstance(deep_analysis, dict):
        return None
    report_degraded = bool(deep_analysis.get("degraded"))
    if deep_analysis.get("degraded"):
        body = _fallback_t3_markdown(deep_analysis)
        logger.info("tier3_report_degraded", commit_sha=commit_sha)
    else:
        # Reaproveita o helper pr_report.build do Tier 2 (mesmo
        # padrão: JSON embedded + context header) mas com SYSTEM
        # específico para attack path.
        user_prompt = prompts.pr_report.build(
            analysis=deep_analysis,
            context={
                "repo": repo_full_name,
                "pr_number": pr_number,
                "commit": commit_sha,
            },
        )
        try:
            response = ClaudeClient().call(
                system=_T3_REPORT_SYSTEM,
                user=user_prompt,
                model=FORMATTING,
                commit_sha=commit_sha,
            )
            body = response.text
        except (CircuitOpenError, GuardBlockedError, ClaudeClientError) as exc:
            logger.warning(
                "tier3_report_claude_failed",
                commit_sha=commit_sha,
                error=str(exc),
            )
            report_degraded = True
            body = _fallback_t3_markdown(
                {
                    **deep_analysis,
                    "degraded": True,
                    "reason": type(exc).__name__,
                }
            )

    post_meta: dict[str, Any]
    if pr_number is None:
        # Scan manual (de branch): sem PR onde comentar — ver post_tier2_report.
        logger.info("tier3_report_sem_pr", commit_sha=commit_sha)
        post_meta = {"posted": False, "reason": "sem_pr"}
    else:
        try:
            comment_id = GitHubClient(installation_id=installation_id).post_pr_comment(
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                body=body,
            )
            logger.info(
                "tier3_report_posted",
                commit_sha=commit_sha,
                comment_id=comment_id,
            )
            post_meta = {"comment_id": comment_id, "posted": True}
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "tier3_report_post_failed",
                commit_sha=commit_sha,
                error=str(exc),
            )
            post_meta = {"posted": False, "error": str(exc)}
    # Persiste o relatório final na projeção consumível via API (best-effort).
    scan_report_writer.persist_report(
        commit_sha=commit_sha,
        tier=3,
        report_markdown=body,
        analysis_json=deep_analysis,
        degraded=report_degraded,
        comment_id=post_meta.get("comment_id"),
        posted=bool(post_meta.get("posted")),
    )
    # Tier 3 é o último da chain — mesmo assim retornamos a análise
    # para consistência (orquestrador pode logar / inspecionar).
    return {**deep_analysis, "_post_meta": post_meta}
