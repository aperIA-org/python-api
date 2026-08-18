"""Tier 3 — ZAP + Threat Intel (KEV/EPSS) + Caldera, em sequência (fault-isolated).

Pipeline:
- ``ZAPScanner.run_safe(target_url, ...)`` — DAST contra deploy preview
- ``ThreatIntelClient.enrich_cve(cve)`` para cada CVE distinto nos findings
- ``CalderaClient.run_safe(...)`` — emulação Caldera com TTPs do CTI

Retorna dict agregado **JSON-safe**:

    {
        "findings": [<zap findings serializados>],
        "cti_data": {"active_threat": bool, "known_exploited": bool,
                     "active_campaigns": bool, "epss_score": float|None, ...}
                    ou {} se nenhum CVE foi enriquecido,
        "caldera_results": {"status": "reachable"|"failed", "success_rate": …,
                            "caldera_validated": bool, "validacao_parcial": bool}
    }

Por que sequencial: T3 não está no caminho crítico (30-60 min).
Caldera depende dos TTPs do CTI, então a ordem ZAP → CTI → Caldera
faz sentido. Paralelismo via Celery group adiciona complexidade sem
ganho prático.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import structlog

from app.core.celery_app import celery_app
from app.core.exceptions import SandboxViolationError
from app.domain.finding.entities import Finding
from app.domain.scan.value_objects import ToolStatus
from app.infrastructure.persistence import scan_tool_run_writer
from app.presentation.workers.persistence_guard import persistir_ou_falhar
from app.infrastructure.intelligence.mitre_caldera_client import CalderaClient
from app.infrastructure.intelligence.threat_intel_client import ThreatIntelClient
from app.infrastructure.scanners.zap_scanner import ZAPScanner

logger = structlog.get_logger()


def _findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        d = dataclasses.asdict(f)
        d["severity"] = f.severity.value
        d["cve_id"] = str(f.cve_id) if f.cve_id else None
        d["id"] = str(f.id)
        d["created_at"] = f.created_at.isoformat()
        rows.append(d)
    return rows


def _collect_cves(t2_findings: list[dict[str, Any]]) -> list[str]:
    """Lista CVEs distintos vindos do Tier 2 (já como dict)."""
    seen: set[str] = set()
    ordered: list[str] = []
    for f in t2_findings or []:
        cve = f.get("cve_id")
        if cve and cve not in seen:
            seen.add(cve)
            ordered.append(cve)
    return ordered


def _merge_cti(cti_results: list[dict | None]) -> dict[str, Any]:
    """Combina enriquecimentos de múltiplos CVEs em um único dict.

    - sinais binários (``active_threat``/``known_exploited``/``active_campaigns``)
      = OR lógico (qualquer CVE com o sinal)
    - ``epss_score`` = máximo (o risco do conjunto é o do pior CVE)
    - ``mitre_techniques`` = união ordenada por primeira aparição
    """
    active = False
    known_exploited = False
    active_campaigns = False
    epss_scores: list[float] = []
    techniques: list[str] = []
    seen: set[str] = set()
    cvss_scores: list[float] = []
    for result in cti_results:
        if not result:
            continue
        if result.get("active_threat"):
            active = True
        if result.get("known_exploited"):
            known_exploited = True
        if result.get("active_campaigns"):
            active_campaigns = True
        epss = result.get("epss_score")
        if isinstance(epss, (int, float)):
            epss_scores.append(float(epss))
        for ttp in result.get("mitre_techniques", []) or []:
            if ttp and ttp not in seen:
                seen.add(ttp)
                techniques.append(ttp)
        cvss = result.get("cvss_base")
        try:
            if cvss is not None:
                cvss_scores.append(float(cvss))
        except (TypeError, ValueError):
            pass

    merged: dict[str, Any] = {}
    if cti_results and any(cti_results):
        # OR nos sinais binários, MAX no EPSS: o risco do conjunto de CVEs é o do
        # pior deles.
        merged["active_threat"] = active
        merged["known_exploited"] = known_exploited
        merged["active_campaigns"] = active_campaigns
        merged["mitre_techniques"] = techniques
        if epss_scores:
            merged["epss_score"] = max(epss_scores)
        if cvss_scores:
            merged["cvss_base"] = max(cvss_scores)
    return merged


@celery_app.task(
    name="app.presentation.workers.tier3_scan_worker.run_tier3_scan",
    bind=True,
    queue="tier3",
)
def run_tier3_scan(
    self,
    *,
    target_url: str | None,
    t2_findings: list[dict[str, Any]],
    commit_sha: str,
    repo_url: str,
    adversary_name: str | None = None,
    mitre_techniques: list[str] | None = None,
) -> dict[str, Any]:
    # ---- ZAP DAST ----
    zap_findings: list[Finding] = []
    if target_url:
        zap_findings = ZAPScanner().run_safe(
            tool_id="zap",
            tier=3,
            target_url=target_url,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
    else:
        logger.info(
            "tier3_zap_skipped",
            commit_sha=commit_sha,
            reason="no_target_url",
        )
        # Sem alvo o DAST não roda, mas o Tier 3 fecha como `done` mesmo assim —
        # e aí o dashboard mostrava o ZAP como concluído. Esta linha é o que
        # separa "escaneou e não achou nada" de "não tinha o que escanear".
        scan_tool_run_writer.record_tool_run(
            commit_sha=commit_sha,
            tier=3,
            tool="zap",
            status=ToolStatus.SKIPPED,
            reason="no_target_url",
        )

    persistir_ou_falhar(zap_findings, commit_sha=commit_sha, tier=3)

    # ---- Threat Intel (KEV + EPSS) por CVE ----
    # `running` antes de comecar: e' o que deixa o dashboard mostrar QUAL
    # ferramenta esta' em execucao, em vez de deduzir pela ordem do pipeline.
    scan_tool_run_writer.record_tool_run(
        commit_sha=commit_sha, tier=3, tool="threat-intel", status=ToolStatus.RUNNING
    )
    cves = _collect_cves(t2_findings)
    cti_results: list[dict | None] = []
    if cves:
        client = ThreatIntelClient()
        for cve in cves:
            cti_results.append(client.enrich_cve(cve))
    cti_merged = _merge_cti(cti_results)

    # ---- Caldera ----
    scan_tool_run_writer.record_tool_run(
        commit_sha=commit_sha, tier=3, tool="caldera", status=ToolStatus.RUNNING
    )
    caldera_results: dict[str, Any]
    try:
        # União das duas fontes, cadeia do Tier 2 primeiro.
        #
        # A do CTI quase nunca soma técnicas: o KEV/EPSS não fornecem técnicas
        # MITRE por CVE (isso é o passo 2 com OTX), e num scan web quase nenhum
        # finding tem CVE. `mitre_techniques` do CTI fica `[]` — o Caldera então
        # roda só sobre a cadeia do Tier 2, que é a fonte real de técnicas.
        techniques = list(mitre_techniques or [])
        for ttp in cti_merged.get("mitre_techniques", []) or []:
            if ttp and ttp not in techniques:
                techniques.append(ttp)
        caldera = CalderaClient()
        caldera_results = caldera.run_safe(
            adversary_name=adversary_name or f"pr-{commit_sha[:8]}",
            mitre_techniques=techniques,
        )
    except SandboxViolationError as exc:
        # Em produção, isso é um erro de configuração que deve falhar
        # o deploy. Aqui no MVP isolamos e seguimos em modo degradado.
        logger.warning(
            "tier3_caldera_sandbox_violation",
            commit_sha=commit_sha,
            error=str(exc),
        )
        caldera_results = {
            "status": "failed",
            "reason": "SandboxViolationError",
            "success_rate": 0.0,
            "techniques_executed": 0,
            "techniques_successful": 0,
            "ttps_used": [],
            "caldera_validated": False,
            "validacao_parcial": False,
            "tecnicas_por_pai": [],
            "tecnicas_sem_cobertura": [],
        }

    # Threat intel e Caldera não passam por `run_safe` (um é um cliente HTTP em
    # laço por CVE, o outro devolve um dict com `status` próprio), então o
    # registro é feito aqui, a partir do desfecho que o worker já calculou.
    scan_tool_run_writer.record_tool_run(
        commit_sha=commit_sha,
        tier=3,
        tool="threat-intel",
        status=ToolStatus.DONE if cti_merged else ToolStatus.SKIPPED,
        # Sem CVE nos findings do Tier 2 não há o que enriquecer — é pulo por
        # falta de entrada, não falha do feed.
        reason=None if cti_merged else ("sem_cves" if not cves else "cti_indisponivel"),
    )
    _caldera_status = str(caldera_results.get("status") or "")
    scan_tool_run_writer.record_tool_run(
        commit_sha=commit_sha,
        tier=3,
        tool="caldera",
        # `reachable` é o "ok" do CalderaClient.run_safe; qualquer outra coisa
        # é falha (inclusive a violação de sandbox tratada acima).
        status=ToolStatus.DONE if _caldera_status == "reachable" else ToolStatus.FAILED,
        reason=None if _caldera_status == "reachable" else (
            str(caldera_results.get("reason") or _caldera_status or "indisponivel")
        ),
    )

    logger.info(
        "tier3_scan_complete",
        commit_sha=commit_sha,
        zap_findings=len(zap_findings),
        cve_count=len(cves),
        cti_status="available" if cti_merged else "unavailable",
        caldera_status=caldera_results.get("status"),
        caldera_validado=caldera_results.get("caldera_validated"),
        caldera_parcial=caldera_results.get("validacao_parcial"),
    )

    return {
        "findings": _findings_to_dicts(zap_findings),
        "cti_data": cti_merged,
        "caldera_results": caldera_results,
    }
