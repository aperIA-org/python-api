"""Tier 3 — ZAP + OpenCTI + Caldera, em sequência (fault-isolated).

Pipeline:
- ``ZAPScanner.run_safe(target_url, ...)`` — DAST contra deploy preview
- ``OpenCTIClient.enrich_cve(cve)`` para cada CVE distinto nos findings
- ``CalderaClient.run_safe(...)`` — emulação Caldera com TTPs do CTI

Retorna dict agregado **JSON-safe**:

    {
        "findings": [<zap findings serializados>],
        "cti_data": {"active_threat": bool, "mitre_techniques": [...]}
                    ou {} se nenhum CVE foi enriquecido,
        "caldera_results": {"status": "ok"|"failed", "success_rate": …}
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
from app.infrastructure.intelligence.mitre_caldera_client import CalderaClient
from app.infrastructure.intelligence.opencti_client import OpenCTIClient
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

    - ``active_threat`` = OR lógico (qualquer CVE com ameaça ativa)
    - ``mitre_techniques`` = união ordenada por primeira aparição
    """
    active = False
    techniques: list[str] = []
    seen: set[str] = set()
    cvss_scores: list[float] = []
    for result in cti_results:
        if not result:
            continue
        if result.get("active_threat"):
            active = True
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
        merged["active_threat"] = active
        merged["mitre_techniques"] = techniques
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
) -> dict[str, Any]:
    # ---- ZAP DAST ----
    zap_findings: list[Finding] = []
    if target_url:
        zap_findings = ZAPScanner().run_safe(
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

    # ---- OpenCTI por CVE ----
    cves = _collect_cves(t2_findings)
    cti_results: list[dict | None] = []
    if cves:
        client = OpenCTIClient()
        for cve in cves:
            cti_results.append(client.enrich_cve(cve))
    cti_merged = _merge_cti(cti_results)

    # ---- Caldera ----
    caldera_results: dict[str, Any]
    try:
        techniques = cti_merged.get("mitre_techniques", [])
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
        }

    logger.info(
        "tier3_scan_complete",
        commit_sha=commit_sha,
        zap_findings=len(zap_findings),
        cve_count=len(cves),
        cti_status="available" if cti_merged else "unavailable",
        caldera_status=caldera_results.get("status"),
    )

    return {
        "findings": _findings_to_dicts(zap_findings),
        "cti_data": cti_merged,
        "caldera_results": caldera_results,
    }
