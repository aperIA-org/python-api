"""Tier 1 — TruffleHog + Semgrep changed-files, em paralelo.

Por que workers separados por scanner:
- Cada scanner falhando isoladamente (`run_safe`) não compromete os
  outros.
- A fila ``tier1`` recebe ambos e o broker distribui — paralelismo
  real desde que haja > 1 worker.

Por que retornar dicts (não dataclasses Finding):
- Celery serializa em JSON. Dataclasses não são JSON-nativas. Cada
  worker converte para dict; o `analysis_worker` reconstrói se
  necessário.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import structlog

from app.core.celery_app import celery_app
from app.domain.finding.entities import Finding
from app.infrastructure.persistence.finding_writer import persist_findings
from app.infrastructure.scanners.semgrep_scanner import SemgrepScanner
from app.infrastructure.scanners.trufflehog_scanner import TruffleHogScanner

logger = structlog.get_logger()


def _findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        d = dataclasses.asdict(f)
        # Severity é Enum — convertemos para string serializável.
        d["severity"] = f.severity.value
        d["cve_id"] = str(f.cve_id) if f.cve_id else None
        d["id"] = str(f.id)
        d["created_at"] = f.created_at.isoformat()
        rows.append(d)
    return rows


@celery_app.task(
    name="app.presentation.workers.tier1_scan_worker.run_trufflehog",
    bind=True,
    queue="tier1",
)
def run_trufflehog(
    self,
    repo_path: str,
    base_sha: str,
    head_sha: str,
    commit_sha: str,
    repo_url: str,
) -> list[dict[str, Any]]:
    findings = TruffleHogScanner().run_safe(
        repo_path=repo_path,
        base_sha=base_sha,
        head_sha=head_sha,
        commit_sha=commit_sha,
        repo_url=repo_url,
    )
    persist_findings(findings, commit_sha=commit_sha, tier=1)
    logger.info(
        "tier1_trufflehog_complete",
        commit_sha=commit_sha,
        findings_count=len(findings),
    )
    return _findings_to_dicts(findings)


@celery_app.task(
    name="app.presentation.workers.tier1_scan_worker.run_semgrep_changed",
    bind=True,
    queue="tier1",
)
def run_semgrep_changed(
    self,
    repo_path: str,
    changed_files: list[str],
    commit_sha: str,
    repo_url: str,
) -> list[dict[str, Any]]:
    findings = SemgrepScanner().run_safe(
        repo_path=repo_path,
        changed_files=changed_files,
        commit_sha=commit_sha,
        repo_url=repo_url,
    )
    persist_findings(findings, commit_sha=commit_sha, tier=1)
    logger.info(
        "tier1_semgrep_complete",
        commit_sha=commit_sha,
        findings_count=len(findings),
    )
    return _findings_to_dicts(findings)
