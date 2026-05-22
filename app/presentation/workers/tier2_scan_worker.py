"""Tier 2 — Trivy + Semgrep expanded + Prowler (condicional).

Diferenças em relação ao Tier 1:

- **Trivy** sempre roda contra ``repo_path`` (SCA + IaC + containers).
- **Semgrep** roda em modo *expanded* (``--config=auto``, repo
  inteiro) — mais profundo, mas só faz sentido depois que T1
  passou no Gate 1.
- **Prowler** só roda se ``has_iac_files(changed_files)`` indicar
  presença de arquivos IaC no PR. CSPM cloud não tem o que olhar em
  PRs que só mudam código de aplicação.

O **`FindingDeduplicator` do domain** é aplicado no agregado antes
de retornar. É a primeira barreira contra duplicidade — a segunda é
a UNIQUE constraint ``findings_dedup_key`` no banco, exercitada
quando os findings T1 + T2 forem persistidos juntos.

Findings são serializados como dict (Celery não transporta
``Finding``); o caller (orquestrador da Semana 12) reconstrói se
precisar reaplicar a entidade.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import structlog

from app.core.celery_app import celery_app
from app.domain.finding.entities import Finding
from app.domain.finding.services import FindingDeduplicator
from app.infrastructure.scanners.prowler_scanner import (
    ProwlerScanner,
    has_iac_files,
)
from app.infrastructure.scanners.semgrep_scanner import SemgrepScanner
from app.infrastructure.scanners.trivy_scanner import TrivyScanner

logger = structlog.get_logger()


class _SemgrepExpandedAdapter(SemgrepScanner):
    """Adapter que faz ``run_safe`` chamar ``scan_expanded``.

    ``run_safe`` (do ``BaseScanner``) sempre invoca ``self.scan(...)``.
    Em T2 queremos o modo expanded (config=auto, repo inteiro) — esta
    subclasse troca a implementação de ``scan`` sem duplicar lógica.
    """

    def scan(  # type: ignore[override]
        self, repo_path: str, commit_sha: str, repo_url: str
    ) -> list[Finding]:
        return self.scan_expanded(repo_path, commit_sha, repo_url)


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


@celery_app.task(
    name="app.presentation.workers.tier2_scan_worker.run_tier2_scan",
    bind=True,
    queue="tier2",
)
def run_tier2_scan(
    self,
    repo_path: str,
    changed_files: list[str],
    commit_sha: str,
    repo_url: str,
    cloud_provider: str = "aws",
) -> list[dict[str, Any]]:
    """Roda os 3 scanners de T2 em sequência (fault-isolated).

    Por que sequencial e não ``group()``: T2 já não está no caminho
    crítico (≤ 10 min). Paralelismo via Celery group adiciona
    complexidade de orquestração; sequencial dentro do mesmo worker
    é mais simples e tolera scanner indisponível via ``run_safe``.
    """
    trivy_findings: list[Finding] = TrivyScanner().run_safe(
        target=repo_path,
        commit_sha=commit_sha,
        repo_url=repo_url,
    )

    semgrep_findings: list[Finding] = _SemgrepExpandedAdapter().run_safe(
        repo_path=repo_path,
        commit_sha=commit_sha,
        repo_url=repo_url,
    )

    prowler_findings: list[Finding] = []
    if has_iac_files(changed_files):
        prowler_findings = ProwlerScanner().run_safe(
            provider=cloud_provider,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
        logger.info(
            "tier2_prowler_executed",
            commit_sha=commit_sha,
            iac_files_detected=True,
            findings_count=len(prowler_findings),
        )
    else:
        logger.info(
            "tier2_prowler_skipped",
            commit_sha=commit_sha,
            reason="no_iac_files",
        )

    aggregated = trivy_findings + semgrep_findings + prowler_findings
    deduplicated = FindingDeduplicator().deduplicate(aggregated)

    logger.info(
        "tier2_scan_complete",
        commit_sha=commit_sha,
        trivy=len(trivy_findings),
        semgrep_expanded=len(semgrep_findings),
        prowler=len(prowler_findings),
        aggregated=len(aggregated),
        after_dedup=len(deduplicated),
    )

    return _findings_to_dicts(deduplicated)
