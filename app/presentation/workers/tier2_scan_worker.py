"""Tier 2 — Trivy + Semgrep expanded + Prowler (condicional).

Diferenças em relação ao Tier 1:

- **Trivy** sempre roda contra a árvore do commit (SCA + IaC +
  containers).
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

O worker faz o **próprio checkout** do commit: o container do Tier 2 não
compartilha filesystem com o do Tier 1, então a árvore clonada lá não existe
aqui. Racional completo em ``infrastructure/git/repo_checkout.py``.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import structlog

from app.core.celery_app import celery_app
from app.domain.finding.entities import Finding
from app.domain.finding.services import FindingDeduplicator
from app.domain.scan.value_objects import ToolStatus
from app.infrastructure.git.repo_checkout import listar_arquivos_alterados
from app.infrastructure.persistence import scan_tool_run_writer
from app.presentation.workers.persistence_guard import persistir_ou_falhar
from app.infrastructure.scanners.prowler_scanner import (
    ProwlerScanner,
    has_iac_files,
)
from app.infrastructure.scanners.semgrep_scanner import SemgrepScanner
from app.infrastructure.scanners.trivy_scanner import TrivyScanner
from app.presentation.workers.checkout_guard import checkout_para_scan

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
    repo_full_name: str,
    installation_id: int,
    changed_files: list[str],
    commit_sha: str,
    repo_url: str,
    base_sha: str = "",
    cloud_provider: str = "aws",
) -> list[dict[str, Any]]:
    """Roda os 3 scanners de T2 em sequência (fault-isolated).

    Por que sequencial e não ``group()``: T2 já não está no caminho
    crítico (≤ 10 min). Paralelismo via Celery group adiciona
    complexidade de orquestração; sequencial dentro do mesmo worker
    é mais simples e tolera scanner indisponível via ``run_safe``.

    ``changed_files`` aqui só decide se o Prowler roda (``has_iac_files``);
    Trivy e Semgrep expanded sempre varrem a árvore inteira. Quando a lista
    chega vazia e existe base (PR), calculamos o diff no próprio checkout —
    sem isso o Prowler jamais dispararia, porque o canvas não carrega diff.
    """
    with checkout_para_scan(
        tier=2,
        repo_full_name=repo_full_name,
        commit_sha=commit_sha,
        installation_id=installation_id,
        base_sha=base_sha,
    ) as repo_path:
        arquivos = changed_files or listar_arquivos_alterados(
            repo_path, base_sha=base_sha, head_sha=commit_sha
        )

        trivy_findings: list[Finding] = TrivyScanner().run_safe(
            tool_id="trivy",
            tier=2,
            target=repo_path,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )

        semgrep_findings: list[Finding] = _SemgrepExpandedAdapter().run_safe(
            tool_id="semgrep-full",
            tier=2,
            repo_path=repo_path,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )

        prowler_findings: list[Finding] = []
        if has_iac_files(arquivos):
            prowler_findings = ProwlerScanner().run_safe(
                tool_id="prowler",
                tier=2,
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
            # O pulo do Prowler é uma DECISÃO do pipeline, não uma ausência de
            # dado. Sem esta linha o Tier 2 fecha como `done` e o dashboard
            # mostra o Prowler como concluído — uma ferramenta que não rodou.
            scan_tool_run_writer.record_tool_run(
                commit_sha=commit_sha,
                tier=2,
                tool="prowler",
                status=ToolStatus.SKIPPED,
                reason="no_iac_files",
            )

    aggregated = trivy_findings + semgrep_findings + prowler_findings
    deduplicated = FindingDeduplicator().deduplicate(aggregated)

    persistir_ou_falhar(deduplicated, commit_sha=commit_sha, tier=2)

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
