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

Cada task faz o **próprio checkout** do commit (``checkout_para_scan``) em vez
de receber um ``repo_path`` pronto pelo canvas: as duas tasks do grupo podem
cair em workers/containers diferentes, que não compartilham filesystem. O
racional completo está em ``infrastructure/git/repo_checkout.py``.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import structlog

from app.core.celery_app import celery_app
from app.domain.finding.entities import Finding
from app.infrastructure.git.repo_checkout import listar_arquivos_alterados
from app.presentation.workers.persistence_guard import persistir_ou_falhar
from app.infrastructure.scanners.semgrep_scanner import SemgrepScanner
from app.infrastructure.scanners.trufflehog_scanner import TruffleHogScanner
from app.presentation.workers.checkout_guard import checkout_para_scan

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
    repo_full_name: str,
    installation_id: int,
    base_sha: str,
    head_sha: str,
    commit_sha: str,
    repo_url: str,
) -> list[dict[str, Any]]:
    """Busca secrets verificados na árvore do commit.

    ``base_sha`` é passado ao checkout para que o objeto do commit-base exista
    localmente — é dele que o TruffleHog precisa no ``--since-commit``.
    """
    with checkout_para_scan(
        tier=1,
        repo_full_name=repo_full_name,
        commit_sha=commit_sha,
        installation_id=installation_id,
        base_sha=base_sha,
    ) as repo_path:
        findings = TruffleHogScanner().run_safe(
            tool_id="trufflehog",
            tier=1,
            repo_path=repo_path,
            base_sha=base_sha,
            head_sha=head_sha,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
    persistir_ou_falhar(findings, commit_sha=commit_sha, tier=1)
    logger.info(
        "tier1_trufflehog_complete",
        commit_sha=commit_sha,
        findings_count=len(findings),
        # O modo decide o que foi examinado: `git` varre os commits do PR,
        # `filesystem` varre a árvore do commit. Sem isso no log, "0 findings"
        # é ambíguo entre "não achei" e "não procurei".
        modo="git" if base_sha and base_sha != head_sha else "filesystem",
        verificados=sum(1 for f in findings if f.secret_verified),
    )
    return _findings_to_dicts(findings)


@celery_app.task(
    name="app.presentation.workers.tier1_scan_worker.run_semgrep_changed",
    bind=True,
    queue="tier1",
)
def run_semgrep_changed(
    self,
    repo_full_name: str,
    installation_id: int,
    changed_files: list[str],
    commit_sha: str,
    repo_url: str,
    base_sha: str = "",
) -> list[dict[str, Any]]:
    """Semgrep no escopo do PR — ou na árvore inteira quando não há diff.

    Quem define o alvo, em ordem:

    1. ``changed_files`` explícito (o canvas não preenche hoje; fica como
       porta de entrada para um diff calculado fora do worker);
    2. o **diff real** ``base_sha..commit_sha``, calculado no checkout — é o
       caso do webhook de PR, onde os dois SHAs diferem;
    3. lista vazia → o Semgrep varre a árvore inteira. É o scan manual de
       branch, que não tem base contra o que comparar, e também o fallback
       quando o diff não pôde ser calculado (force-push no base). Varrer
       demais é o erro aceitável; varrer nada não é.
    """
    with checkout_para_scan(
        tier=1,
        repo_full_name=repo_full_name,
        commit_sha=commit_sha,
        installation_id=installation_id,
        base_sha=base_sha,
    ) as repo_path:
        alvos = changed_files or listar_arquivos_alterados(
            repo_path, base_sha=base_sha, head_sha=commit_sha
        )
        findings = SemgrepScanner().run_safe(
            # `semgrep-changed`, não `semgrep`: o mesmo scanner roda de novo no
            # Tier 2 sobre a árvore inteira, e as duas rodadas são ferramentas
            # distintas do ponto de vista de quem lê o pipeline.
            tool_id="semgrep-changed",
            tier=1,
            repo_path=repo_path,
            changed_files=alvos,
            commit_sha=commit_sha,
            repo_url=repo_url,
        )
    persistir_ou_falhar(findings, commit_sha=commit_sha, tier=1)
    logger.info(
        "tier1_semgrep_complete",
        commit_sha=commit_sha,
        findings_count=len(findings),
        arquivos_no_escopo=len(alvos),
        escopo="diff" if alvos else "arvore_inteira",
    )
    return _findings_to_dicts(findings)
