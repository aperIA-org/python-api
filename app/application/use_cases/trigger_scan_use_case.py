"""Disparo do pipeline de segurança — webhook de PR e scan manual.

Dois gatilhos, **um único caminho de disparo**: ``dispatch_pipeline`` é o
ponto onde os argumentos "de MVP" do canvas (``repo_path`` stub,
``changed_files`` vazio, ``target_url`` ausente) são preenchidos. O webhook
(``POST /webhook/github``) e o scan manual (``POST /repositories/{id}/scan``)
chamam a mesma função, então nenhum dos dois pode divergir do outro.

``TriggerRepositoryScanUseCase`` acrescenta ao scan manual o que o webhook
recebe de graça no payload: o commit HEAD do branch default (resolvido no
GitHub) e a checagem de que não há scan em andamento para aquele commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol
from uuid import UUID

import structlog

from app.application.exceptions import (
    GithubAppNotConfiguredError,
    GithubResolutionError,
    RepositoryInactiveError,
    ScanAlreadyInProgressError,
)
from app.domain.github.entities import Repository
from app.domain.scan.repositories import ScanJobRepository
from app.domain.scan.value_objects import TierStatus

logger = structlog.get_logger()

# Tiers ainda não concluídos — se algum tier está nesses estados, o scan
# daquele commit ainda está rodando (ou na fila).
_STATUS_EM_ANDAMENTO = (TierStatus.QUEUED, TierStatus.RUNNING)


class HeadShaResolver(Protocol):
    """Só o que o use case precisa do ``GitHubClient`` (injetado pela rota).

    A camada de aplicação não importa infraestrutura — a rota passa a própria
    classe ``GitHubClient`` como factory.
    """

    def get_branch_head_sha(self, repo_full_name: str, branch: str) -> str: ...


def dispatch_pipeline(
    *,
    commit_sha: str,
    repo_url: str,
    repo_full_name: str,
    installation_id: int,
    pr_number: int | None,
    base_sha: str | None = None,
    user_id: UUID | None = None,
    repository_id: UUID | None = None,
) -> Any:
    """Dispara o canvas Celery completo para um commit.

    ``pr_number=None`` significa scan de branch (manual): o pipeline é o mesmo,
    apenas não há PR onde comentar.

    Estado do MVP (igual para os dois gatilhos):
    - ``repo_path``: stub — sem checkout real os scanners locais devolvem ``[]``
    - ``changed_files``: vazio — Semgrep T1 vira no-op rápido
    - ``target_url``: ``None`` — ZAP é skipado
    """
    # Import tardio: evita construir a app Celery no import das rotas
    # (os testes de webhook/rotas carregam o módulo sem broker).
    from app.core.orchestrator import start_pipeline

    return start_pipeline(
        commit_sha=commit_sha,
        repo_url=repo_url,
        pr_number=pr_number,
        installation_id=installation_id,
        repo_full_name=repo_full_name,
        repo_path=f"/tmp/aperia/{commit_sha[:12]}",
        base_sha=base_sha or commit_sha,
        head_sha=commit_sha,
        changed_files=[],
        target_url=None,
        user_id=user_id,
        repository_id=repository_id,
    )


@dataclass(frozen=True)
class ManualScanDispatch:
    """Resultado do scan manual: o commit resolvido e o branch de origem."""

    commit_sha: str
    branch: str
    status: str = "queued"


class TriggerRepositoryScanUseCase:
    """Dispara um scan manual (de branch) para um repositório já ativado."""

    def __init__(
        self,
        scan_jobs: ScanJobRepository,
        github_client_factory: Callable[[int], HeadShaResolver],
        *,
        github_app_configured: bool,
        dispatch: Callable[..., Any] = dispatch_pipeline,
    ) -> None:
        self.scan_jobs = scan_jobs
        self.github_client_factory = github_client_factory
        self.github_app_configured = github_app_configured
        self.dispatch = dispatch

    def execute(self, repository: Repository) -> ManualScanDispatch:
        """Valida, resolve o HEAD do branch default e dispara o pipeline.

        Ownership é responsabilidade do caller (a rota já respondeu 404).
        """
        if not repository.active:
            raise RepositoryInactiveError(
                "Repositorio desativado: reative antes de iniciar um scan."
            )
        if not self.github_app_configured:
            raise GithubAppNotConfiguredError(
                "GitHub App nao configurado (credenciais do App ausentes)."
            )

        branch = repository.default_branch or "main"
        try:
            commit_sha = self.github_client_factory(
                repository.installation_id
            ).get_branch_head_sha(repository.full_name, branch)
        except Exception as exc:  # noqa: BLE001 — qualquer falha vira erro de contrato
            logger.warning(
                "manual_scan_head_resolve_failed",
                repo=repository.full_name,
                branch=branch,
                error=str(exc),
            )
            raise GithubResolutionError(
                f"Nao foi possivel resolver o HEAD de {branch} no GitHub."
            ) from exc

        existente = self.scan_jobs.get_by_commit(commit_sha)
        if existente is not None and _em_andamento(existente):
            raise ScanAlreadyInProgressError(
                f"Ja existe um scan em andamento para o commit {commit_sha}."
            )

        self.dispatch(
            commit_sha=commit_sha,
            repo_url=repository.url,
            repo_full_name=repository.full_name,
            installation_id=repository.installation_id,
            # Scan de branch: não há PR onde comentar.
            pr_number=None,
            base_sha=commit_sha,
            user_id=repository.user_id,
            repository_id=repository.id,
        )
        logger.info(
            "manual_scan_dispatched",
            repo=repository.full_name,
            branch=branch,
            commit_sha=commit_sha,
            repository_id=str(repository.id),
        )
        return ManualScanDispatch(commit_sha=commit_sha, branch=branch)


def _em_andamento(job) -> bool:
    """Verdadeiro se algum tier do scan ainda está na fila ou rodando."""
    return any(
        status in _STATUS_EM_ANDAMENTO
        for status in (job.tier1_status, job.tier2_status, job.tier3_status)
        if status is not None
    )
