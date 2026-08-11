"""Disparo do pipeline de segurança — webhook de PR e scan manual.

Dois gatilhos, **um único caminho de disparo**: ``dispatch_pipeline`` é o ponto
onde os argumentos do canvas são preenchidos. O webhook
(``POST /webhook/github``) e o scan manual (``POST /repositories/{id}/scan``)
chamam a mesma função, então nenhum dos dois pode divergir do outro.

``TriggerRepositoryScanUseCase`` acrescenta ao scan manual o que o webhook
recebe de graça no payload: o commit HEAD do branch default (resolvido no
GitHub) e a checagem de que não há scan em andamento para aquele commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Protocol
from uuid import UUID

import structlog

from app.application.exceptions import (
    GithubAppNotConfiguredError,
    GithubResolutionError,
    RepositoryInactiveError,
    ScanAlreadyInProgressError,
)
from app.config import settings
from app.domain.github.entities import Repository
from app.domain.scan.repositories import ScanJobRepository

logger = structlog.get_logger()


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
    target_url: str | None = None,
) -> Any:
    """Dispara o canvas Celery completo para um commit.

    ``pr_number=None`` significa scan de branch (manual): o pipeline é o mesmo,
    apenas não há PR onde comentar.

    O canvas não recebe ``repo_path``: cada task que lê arquivos faz o próprio
    checkout efêmero do commit (``infrastructure/git/repo_checkout``), porque
    os workers de T1 e T2 rodam em containers sem filesystem compartilhado.

    ``changed_files`` sai daqui **vazio de propósito**, e não por omissão: a
    camada de aplicação não fala com o GitHub nem com o disco. Quem precisa do
    escopo calcula o diff ``base_sha..commit_sha`` dentro do próprio checkout —
    no scan de PR os dois SHAs diferem e o diff existe; no scan manual de
    branch ``base_sha == commit_sha``, não há base contra o que comparar e o
    comportamento correto é varrer a árvore inteira.

    ``target_url`` é o alvo do DAST (ZAP) no Tier 3 e vem do repositório
    cadastrado (``Repository.target_url``), não do evento: nem o payload do
    webhook nem o scan manual sabem onde a aplicação está publicada — quem
    sabe é o usuário, que informou no cadastro do repositório. ``None``
    (repositório sem deploy conhecido, ou PR de repositório não cadastrado)
    faz o Tier 3 pular o ZAP com ``reason="no_target_url"``, que era o
    comportamento fixo antes deste campo existir.
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
        base_sha=base_sha or commit_sha,
        head_sha=commit_sha,
        changed_files=[],
        target_url=target_url,
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
        stale_after_minutes: int | None = None,
        commit: Callable[[], None] | None = None,
    ) -> None:
        self.scan_jobs = scan_jobs
        self.github_client_factory = github_client_factory
        self.github_app_configured = github_app_configured
        self.dispatch = dispatch
        # Controle de transação continua na camada de apresentação (a rota
        # passa ``db.commit``). O caso de uso só precisa dele para fechar a
        # liberação de um job travado ANTES de disparar o pipeline — ver o
        # comentário em ``execute``.
        self.commit = commit
        # Lido em runtime (não como default de argumento) para que testes
        # possam sobrescrever ``settings`` via monkeypatch.
        self.stale_after_minutes = (
            stale_after_minutes
            if stale_after_minutes is not None
            else settings.SCAN_STALE_AFTER_MINUTES
        )

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
        if existente is not None and existente.em_andamento():
            # Checagem preguiçosa de job travado: um "running" que não progride
            # há mais que o limiar não representa nada rodando de verdade (a
            # fila do broker se perdeu). Ele não pode bloquear — sem isso o 409
            # vira prisão perpétua para este commit, já que a UNIQUE em
            # commit_sha faz sempre cair na mesma linha.
            if existente.esta_travado(
                agora=datetime.utcnow(), limiar_minutos=self.stale_after_minutes
            ):
                self.scan_jobs.fail_pending_tiers(commit_sha)
                # Commit ANTES do dispatch, e não depois: ``dispatch`` chama
                # ``create_scan_job``, que abre a própria Session e atualiza
                # esta mesma linha. Com o UPDATE ainda aberto aqui, aquela
                # escrita ficaria esperando um lock que só sai quando esta
                # requisição terminar — que por sua vez espera o dispatch.
                if self.commit is not None:
                    self.commit()
                logger.warning(
                    "scan_job_stale_liberado_no_disparo",
                    commit_sha=commit_sha,
                    repo=repository.full_name,
                    ultimo_progresso_em=existente.ultimo_progresso_em.isoformat(),
                    limiar_minutos=self.stale_after_minutes,
                )
            else:
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
            # Alvo do DAST: o que o usuário cadastrou neste repositório.
            target_url=repository.target_url,
        )
        logger.info(
            "manual_scan_dispatched",
            repo=repository.full_name,
            branch=branch,
            commit_sha=commit_sha,
            repository_id=str(repository.id),
        )
        return ManualScanDispatch(commit_sha=commit_sha, branch=branch)
