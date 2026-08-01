"""Checkout efêmero visto pelos scan workers, com contrato de falha explícito.

Fina camada sobre ``infrastructure.git.repo_checkout``: o módulo de
infraestrutura sabe clonar; aqui mora o que fazer quando **não** dá para
clonar.

Por que não é best-effort como os scanners: a filosofia "scanner falho → ``[]``"
existe porque um scanner ausente ainda deixa os outros trabalharem. Sem a
árvore em disco não há trabalho nenhum — Semgrep, TruffleHog e Trivy leem
arquivos. Fingir sucesso devolveria zero findings e o pipeline concluiria
dizendo "nada encontrado", que é o pior desfecho possível num produto de
segurança. Então a task **falha**.

E como uma task que falha interrompe o canvas, ninguém mais marcaria o
``ScanJob``: ele ficaria ``running`` até a varredura de jobs travados
(``RecoverStaleScanJobsUseCase``, limiar ``SCAN_STALE_AFTER_MINUTES``) —
bloqueando novos disparos daquele commit com 409 nesse intervalo. Por isso o
guard encerra os tiers pendentes antes de propagar a exceção, usando
exatamente a mesma operação idempotente da varredura.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager

import structlog

from app.core.exceptions import RepoCheckoutError
from app.infrastructure.git.repo_checkout import checkout_repo
from app.infrastructure.persistence import scan_job_writer

logger = structlog.get_logger()


@contextmanager
def checkout_para_scan(
    *,
    tier: int,
    repo_full_name: str,
    commit_sha: str,
    installation_id: int,
    base_sha: str | None = None,
) -> Iterator[str]:
    """Entrega o caminho da árvore do commit; falha limpa se o checkout quebrar.

    ``ExitStack`` (em vez de um ``with`` simples) delimita o ``try`` **só** à
    entrada do context manager: uma exceção vinda do corpo do ``with`` do
    caller não pode ser confundida com falha de checkout, mas a limpeza do
    diretório continua garantida pelo stack.
    """
    with ExitStack() as stack:
        try:
            caminho = stack.enter_context(
                checkout_repo(
                    repo_full_name=repo_full_name,
                    commit_sha=commit_sha,
                    installation_id=installation_id,
                    base_sha=base_sha,
                )
            )
        except RepoCheckoutError as exc:
            motivo = str(exc)  # já vem redigido de ``repo_checkout``
            logger.error(
                "scan_checkout_falhou",
                tier=tier,
                repo=repo_full_name,
                commit_sha=commit_sha,
                error=motivo,
            )
            scan_job_writer.fail_pending_tiers(
                commit_sha, motivo=f"checkout_tier{tier}: {motivo}"
            )
            raise
        yield caminho
