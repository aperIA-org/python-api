"""Gravação de findings vista pelos scan workers, com contrato de falha explícito.

Fina camada sobre ``infrastructure.persistence.finding_writer``: o módulo de
infraestrutura sabe gravar; aqui mora o que fazer quando **não** dá para gravar.

Irmão de ``checkout_guard`` e pelo mesmo motivo. A filosofia "scanner falho →
``[]``" existe porque um scanner ausente ainda deixa os outros trabalharem.
Perder a gravação é outra coisa: o scan encontrou algo e o produto não vai
mostrar. O dashboard lê ``GET /findings``, não o payload do canvas — então um
pipeline que conclui "com sucesso" depois de falhar a escrita está afirmando
"repositório limpo" sobre um repositório onde ele mesmo achou vulnerabilidade.

E como uma task que falha interrompe o canvas, ninguém mais marcaria o
``ScanJob``: ele ficaria ``running`` até a varredura de jobs travados
(``RecoverStaleScanJobsUseCase``, limiar ``SCAN_STALE_AFTER_MINUTES``),
bloqueando novos disparos daquele commit com 409 nesse intervalo. Por isso o
guard encerra os tiers pendentes antes de propagar, com a mesma operação
idempotente da varredura.
"""

from __future__ import annotations

import structlog

from app.core.exceptions import FindingPersistenceError
from app.domain.finding.entities import Finding
from app.infrastructure.persistence import scan_job_writer
from app.infrastructure.persistence.finding_writer import persist_findings

logger = structlog.get_logger()


def persistir_ou_falhar(
    findings: list[Finding], *, commit_sha: str, tier: int
) -> int:
    """Grava os findings do tier; encerra o ``ScanJob`` e propaga se falhar."""
    try:
        return persist_findings(findings, commit_sha=commit_sha, tier=tier)
    except FindingPersistenceError as exc:
        motivo = str(exc)
        logger.error(
            "scan_persistencia_falhou",
            tier=tier,
            commit_sha=commit_sha,
            count=len(findings),
            error=motivo,
        )
        scan_job_writer.fail_pending_tiers(
            commit_sha, motivo=f"persistencia_tier{tier}: {motivo}"
        )
        raise
