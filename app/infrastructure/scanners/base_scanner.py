import time
from abc import ABC, abstractmethod
from datetime import datetime

import structlog

from app.domain.finding.entities import Finding
from app.domain.scan.value_objects import ToolStatus

logger = structlog.get_logger()


class BaseScanner(ABC):
    TIMEOUT: int = 120

    @abstractmethod
    def scan(self, *args, **kwargs) -> list[Finding]:
        raise NotImplementedError

    def run_safe(
        self,
        *args,
        scanner_name: str = "",
        tool_id: str = "",
        tier: int | None = None,
        **kwargs,
    ) -> list[Finding]:
        """Roda o scanner sem deixar exceção escapar, e registra o desfecho.

        ``tool_id`` + ``tier`` ligam a persistência em ``scan_tool_runs``. São
        opcionais para não quebrar chamadas antigas, mas todo call site do
        pipeline os passa: é AQUI, e só aqui, que existe a diferença entre
        "rodou e não achou nada" e "estourou" — depois do ``return []`` as duas
        situações são o mesmo valor. ``tool_id`` é explícito (e não o nome da
        classe) porque o Semgrep roda em dois tiers com escopos diferentes e
        precisa aparecer como duas ferramentas: ``semgrep-changed`` e
        ``semgrep-full``.
        """
        start = time.monotonic()
        started_at = datetime.utcnow()
        name = scanner_name or self.__class__.__name__
        # Marca `running` ANTES de executar. Sem isso a linha só nasce no fim, e
        # durante o scan o dashboard sabia quais ferramentas já terminaram mas
        # não qual estava rodando — teria que adivinhar pela ordem do pipeline.
        # O upsert por `(scan_job_id, tool)` sobrescreve isso no fim.
        self._registrar(
            tool_id=tool_id,
            tier=tier,
            commit_sha=kwargs.get("commit_sha", ""),
            status=ToolStatus.RUNNING,
            started_at=started_at,
            completed_at=None,
        )
        try:
            findings = self.scan(*args, **kwargs)
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.info(
                "scanner_done",
                scanner=name,
                findings_count=len(findings),
                duration_ms=duration_ms,
                commit_sha=kwargs.get("commit_sha", ""),
            )
            self._registrar(
                tool_id=tool_id,
                tier=tier,
                commit_sha=kwargs.get("commit_sha", ""),
                status=ToolStatus.DONE,
                findings_count=len(findings),
                duration_ms=duration_ms,
                started_at=started_at,
            )
            return findings
        except Exception as e:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.warning(
                "scanner_skipped",
                scanner=name,
                # `error` sozinho é a mensagem da biblioteca que estourou, e ela
                # descreve o sintoma, não a causa: um ZAP morto por OOM chega
                # aqui como "No address associated with hostname", que parece
                # DNS. O tipo da exceção é o que separa "a ferramenta não está
                # lá" de "não terminou no tempo".
                error_type=type(e).__name__,
                error=str(e),
                commit_sha=kwargs.get("commit_sha", ""),
            )
            self._registrar(
                tool_id=tool_id,
                tier=tier,
                commit_sha=kwargs.get("commit_sha", ""),
                status=ToolStatus.FAILED,
                # Mesmo racional do log: o tipo separa "não está instalada" de
                # "estourou o tempo", e é o que a UI consegue mostrar.
                reason=f"{type(e).__name__}: {e}",
                duration_ms=duration_ms,
                started_at=started_at,
            )
            return []

    @staticmethod
    def _registrar(*, tool_id: str, tier: int | None, commit_sha: str, **campos) -> None:
        """Grava a linha de ``scan_tool_runs``, se o call site pediu.

        Import tardio de propósito: ``base_scanner`` é importado por adapters que
        rodam fora do worker (e nos testes de unidade dos scanners), e puxar a
        camada de persistência no topo do módulo arrastaria SQLAlchemy e a
        engine para dentro deles sem necessidade.
        """
        if not tool_id or tier is None or not commit_sha:
            return
        from app.infrastructure.persistence import scan_tool_run_writer

        campos.setdefault("completed_at", datetime.utcnow())
        scan_tool_run_writer.record_tool_run(
            commit_sha=commit_sha,
            tier=tier,
            tool=tool_id,
            **campos,
        )
