import time
from abc import ABC, abstractmethod

import structlog

from app.domain.finding.entities import Finding

logger = structlog.get_logger()


class BaseScanner(ABC):
    TIMEOUT: int = 120

    @abstractmethod
    def scan(self, *args, **kwargs) -> list[Finding]:
        raise NotImplementedError

    def run_safe(self, *args, scanner_name: str = "", **kwargs) -> list[Finding]:
        start = time.monotonic()
        name = scanner_name or self.__class__.__name__
        try:
            findings = self.scan(*args, **kwargs)
            logger.info(
                "scanner_done",
                scanner=name,
                findings_count=len(findings),
                duration_ms=int((time.monotonic() - start) * 1000),
                commit_sha=kwargs.get("commit_sha", ""),
            )
            return findings
        except Exception as e:
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
            return []
