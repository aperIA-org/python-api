from enum import Enum
from dataclasses import dataclass


class ScanTier(int, Enum):
    ONE = 1
    TWO = 2
    THREE = 3


class TierStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    # Interrompido por quem disparou. Terminal, e distinto de FAILED: nada
    # quebrou — alguém decidiu parar, e o relatório precisa dizer isso.
    CANCELLED = "cancelled"


class ToolStatus(str, Enum):
    """Desfecho de UMA ferramenta dentro de um tier.

    Espelha ``TierStatus`` de propósito — a tela mostra os dois lado a lado —
    mas acrescenta ``DEGRADED``, que só existe no nível da ferramenta: os
    passos de I.A caem para uma heurística quando o Claude falha, e o tier
    fecha como ``done`` mesmo assim. Sem esse valor, "a I.A respondeu" e "a I.A
    caiu e o pipeline seguiu com o plano B" ficariam indistinguíveis.
    """

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    # Espelha TierStatus.CANCELLED: a ferramenta que estava rodando quando
    # alguem parou o scan. Sem isso ela ficaria "running" para sempre.
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class RepoUrl:
    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith("https://"):
            raise ValueError(f"RepoUrl deve começar com https://: {self.value}")

    def __str__(self) -> str:
        return self.value
