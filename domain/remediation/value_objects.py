from dataclasses import dataclass
from enum import Enum


class RemediationDecision(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class PatchContent:
    """Conteúdo de um patch gerado para code suggestion."""
    file_path: str
    original_code: str
    patched_code: str
    diff: str
    explanation: str

    def __post_init__(self) -> None:
        if not self.file_path:
            raise ValueError("file_path não pode ser vazio")
        if not self.diff:
            raise ValueError("diff não pode ser vazio")
