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


@dataclass(frozen=True)
class RepoUrl:
    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith("https://"):
            raise ValueError(f"RepoUrl deve começar com https://: {self.value}")

    def __str__(self) -> str:
        return self.value
