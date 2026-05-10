import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CommitSha:
    value: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.value):
            raise ValueError(f"Commit SHA inválido: {self.value}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class RepoUrl:
    value: str

    def __post_init__(self) -> None:
        if not self.value.startswith(("https://github.com/", "https://gitlab.com/", "git@")):
            raise ValueError(f"RepoUrl inválida: {self.value}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class DiffContext:
    base_sha: str
    head_sha: str
    changed_files: tuple[str, ...]
    additions: int = 0
    deletions: int = 0
