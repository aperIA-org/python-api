from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4

from app.domain.scan.value_objects import ToolStatus


@dataclass
class ScanToolRun:
    """A execução de UMA ferramenta dentro de um tier de UMA execução.

    Existe porque ``ScanJob`` só tem ``tier{1,2,3}_status``: o dashboard sabia
    dizer "o Tier 2 concluiu", nunca "o Trivy concluiu e o Prowler não rodou".
    Pior, ``BaseScanner.run_safe`` engole a exceção e devolve ``[]``, então
    "rodou e não achou nada" e "quebrou" chegavam ao banco como a mesma coisa —
    a diferença só existia na linha do structlog, que ninguém consulta.

    ``tool`` é um identificador estável, não o nome da classe: o Semgrep roda em
    dois tiers com escopos diferentes (``semgrep-changed`` no diff,
    ``semgrep-full`` na árvore) e precisa aparecer como duas linhas.

    ``reason`` guarda o motivo quando ele existe — ``no_iac_files``,
    ``no_target_url``, o tipo da exceção. É o campo que transforma um
    ``skipped`` mudo em uma frase que a UI pode mostrar.
    """

    commit_sha: str
    tier: int
    tool: str
    status: ToolStatus
    scan_job_id: UUID
    id: UUID = field(default_factory=uuid4)
    reason: str | None = None
    findings_count: int | None = None
    duration_ms: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
