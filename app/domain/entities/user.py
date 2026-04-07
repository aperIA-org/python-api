import uuid
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class User:
    id: uuid.UUID
    username: str
    email: str
    created_at: datetime | None
    updated_at: datetime | None
