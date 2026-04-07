import uuid
from typing import Protocol

from app.domain.entities.user import User


class UserRepository(Protocol):
    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        ...

    def exists_by_email(self, email: str) -> bool:
        ...

    def insert(
        self,
        username: str,
        password: str,
        email: str,
    ) -> User:
        ...
