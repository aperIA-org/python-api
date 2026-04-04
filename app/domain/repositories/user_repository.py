import uuid
from typing import Protocol

from app.infrastructure.persistence.models.user_model import UserModel


class UserRepository(Protocol):
    def get_by_id(self, user_id: uuid.UUID) -> UserModel | None:
        ...

    def insert(
        self,
        username: str | None,
        password: str | None,
        email: str | None,
    ) -> UserModel:
        ...
