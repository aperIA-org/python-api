import uuid

from app.domain.entities.user import User
from app.domain.repositories.user_repository import UserRepository


class GetUserUseCase:
    def __init__(self, user_repository: UserRepository) -> None:
        self.user_repository = user_repository

    def execute(self, user_id: uuid.UUID) -> User | None:
        return self.user_repository.get_by_id(user_id)
