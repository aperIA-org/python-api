import uuid

from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.persistence.models.user_model import UserModel


class GetUserUseCase:
    def __init__(self, user_repository: UserRepository) -> None:
        self.user_repository = user_repository

    def execute(self, user_id: uuid.UUID) -> UserModel | None:
        return self.user_repository.get_by_id(user_id)
