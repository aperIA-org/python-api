from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.persistence.models.user_model import UserModel


class CreateUserUseCase:
    def __init__(self, user_repository: UserRepository) -> None:
        self.user_repository = user_repository

    def execute(
        self,
        username: str | None,
        password: str | None,
        email: str | None,
    ) -> UserModel:
        return self.user_repository.insert(
            username=username,
            password=password,
            email=email,
        )
