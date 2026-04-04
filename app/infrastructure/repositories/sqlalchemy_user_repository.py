import uuid

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.persistence.models.user_model import UserModel

class SQLAlchemyUserRepository(UserRepository):
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: uuid.UUID) -> UserModel | None:
        return self.db.get(UserModel, user_id)

    def insert(
        self,
        username: str | None,
        password: str | None,
        email: str | None,
    ) -> UserModel:
        user = UserModel(username=username, password=password, email=email)
        try:
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
        except SQLAlchemyError:
            self.db.rollback()
            raise
        return user
