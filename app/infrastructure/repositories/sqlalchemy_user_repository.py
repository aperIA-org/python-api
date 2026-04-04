import uuid

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.persistence.models.user_model import UserModel

class SQLAlchemyUserRepository(UserRepository):
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: uuid.UUID) -> UserModel | None:
        return self.db.get(UserModel, user_id)

    def exists_by_email(self, email: str) -> bool:
        normalized_email = email.lower()
        query = self.db.query(UserModel.id).filter(func.lower(UserModel.email) == normalized_email)
        return self.db.query(query.exists()).scalar() or False

    def insert(
        self,
        username: str,
        password: str,
        email: str,
    ) -> UserModel:
        user = UserModel(
            username=username,
            password=password,
            email=email.strip().lower(),
        )
        try:
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
        except SQLAlchemyError:
            self.db.rollback()
            raise
        return user
