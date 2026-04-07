import uuid

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.domain.entities.user import User
from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.persistence.models.user_model import UserModel

class SQLAlchemyUserRepository(UserRepository):
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        user_model = self.db.get(UserModel, user_id)
        if user_model is None:
            return None
        return self._to_domain(user_model)

    def exists_by_email(self, email: str) -> bool:
        normalized_email = email.lower()
        query = self.db.query(UserModel.id).filter(func.lower(UserModel.email) == normalized_email)
        return self.db.query(query.exists()).scalar() or False

    def insert(
        self,
        username: str,
        password: str,
        email: str,
    ) -> User:
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
        return self._to_domain(user)

    def _to_domain(self, user_model: UserModel) -> User:
        return User(
            id=user_model.id,
            username=user_model.username,
            email=user_model.email,
            created_at=user_model.created_at,
            updated_at=user_model.updated_at,
        )
