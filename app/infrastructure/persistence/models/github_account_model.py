from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    String,
    UniqueConstraint,
    Uuid,
)

from app.domain.github.entities import GithubAccount
from app.infrastructure.persistence.models.base import Base


class GithubAccountModel(Base):
    __tablename__ = "github_accounts"

    __table_args__ = (
        UniqueConstraint("installation_id", name="github_accounts_installation_key"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    user_id = Column(Uuid(as_uuid=True), nullable=False)
    installation_id = Column(BigInteger, nullable=False)
    github_login = Column(String(255))
    account_type = Column(String(20))
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, account: GithubAccount) -> "GithubAccountModel":
        return cls(
            id=account.id,
            user_id=account.user_id,
            installation_id=account.installation_id,
            github_login=account.github_login,
            account_type=account.account_type,
            created_at=account.created_at,
        )

    def to_entity(self) -> GithubAccount:
        return GithubAccount(
            id=self.id,
            user_id=self.user_id,
            installation_id=self.installation_id,
            github_login=self.github_login,
            account_type=self.account_type,
            created_at=self.created_at,
        )
