from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)

from app.domain.github.entities import Repository
from app.infrastructure.persistence.models.base import Base


class RepositoryModel(Base):
    __tablename__ = "repositories"

    __table_args__ = (
        UniqueConstraint("user_id", "github_repo_id", name="repositories_user_repo_key"),
    )

    id = Column(Uuid(as_uuid=True), primary_key=True)
    user_id = Column(Uuid(as_uuid=True), nullable=False)
    github_account_id = Column(Uuid(as_uuid=True), nullable=False)
    installation_id = Column(BigInteger, nullable=False)
    github_repo_id = Column(BigInteger, nullable=False)
    full_name = Column(Text, nullable=False)
    url = Column(Text)
    default_branch = Column(String(255))
    active = Column(Boolean, nullable=False, default=True)
    # Alvo do DAST (ZAP/Tier 3). Nullable: a maioria dos repositórios não tem
    # um deploy conhecido. Ver `app/domain/github/target_url.py`.
    target_url = Column(Text)
    created_at = Column(DateTime, nullable=False)

    @classmethod
    def from_entity(cls, repository: Repository) -> "RepositoryModel":
        return cls(
            id=repository.id,
            user_id=repository.user_id,
            github_account_id=repository.github_account_id,
            installation_id=repository.installation_id,
            github_repo_id=repository.github_repo_id,
            full_name=repository.full_name,
            url=repository.url,
            default_branch=repository.default_branch,
            active=repository.active,
            target_url=repository.target_url,
            created_at=repository.created_at,
        )

    def to_entity(self) -> Repository:
        return Repository(
            id=self.id,
            user_id=self.user_id,
            github_account_id=self.github_account_id,
            installation_id=self.installation_id,
            github_repo_id=self.github_repo_id,
            full_name=self.full_name,
            url=self.url,
            default_branch=self.default_branch,
            active=self.active,
            target_url=self.target_url,
            created_at=self.created_at,
        )
