import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from app.application.use_cases.create_user_use_case import CreateUserUseCase
from app.application.use_cases.get_user_use_case import GetUserUseCase
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.repositories.sqlalchemy_user_repository import SQLAlchemyUserRepository
from app.presentation.schemas.user_schema import UserCreate, UserResponse

router = APIRouter(prefix="/users", tags=["users"])

@router.post("", response_model=UserResponse, status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
    repository = SQLAlchemyUserRepository(db)
    create_user_use_case = CreateUserUseCase(repository)
    try:
        user = create_user_use_case.execute(
            username=payload.username,
            password=payload.password,
            email=payload.email,
        )
    except ProgrammingError as exc:
        message = str(exc.orig).lower() if getattr(exc, "orig", None) else str(exc).lower()
        if "insufficientprivilege" in message or "permission denied" in message:
            raise HTTPException(
                status_code=500,
                detail="Usuario do banco sem permissao para inserir na tabela users",
            ) from exc
        raise
    return UserResponse.model_validate(user)

@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: uuid.UUID, db: Session = Depends(get_db)) -> UserResponse:
    repository = SQLAlchemyUserRepository(db)
    get_user_use_case = GetUserUseCase(repository)
    user = get_user_use_case.execute(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)
