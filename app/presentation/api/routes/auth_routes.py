from __future__ import annotations

import hashlib
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.application.exceptions import (
    InvalidCredentialsError,
    TokenExpiredError,
    TokenReusedError,
    TokenRevokedError,
)
from app.application.use_cases.login_use_case import LoginCommand, LoginUseCase
from app.application.use_cases.refresh_token_use_case import RefreshTokenUseCase
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.repositories.sqlalchemy_refresh_token_repository import (
    SQLAlchemyRefreshTokenRepository,
)
from app.infrastructure.repositories.sqlalchemy_user_repository import SQLAlchemyUserRepository
from app.infrastructure.security.argon2_password_service import Argon2PasswordService
from app.infrastructure.security.rate_limit import limite_por_ip
from app.presentation.schemas.auth_schema import LoginRequest, RefreshRequest, TokenResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

# Resposta generica para qualquer falha de autenticacao.
# Nao expoe se foi email ou senha que falhou.
_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Credenciais invalidas ou token expirado.",
    headers={"WWW-Authenticate": "Bearer"},
)

_INTERNAL_DB_ERROR = HTTPException(
    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    detail="Internal server error",
)

# Respostas de erro reaproveitadas na documentação OpenAPI das rotas de auth.
_AUTH_ERROR_RESPONSES = {
    401: {"description": "Credenciais inválidas ou token expirado/revogado/reusado.", "content": {"application/json": {"example": {"detail": "Credenciais invalidas ou token expirado."}}}},
    500: {"description": "Erro interno ao acessar o banco.", "content": {"application/json": {"example": {"detail": "Internal server error"}}}},
}


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login",
    response_description="Autenticação bem-sucedida.",
    responses=_AUTH_ERROR_RESPONSES,
    # Forca bruta de senha e o risco real aqui: sem teto, a unica barreira e o
    # tamanho da senha. 10 a cada 15 min cobre quem erra a senha de verdade.
    dependencies=[Depends(limite_por_ip(escopo="login", maximo=10, janela_s=900))],
)
async def login(
    body: LoginRequest,
    request: Request,
    session: Session = Depends(get_db),
):
    """
    Autentica o usuario e retorna um par access_token + refresh_token.

    - access_token: JWT de curta duracao (15 min por padrao)
    - refresh_token: token opaco de longa duracao (7 dias por padrao)
    """
    use_case = LoginUseCase(
        user_repo=SQLAlchemyUserRepository(session),
        token_repo=SQLAlchemyRefreshTokenRepository(session),
        password_verifier=Argon2PasswordService(),
    )

    try:
        tokens = await use_case.execute(LoginCommand(email=body.email, password=body.password))
        session.commit()
    except InvalidCredentialsError as exc:
        session.rollback()
        logger.warning(
            "login_failed",
            extra={
                "email_domain": body.email.split("@")[-1] if "@" in body.email else "unknown",
                "ip": request.client.host if request.client else None,
            },
        )
        raise _UNAUTHORIZED from exc
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("login_db_error", exc_info=exc)
        raise _INTERNAL_DB_ERROR from exc

    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Renovar tokens (rotação)",
    response_description="Novo par de tokens emitido.",
    responses=_AUTH_ERROR_RESPONSES,
)
async def refresh(
    body: RefreshRequest,
    session: Session = Depends(get_db),
):
    """
    Troca um refresh_token valido por um novo par de tokens (rotacao).

    Se o refresh_token ja tiver sido usado anteriormente (reuso suspeito),
    toda a familia de tokens e invalidada.
    """
    use_case = RefreshTokenUseCase(
        token_repo=SQLAlchemyRefreshTokenRepository(session),
    )

    try:
        tokens = await use_case.execute(body.refresh_token)
        session.commit()
    except TokenReusedError as exc:
        # NAO faz rollback: o use case ja revogou a familia inteira e essa
        # revogacao PRECISA persistir — e a resposta ao reuso. Um rollback aqui
        # (o que havia antes) desfazia a defesa, deixando a familia viva.
        session.commit()
        logger.warning("refresh_token_reuse_attempt_blocked")
        raise _UNAUTHORIZED from exc
    except (TokenExpiredError, TokenRevokedError) as exc:
        session.rollback()
        raise _UNAUTHORIZED from exc
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("refresh_db_error", exc_info=exc)
        raise _INTERNAL_DB_ERROR from exc

    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout",
    response_description="Token revogado (ou já inválido). Sem corpo de resposta.",
    responses={
        500: {"description": "Erro interno ao acessar o banco.", "content": {"application/json": {"example": {"detail": "Internal server error"}}}},
    },
)
async def logout(
    body: RefreshRequest,
    session: Session = Depends(get_db),
):
    """
    Invalida o refresh_token fornecido.
    Sempre retorna 204, mesmo se o token ja estiver invalido (evita oracle).
    """
    token_repo = SQLAlchemyRefreshTokenRepository(session)
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    try:
        # Revogacao silenciosa: nao levanta erro se o token nao existir.
        await token_repo.revoke_by_hash(token_hash)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("logout_db_error", exc_info=exc)
        raise _INTERNAL_DB_ERROR from exc
