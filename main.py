import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, status
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

app = FastAPI(title="Python API")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d])\S{8,}$"
)

users_by_id: dict[str, dict] = {}
users_by_email: dict[str, dict] = {}
users_by_username: dict[str, dict] = {}


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    createdAt: datetime


class TokenResponse(BaseModel):
    token: str
    tokenType: str = "Bearer"


def validate_password_strength(password: str) -> None:
    if not PASSWORD_PATTERN.match(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "password deve ter ao menos 8 caracteres, com letra maiuscula, "
                "minuscula, numero e simbolo."
            ),
        )


def make_user_response(user: dict) -> UserResponse:
    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        createdAt=user["createdAt"],
    )


def generate_token(user: dict) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRES_MINUTES)
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "email": user["email"],
        "exp": expires_at,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token nao informado."
        )

    token = authorization.split(" ", 1)[1]

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido ou expirado.",
        ) from error

    user_id = payload.get("sub")
    user = users_by_id.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario nao encontrado."
        )
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/users", status_code=status.HTTP_201_CREATED)
def register_user(payload: RegisterRequest) -> dict:
    username = payload.username.strip()
    email = payload.email.lower()

    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="username e obrigatorio."
        )

    validate_password_strength(payload.password)

    if email in users_by_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email ja cadastrado."
        )

    if username in users_by_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username ja cadastrado."
        )

    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "passwordHash": pwd_context.hash(payload.password),
        "createdAt": datetime.now(timezone.utc),
    }
    users_by_id[user["id"]] = user
    users_by_email[email] = user
    users_by_username[username] = user

    return {"message": "Usuario cadastrado com sucesso.", "user": make_user_response(user)}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register_user_alias(payload: RegisterRequest) -> dict:
    return register_user(payload)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    user = users_by_email.get(payload.email.lower())

    if not user or not pwd_context.verify(payload.password, user["passwordHash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais invalidas."
        )

    return TokenResponse(token=generate_token(user))


@app.get("/auth/me")
def me(current_user: dict = Depends(get_current_user)) -> dict:
    return {"user": make_user_response(current_user)}
