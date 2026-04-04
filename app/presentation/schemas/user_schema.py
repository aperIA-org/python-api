import uuid

from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str | None = None
    password: str | None = None
    email: str | None = None

class UserCreatedResponse(BaseModel):
    id: uuid.UUID

class UserResponse(BaseModel):
    id: uuid.UUID
    username: str | None
    password: str | None
    email: str | None

    model_config = {"from_attributes": True}
