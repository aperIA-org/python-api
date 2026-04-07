import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    email: str = Field(..., min_length=3, max_length=500)

    model_config = ConfigDict(extra="forbid")

class UserCreatedResponse(BaseModel):
    id: uuid.UUID

class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    created_at: datetime | None
    updated_at: datetime | None

    model_config = {"from_attributes": True}
