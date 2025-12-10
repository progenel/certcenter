from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., description="Имя пользователя")
    password: str = Field(..., description="Пароль")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
