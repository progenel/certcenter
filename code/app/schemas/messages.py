from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class MessageSendRequest(BaseModel):
    recipients: List[str] = Field(..., description="Список получателей (username или serial)")
    subject: Optional[str] = Field(None, description="Тема сообщения")
    content: str = Field(..., description="Текст сообщения")


class MessageMeta(BaseModel):
    id: str
    subject: Optional[str]
    sender: Optional[str]
    recipients: List[str]
    created_at: datetime


class MessageResponse(MessageMeta):
    pass


class MessageDecryptRequest(BaseModel):
    private_key_pem: str = Field(..., description="Приватный ключ PEM")
    private_key_password: Optional[str] = Field(None, description="Пароль ключа, если есть")
    recipient_serial: Optional[str] = Field(None, description="Серийный номер получателя (если несколько ключей)")
