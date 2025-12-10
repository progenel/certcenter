from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class PublicKeyIn(BaseModel):
    pem: str = Field(..., description="Публичный ключ в PEM")
    label: Optional[str] = Field(None, description="Метка ключа/серийный номер, если есть")


class PublicKeyOut(BaseModel):
    id: str
    user_id: str
    label: Optional[str]
    created_at: datetime
