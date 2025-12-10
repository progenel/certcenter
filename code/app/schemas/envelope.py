from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class EnvelopeRequest(BaseModel):
    recipients: List[str] = Field(
        ..., description="Список идентификаторов получателей или их сертификатов"
    )
    filename: str = Field(..., description="Имя исходного файла")
    content_b64: str = Field(..., description="Содержимое файла в base64")
    direct_encrypt: bool = Field(
        False,
        description="При одном получателе — прямое шифрование его открытым ключом (опционально)",
    )


class EnvelopeResponse(BaseModel):
    id: str
    download_url: str
    created_at: datetime
    recipients: List[str]
    keys: List["EncryptedKey"] = Field(default_factory=list)
    key_b64: str | None = None
    nonce_b64: str | None = None


class EncryptedKey(BaseModel):
    recipient: str
    cert_serial: str
    encrypted_key_b64: str


class DecryptRequest(BaseModel):
    recipient_serial: str
    private_key_pem: str
    private_key_password: str | None = None


class EnvelopeMetadata(BaseModel):
    id: str
    recipients: List[str]
    filename: str
    created_at: datetime
    keys: List[EncryptedKey] = Field(default_factory=list)


EnvelopeResponse.model_rebuild()
EnvelopeMetadata.model_rebuild()
