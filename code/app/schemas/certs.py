from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class CertSubject(BaseModel):
    cn: str = Field(..., description="Common Name")
    o: Optional[str] = Field(None, description="Organization")
    ou: Optional[str] = Field(None, description="Organizational Unit")
    email: Optional[str] = Field(None, description="Email address")


class CertRequest(BaseModel):
    csr_pem: Optional[str] = Field(None, description="CSR PEM, если клиент сам генерирует ключ")
    subject: Optional[CertSubject] = Field(None, description="DN для серверной генерации")
    profile: str = Field(..., description="Профиль использования (подпись/шифрование/VPN)")
    generate_key: bool = Field(
        False,
        description="Создать ключ на сервере и вернуть PKCS#12 (если false — ожидаем CSR)",
    )
    pkcs12_password: Optional[str] = Field(
        None, description="Пароль для PKCS#12 (только при серверной генерации)"
    )


class CertResponse(BaseModel):
    id: str
    serial: str
    status: str
    profile: str
    pem: Optional[str] = None
    created_at: datetime
    user_id: Optional[str] = None


class RevokeRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Причина отзыва")


class StatusResponse(BaseModel):
    serial: str
    status: str
    reason: Optional[str] = None
    revoked_at: Optional[datetime] = None


class CertRequestCreate(BaseModel):
    profile: str
    csr_pem: Optional[str] = None
    comment: Optional[str] = None


class CertRequestOut(BaseModel):
    id: str
    user_id: str
    profile: str
    status: str
    comment: Optional[str] = None
    created_at: datetime
