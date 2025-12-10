import base64
import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509

from app.config import get_settings
from app.db import get_db
from app.deps import require_token
from app.models import Artifact, Envelope, EnvelopeKey, User, Certificate, UserPublicKey
from app.schemas.envelope import (
    DecryptRequest,
    EnvelopeMetadata,
    EnvelopeRequest,
    EnvelopeResponse,
    EncryptedKey,
)

router = APIRouter(prefix="/api/envelope", tags=["envelope"])
settings = get_settings()

AES_KEY_LEN = 32  # 256-bit
NONCE_LEN = 12


def aesgcm_encrypt(content: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, content, associated_data=None)


def aesgcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def _resolve_recipient(recipient: str, db: Session) -> dict:
    user = db.query(User).filter(User.username == recipient).first()
    cert: Certificate | None = None
    user_key: UserPublicKey | None = None
    label = recipient
    if user:
        user_key = (
            db.query(UserPublicKey)
            .filter(UserPublicKey.user_id == user.id, UserPublicKey.is_active == True)  # noqa: E712
            .order_by(UserPublicKey.created_at.desc())
            .first()
        )
        cert = (
            db.query(Certificate)
            .filter(Certificate.user_id == user.id, Certificate.status == "issued")
            .order_by(Certificate.created_at.desc())
            .first()
        )
        label = user.username
    if cert is None and user_key is None:
        cert = db.query(Certificate).filter(Certificate.serial == recipient, Certificate.status == "issued").first()
        if cert:
            owner = db.query(User).filter(User.id == cert.user_id).first()
            label = owner.username if owner else recipient
    if user_key:
        try:
            public_key = serialization.load_pem_public_key(user_key.pem.encode("utf-8"))
        except Exception:
            raise HTTPException(status_code=400, detail=f"Публичный ключ получателя {recipient} поврежден")
        cert_serial = user_key.label or "public-key"
        cert_obj = None
    else:
        if cert is None or not cert.pem:
            raise HTTPException(status_code=404, detail=f"Нет активного сертификата для получателя {recipient}")
        cert_obj = x509.load_pem_x509_certificate(cert.pem.encode("utf-8"))
        public_key = cert_obj.public_key()
        cert_serial = cert.serial
    user_id = user.id if user else (cert.user_id if cert else None)
    return {
        "label": label,
        "user_id": user_id,
        "cert_obj": cert_obj,
        "public_key": public_key,
        "cert_serial": cert_serial,
    }


def _ensure_env_access(env: Envelope, user: User, db: Session) -> None:
    if user.username in ("admin", "officer"):
        return
    tokens = [t.strip() for t in (env.recipients or "").split(",") if t.strip()]
    if user.username in tokens:
        return
    has_key = (
        db.query(EnvelopeKey)
        .filter(EnvelopeKey.envelope_id == env.id, EnvelopeKey.recipient_user_id == user.id)
        .first()
        is not None
    )
    if not has_key:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.post("", response_model=EnvelopeResponse, dependencies=[Depends(require_token)])
def encrypt(payload: EnvelopeRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> EnvelopeResponse:
    recipients = [_resolve_recipient(r, db) for r in payload.recipients]
    if not recipients:
        raise HTTPException(status_code=400, detail="Нужен хотя бы один получатель")
    env_id = str(uuid4())
    key = os.urandom(AES_KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    plaintext = base64.b64decode(payload.content_b64)
    ciphertext = aesgcm_encrypt(plaintext, key, nonce)
    storage_path = Path(settings.artifacts_path) / f"{env_id}.enc"
    storage_path.write_bytes(nonce + ciphertext)

    env = Envelope(
        id=env_id,
        filename=payload.filename,
        recipients=",".join([r["label"] for r in recipients]),
        storage_url=str(storage_path),
        direct_encrypt=False,
        created_at=datetime.utcnow(),
    )
    db.add(env)
    db.add(
        Artifact(
            id=str(uuid4()),
            kind="envelope",
            url=str(storage_path),
            description="Encrypted file (AES-GCM)",
            owner_user_id=None,  # доступ по списку получателей
            created_at=datetime.utcnow(),
        )
    )
    key_records: list[EncryptedKey] = []
    for r in recipients:
        public_key = r["public_key"]
        enc_key = public_key.encrypt(
            key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        enc_key_b64 = base64.b64encode(enc_key).decode("utf-8")
        key_records.append(
            EncryptedKey(recipient=r["label"], cert_serial=r["cert_serial"], encrypted_key_b64=enc_key_b64)
        )
        db.add(
            EnvelopeKey(
                id=str(uuid4()),
                envelope_id=env_id,
                recipient_user_id=r["user_id"],
                recipient_serial=r["cert_serial"],
                recipient_label=r["label"],
                encrypted_key_b64=enc_key_b64,
            )
        )
    db.commit()
    return EnvelopeResponse(
        id=env.id,
        download_url=f"/api/envelope/{env.id}",
        created_at=env.created_at,
        recipients=[r["label"] for r in recipients],
        keys=key_records,
        key_b64=None,
        nonce_b64=None,
    )


@router.get("/{env_id}", response_model=EnvelopeMetadata, dependencies=[Depends(require_token)])
def get_envelope(env_id: str, user=Depends(require_token), db: Session = Depends(get_db)) -> EnvelopeMetadata:
    env = db.get(Envelope, env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Envelope not found")
    _ensure_env_access(env, user, db)
    keys_query = db.query(EnvelopeKey).filter(EnvelopeKey.envelope_id == env.id)
    if user.username not in ("admin", "officer"):
        keys_query = keys_query.filter(EnvelopeKey.recipient_user_id == user.id)
    keys = [
        EncryptedKey(
            recipient=k.recipient_label or "",
            cert_serial=k.recipient_serial or "",
            encrypted_key_b64=k.encrypted_key_b64,
        )
        for k in keys_query.all()
    ]
    return EnvelopeMetadata(
        id=env.id,
        recipients=env.recipients.split(",") if env.recipients else [],
        filename=env.filename,
        created_at=env.created_at,
        keys=keys,
    )


@router.get("/{env_id}/download", dependencies=[Depends(require_token)])
def download_encrypted(env_id: str, user=Depends(require_token), db: Session = Depends(get_db)):
    env = db.get(Envelope, env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Envelope not found")
    _ensure_env_access(env, user, db)
    path = Path(env.storage_url)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, filename=path.name)


@router.post("/{env_id}/decrypt")
def decrypt_env(env_id: str, payload: DecryptRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> dict:
    env = db.get(Envelope, env_id)
    if not env:
        raise HTTPException(status_code=404, detail="Envelope not found")
    _ensure_env_access(env, user, db)
    key_row = (
        db.query(EnvelopeKey)
        .filter(
            EnvelopeKey.envelope_id == env.id,
            EnvelopeKey.recipient_serial == payload.recipient_serial,
        )
        .first()
    )
    if key_row is None:
        key_row = (
            db.query(EnvelopeKey)
            .filter(EnvelopeKey.envelope_id == env.id, EnvelopeKey.recipient_user_id == user.id)
            .first()
        )
    if key_row is None:
        raise HTTPException(status_code=404, detail="Ключ для получателя не найден")
    if user.username not in ("admin", "officer") and key_row.recipient_user_id and key_row.recipient_user_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        private_key = serialization.load_pem_private_key(
            payload.private_key_pem.encode("utf-8"), password=(payload.private_key_password or None).encode("utf-8") if payload.private_key_password else None
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Не удалось загрузить закрытый ключ")
    try:
        aes_key = private_key.decrypt(
            base64.b64decode(key_row.encrypted_key_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Не удалось расшифровать ключ")
    path = Path(env.storage_url)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    data = path.read_bytes()
    nonce = data[:NONCE_LEN]
    ciphertext = data[NONCE_LEN:]
    try:
        plaintext = aesgcm_decrypt(ciphertext, aes_key, nonce)
    except Exception:
        raise HTTPException(status_code=400, detail="Decrypt failed")
    return {"content_b64": base64.b64encode(plaintext).decode("utf-8")}
