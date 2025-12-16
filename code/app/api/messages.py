import base64
import os
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.deps import require_token
from app.models import Certificate, Message, MessageKey, User, UserPublicKey
from app.schemas.messages import MessageDecryptRequest, MessageMeta, MessageResponse, MessageSendRequest

router = APIRouter(prefix="/api/messages", tags=["messages"])
settings = get_settings()

AES_KEY_LEN = 32
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


def _ensure_message_access(msg: Message, user: User, db: Session) -> None:
    if user.username in ("admin", "officer") or msg.sender_user_id == user.id:
        return
    has_key = (
        db.query(MessageKey)
        .filter(MessageKey.message_id == msg.id, MessageKey.recipient_user_id == user.id)
        .first()
        is not None
    )
    if not has_key:
        raise HTTPException(status_code=403, detail="Forbidden")


@router.post("", response_model=MessageResponse, dependencies=[Depends(require_token)])
def send_message(payload: MessageSendRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> MessageResponse:
    recipients = [_resolve_recipient(r, db) for r in payload.recipients]
    if not recipients:
        raise HTTPException(status_code=400, detail="Нужен хотя бы один получатель")
    msg_id = str(uuid4())
    key = os.urandom(AES_KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = aesgcm_encrypt(payload.content.encode("utf-8"), key, nonce)

    msg_dir = Path(settings.artifacts_path) / "messages"
    msg_dir.mkdir(parents=True, exist_ok=True)
    storage_path = msg_dir / f"{msg_id}.enc"
    storage_path.write_bytes(nonce + ciphertext)

    msg = Message(
        id=msg_id,
        sender_user_id=user.id,
        subject=payload.subject,
        recipients=",".join([r["label"] for r in recipients]),
        storage_url=str(storage_path),
        created_at=datetime.utcnow(),
    )
    db.add(msg)

    for r in recipients:
        public_key = r["public_key"]
        enc_key = public_key.encrypt(
            key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        enc_key_b64 = base64.b64encode(enc_key).decode("utf-8")
        db.add(
            MessageKey(
                id=str(uuid4()),
                message_id=msg_id,
                recipient_user_id=r["user_id"],
                recipient_serial=r["cert_serial"],
                recipient_label=r["label"],
                encrypted_key_b64=enc_key_b64,
            )
        )
    db.commit()
    return MessageResponse(
        id=msg.id,
        subject=msg.subject,
        sender=user.username,
        recipients=[r["label"] for r in recipients],
        created_at=msg.created_at,
    )


@router.get("", response_model=list[MessageMeta], dependencies=[Depends(require_token)])
def list_messages(user=Depends(require_token), db: Session = Depends(get_db)) -> list[MessageMeta]:
    query = db.query(Message)
    if user.username not in ("admin", "officer"):
        query = query.join(MessageKey, Message.id == MessageKey.message_id, isouter=True).filter(
            or_(
                Message.sender_user_id == user.id,
                MessageKey.recipient_user_id == user.id,
                Message.recipients.ilike(f"%{user.username}%"),
            )
        )
    messages = query.order_by(Message.created_at.desc()).all()
    result: list[MessageMeta] = []
    for m in messages:
        sender = db.query(User).filter(User.id == m.sender_user_id).first()
        result.append(
            MessageMeta(
                id=m.id,
                subject=m.subject,
                sender=sender.username if sender else None,
                recipients=m.recipients.split(",") if m.recipients else [],
                created_at=m.created_at,
            )
        )
    return result


@router.get("/{msg_id}", response_model=MessageMeta, dependencies=[Depends(require_token)])
def get_message(msg_id: str, user=Depends(require_token), db: Session = Depends(get_db)) -> MessageMeta:
    msg = db.get(Message, msg_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    _ensure_message_access(msg, user, db)
    sender = db.query(User).filter(User.id == msg.sender_user_id).first()
    return MessageMeta(
        id=msg.id,
        subject=msg.subject,
        sender=sender.username if sender else None,
        recipients=msg.recipients.split(",") if msg.recipients else [],
        created_at=msg.created_at,
    )


@router.post("/{msg_id}/decrypt")
def decrypt_message(msg_id: str, payload: MessageDecryptRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> dict:
    msg = db.get(Message, msg_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    _ensure_message_access(msg, user, db)
    key_row = (
        db.query(MessageKey)
        .filter(
            MessageKey.message_id == msg.id,
            MessageKey.recipient_serial == payload.recipient_serial,
        )
        .first()
    )
    if key_row is None:
        key_row = (
            db.query(MessageKey)
            .filter(MessageKey.message_id == msg.id, MessageKey.recipient_user_id == user.id)
            .first()
        )
    if key_row is None:
        raise HTTPException(status_code=404, detail="Ключ для получателя не найден")
    if user.username not in ("admin", "officer") and key_row.recipient_user_id and key_row.recipient_user_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        private_key = serialization.load_pem_private_key(
            payload.private_key_pem.encode("utf-8"),
            password=(payload.private_key_password or None).encode("utf-8") if payload.private_key_password else None,
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
    path = Path(msg.storage_url)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    data = path.read_bytes()
    nonce = data[:NONCE_LEN]
    ciphertext = data[NONCE_LEN:]
    try:
        plaintext = aesgcm_decrypt(ciphertext, aes_key, nonce)
    except Exception:
        raise HTTPException(status_code=400, detail="Decrypt failed")
    return {"content": plaintext.decode("utf-8", errors="ignore")}
