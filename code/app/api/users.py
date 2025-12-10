from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization

from app.db import get_db
from app.models import User, UserPublicKey
from app.schemas.auth import LoginRequest
from app.security import hash_password
from app.deps import require_token, check_role
from app.schemas.user_keys import PublicKeyIn, PublicKeyOut

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[LoginRequest], dependencies=[Depends(require_token)])
def list_users(user=Depends(require_token), db: Session = Depends(get_db)) -> list[LoginRequest]:
    check_role(user, db, "admin")
    users = db.query(User).all()
    return [LoginRequest(username=u.username, password="***") for u in users]


@router.post("", response_model=LoginRequest, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_token)])
def create_user(payload: LoginRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> LoginRequest:
    check_role(user, db, "admin")
    exists = db.query(User).filter(User.username == payload.username).first()
    if exists:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User exists")
    user = User(
        id=str(uuid4()),
        username=payload.username,
        full_name=payload.username,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    db.add(user)
    db.commit()
    return LoginRequest(username=user.username, password="***")


@router.get("/me/public-key", response_model=PublicKeyOut, dependencies=[Depends(require_token)])
def get_my_public_key(user=Depends(require_token), db: Session = Depends(get_db)) -> PublicKeyOut:
    key = (
        db.query(UserPublicKey)
        .filter(UserPublicKey.user_id == user.id, UserPublicKey.is_active == True)  # noqa: E712
        .order_by(UserPublicKey.created_at.desc())
        .first()
    )
    if not key:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Public key not set")
    return PublicKeyOut(id=key.id, user_id=key.user_id, label=key.label, created_at=key.created_at)


@router.post("/me/public-key", response_model=PublicKeyOut, dependencies=[Depends(require_token)])
def set_my_public_key(payload: PublicKeyIn, user=Depends(require_token), db: Session = Depends(get_db)) -> PublicKeyOut:
    # validate PEM
    try:
        serialization.load_pem_public_key(payload.pem.encode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Некорректный PEM ключ")
    # deactivate old keys
    db.query(UserPublicKey).filter(UserPublicKey.user_id == user.id).update({"is_active": False})
    key = UserPublicKey(
        id=str(uuid4()),
        user_id=user.id,
        pem=payload.pem,
        label=payload.label,
        is_active=True,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return PublicKeyOut(id=key.id, user_id=key.user_id, label=key.label, created_at=key.created_at)
