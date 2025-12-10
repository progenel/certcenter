import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import HTTPException, status
from jwt import PyJWTError, decode as jwt_decode, encode as jwt_encode

from app.config import get_settings

settings = get_settings()

def hash_password(password: str) -> str:
    """MVP hash (SHA-256)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    return hash_password(password) == password_hash


def generate_token(username: str) -> str:
    """Generate JWT token (MVP)."""
    expire = datetime.utcnow() + timedelta(minutes=settings.jwt_exp_minutes)
    payload = {"sub": username, "exp": expire}
    return jwt_encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    try:
        return jwt_decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
