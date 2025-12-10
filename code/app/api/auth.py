from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.schemas.auth import LoginRequest, TokenResponse
from app.db import get_db
from app.models import Role, User, UserRole
from app.security import generate_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User inactive")
    # Ensure roles for admin/user
    role_map = {
        "admin": "admin",
        "officer": "officer",
        "user": "user",
    }
    role_name = role_map.get(user.username, "user")
    if db.query(Role).filter(Role.id == role_name).first() is None:
        db.add(Role(id=role_name, name=role_name, description=f"Demo {role_name} role"))
        db.commit()
    if db.query(UserRole).filter(UserRole.user_id == user.id, UserRole.role_id == role_name).first() is None:
        db.add(UserRole(user_id=user.id, role_id=role_name))
        db.commit()
    token = generate_token(user.username)
    return TokenResponse(access_token=token, token_type="bearer")
