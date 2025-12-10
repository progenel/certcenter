from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import require_token, check_role
from app.models import CertRequest, Certificate
from app.schemas.certs import CertRequest as CertRequestSchema
from app.schemas.certs import CertRequestCreate, CertRequestOut, CertResponse
from app.api.certs import _issue_cert_internal

router = APIRouter(prefix="/api/requests", tags=["cert-requests"])


@router.post("/certs", response_model=CertRequestOut, status_code=status.HTTP_201_CREATED)
def create_cert_request(payload: CertRequestCreate, user=Depends(require_token), db: Session = Depends(get_db)):
    req = CertRequest(
        id=str(uuid4()),
        user_id=user.id,
        profile=payload.profile,
        csr_pem=payload.csr_pem,
        comment=payload.comment,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.add(req)
    db.commit()
    db.refresh(req)
    return CertRequestOut(
        id=req.id,
        user_id=req.user_id,
        profile=req.profile,
        status=req.status,
        comment=req.comment,
        created_at=req.created_at,
    )


@router.get("/certs", response_model=list[CertRequestOut])
def list_cert_requests(user=Depends(require_token), db: Session = Depends(get_db)):
    # Офицер безопасности/админ видят все, пользователь — только свои
    if user.username in ("admin", "officer"):
        reqs = db.query(CertRequest).all()
    else:
        reqs = db.query(CertRequest).filter(CertRequest.user_id == user.id).all()
    return [
        CertRequestOut(
            id=r.id,
            user_id=r.user_id,
            profile=r.profile,
            status=r.status,
            comment=r.comment,
            created_at=r.created_at,
        )
        for r in reqs
    ]


@router.post("/certs/{req_id}/approve", response_model=CertResponse)
def approve_cert_request(
    req_id: str,
    user=Depends(require_token),
    db: Session = Depends(get_db),
):
    # Только админ/офицер
    if user.username not in ("admin", "officer"):
        check_role(user, db, ["admin", "officer"])
    req = db.get(CertRequest, req_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    req.status = "approved"
    cert_payload = CertRequestSchema(
        csr_pem=req.csr_pem,
        subject=None,
        profile=req.profile,
        generate_key=True,
        pkcs12_password=None,
    )
    return _issue_cert_internal(
        cert_payload,
        db=db,
        actor=user,
        owner_user_id=req.user_id,
        request_id=req.id,
    )


@router.post("/certs/{req_id}/reject", response_model=CertRequestOut)
def reject_cert_request(
    req_id: str,
    user=Depends(require_token),
    db: Session = Depends(get_db),
):
    if user.username not in ("admin", "officer"):
        check_role(user, db, "admin")
    req = db.get(CertRequest, req_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    req.status = "rejected"
    db.add(req)
    db.commit()
    db.refresh(req)
    return CertRequestOut(
        id=req.id,
        user_id=req.user_id,
        profile=req.profile,
        status=req.status,
        comment=req.comment,
        created_at=req.created_at,
    )
