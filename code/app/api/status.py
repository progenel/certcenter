from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Certificate
from app.schemas.certs import StatusResponse

router = APIRouter(prefix="/api/status", tags=["status"])


@router.get("/{serial}", response_model=StatusResponse)
def get_status(serial: str, db: Session = Depends(get_db)) -> StatusResponse:
    cert = db.query(Certificate).filter(Certificate.serial == serial).first()
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    return StatusResponse(
        serial=cert.serial,
        status=cert.status,
        reason=None if cert.status != "revoked" else "revoked",
        revoked_at=None,
    )
