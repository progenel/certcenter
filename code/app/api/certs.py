from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from pathlib import Path
from app.db import get_db
from app.models import Artifact, Certificate, CertRequest, User
from app.schemas.certs import CertRequest, CertResponse, RevokeRequest, StatusResponse, CertSubject
from app.deps import require_token, check_role
from app.config import get_settings
from app.ca import (
    build_and_sign_cert,
    create_pkcs12,
    generate_keypair,
    issue_certificate,
    load_or_create_ca,
)
from app.crl import build_crl, write_crl
from cryptography.x509 import load_pem_x509_crl
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

router = APIRouter(prefix="/api/certs", tags=["certs"])
settings = get_settings()
CA_KEY, CA_CERT = load_or_create_ca(
    Path(settings.artifacts_path) / "ca.key",
    Path(settings.artifacts_path) / "ca.crt",
)


def _issue_cert_internal(
    payload: CertRequest,
    db: Session,
    actor: User,
    owner_user_id: str | None = None,
    request_id: str | None = None,
) -> CertResponse:
    check_role(actor, db, ["admin", "officer"])
    # Если нет CSR и subject, подставляем CN из владельца либо актера
    if not payload.csr_pem and not payload.subject:
        owner = db.get(User, owner_user_id) if owner_user_id else actor
        fallback_cn = (getattr(owner, "full_name", None) or getattr(owner, "username", None) or "user-cert")
        payload.subject = CertSubject(cn=fallback_cn)
    cert_id = str(uuid4())
    builder, public_key = issue_certificate(CA_KEY, CA_CERT, payload.profile, payload.csr_pem, payload.subject.dict() if payload.subject else None)
    if payload.generate_key or public_key is None:
        key = generate_keypair()
        public_key = key.public_key()
    else:
        key = None
    signed_cert = build_and_sign_cert(builder, public_key, CA_KEY)
    fp_hasher = hashes.Hash(hashes.SHA256())
    fp_hasher.update(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    pubkey_fp = fp_hasher.finalize().hex()
    pem_bytes = signed_cert.public_bytes(serialization.Encoding.PEM)
    pem_path = Path(settings.artifacts_path) / f"{pubkey_fp}.pem"
    pem_path.write_bytes(pem_bytes)
    p12_path = None
    key_path = None
    if payload.generate_key and key:
        p12_bytes = create_pkcs12(cert_id, signed_cert, key)
        p12_path = Path(settings.artifacts_path) / f"{pubkey_fp}.p12"
        p12_path.write_bytes(p12_bytes)
        key_path = Path(settings.artifacts_path) / f"{pubkey_fp}-key.pem"
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    cert = Certificate(
        id=cert_id,
        serial=hex(signed_cert.serial_number)[2:],
        profile=payload.profile,
        status="issued",
        pem=pem_bytes.decode("utf-8"),
        created_at=datetime.utcnow(),
        user_id=owner_user_id,
    )
    db.add(cert)
    db.add(
        Artifact(
            id=str(uuid4()),
            kind="cert-pem",
            url=str(pem_path),
            description=f"Certificate PEM for {cert_id} serial {cert.serial}",
            owner_user_id=owner_user_id or actor.id if actor else None,
            created_at=datetime.utcnow(),
        )
    )
    if p12_path:
        db.add(
            Artifact(
                id=str(uuid4()),
                kind="p12",
                url=str(p12_path),
                description=f"PKCS#12 bundle for {cert_id} serial {cert.serial}",
                owner_user_id=owner_user_id or actor.id if actor else None,
                created_at=datetime.utcnow(),
            )
        )
    if key_path:
        db.add(
            Artifact(
                id=str(uuid4()),
                kind="key-pem",
                url=str(key_path),
                description=f"Private key PEM for {cert_id} serial {cert.serial}",
                owner_user_id=owner_user_id or actor.id if actor else None,
                created_at=datetime.utcnow(),
            )
        )
    db.commit()
    db.refresh(cert)
    return CertResponse(
        id=cert.id,
        serial=cert.serial,
        status=cert.status,
        profile=cert.profile,
        pem=cert.pem,
        created_at=cert.created_at,
        user_id=cert.user_id,
    )


@router.get("", response_model=list[CertResponse], dependencies=[Depends(require_token)])
def list_certs(db: Session = Depends(get_db)) -> list[CertResponse]:
    certs = db.query(Certificate).all()
    return [
        CertResponse(
            id=c.id,
            serial=c.serial,
            status=c.status,
            profile=c.profile,
            pem=c.pem,
            created_at=c.created_at,
            user_id=c.user_id,
        )
        for c in certs
    ]


@router.post("", response_model=CertResponse, dependencies=[Depends(require_token)])
def issue_cert(payload: CertRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> CertResponse:
    return _issue_cert_internal(payload, db=db, actor=user, owner_user_id=user.id)


@router.post("/{cert_id}/renew", response_model=CertResponse, dependencies=[Depends(require_token)])
def renew_cert(cert_id: str, payload: CertRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> CertResponse:
    check_role(user, db, ["admin", "officer"])
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    cert.status = "reissued"
    cert.serial = f"{cert_id[:8]}-r"
    cert.profile = payload.profile
    cert.created_at = datetime.utcnow()
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return CertResponse(
        id=cert.id,
        serial=cert.serial,
        status=cert.status,
        profile=cert.profile,
        pem=cert.pem,
        created_at=cert.created_at,
        user_id=cert.user_id,
    )


@router.post("/{cert_id}/revoke", response_model=StatusResponse, dependencies=[Depends(require_token)])
def revoke_cert(cert_id: str, payload: RevokeRequest, user=Depends(require_token), db: Session = Depends(get_db)) -> StatusResponse:
    check_role(user, db, ["admin", "officer"])
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    cert.status = "revoked"
    cert.revoked_at = datetime.utcnow()
    # rebuild CRL
    revoked = db.query(Certificate).filter(Certificate.status == "revoked").all()
    revoked_serials = []
    for c in revoked:
        try:
            serial_int = int(c.serial, 16)
        except ValueError:
            continue
        revoked_serials.append((serial_int, c.revoked_at or datetime.utcnow()))
    crl_bytes = build_crl(CA_KEY, CA_CERT, revoked_serials)
    crl_path = Path(settings.artifacts_path) / "crl.pem"
    write_crl(crl_bytes, crl_path)
    db.add(
        Artifact(
            id=str(uuid4()),
            kind="crl",
            url=str(crl_path),
            description="CRL",
            owner_user_id=None,
            created_at=datetime.utcnow(),
        )
    )
    db.add(cert)
    db.commit()
    return StatusResponse(
        serial=cert.serial,
        status="revoked",
        reason=payload.reason or "unspecified",
        revoked_at=cert.revoked_at,
    )


@router.get("/{cert_id}", response_model=CertResponse)
def get_cert(cert_id: str, db: Session = Depends(get_db)) -> CertResponse:
    cert = db.get(Certificate, cert_id)
    if not cert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Certificate not found")
    return CertResponse(
        id=cert.id,
        serial=cert.serial,
        status=cert.status,
        profile=cert.profile,
        pem=cert.pem,
        created_at=cert.created_at,
        user_id=cert.user_id,
    )


@router.get("/status/{serial}", response_model=StatusResponse)
def check_status(serial: str, db: Session = Depends(get_db)) -> StatusResponse:
    # Проверяем в БД
    cert = db.query(Certificate).filter(Certificate.serial == serial).first()
    if cert and cert.status == "revoked":
        return StatusResponse(serial=serial, status="revoked", reason="revoked", revoked_at=cert.revoked_at)
    # Проверяем CRL-файл
    crl_path = Path(settings.artifacts_path) / "crl.pem"
    if crl_path.exists():
        crl = load_pem_x509_crl(crl_path.read_bytes())
        for revoked in crl:
            if hex(revoked.serial_number)[2:] == serial:
                return StatusResponse(
                    serial=serial,
                    status="revoked",
                    reason="revoked",
                    revoked_at=revoked.revocation_date,
                )
    status_str = cert.status if cert else "unknown"
    return StatusResponse(serial=serial, status=status_str, reason=None, revoked_at=None)
