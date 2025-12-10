from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


def build_crl(ca_key, ca_cert, revoked_serials: List[Tuple[int, datetime]], next_days: int = 7) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(datetime.utcnow())
        .next_update(datetime.utcnow() + timedelta(days=next_days))
    )
    for serial, revoked_at in revoked_serials:
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(revoked_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.PEM)


def write_crl(crl_bytes: bytes, path: Path) -> None:
    path.write_bytes(crl_bytes)
