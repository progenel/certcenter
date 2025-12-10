from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def load_or_create_ca(key_path: Path, cert_path: Path):
    key = None
    cert = None
    if key_path.exists() and cert_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "Demo CA"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Org")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=1))
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .sign(private_key=key, algorithm=hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _build_subject(payload_subject: Optional[dict], fallback_cn: str) -> x509.Name:
    attrs = []
    if payload_subject and payload_subject.get("cn"):
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, payload_subject["cn"]))
        if payload_subject.get("o"):
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, payload_subject["o"]))
        if payload_subject.get("ou"):
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, payload_subject["ou"]))
        if payload_subject.get("email"):
            attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, payload_subject["email"]))
    else:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, fallback_cn))
    return x509.Name(attrs)


def issue_certificate(
    ca_key,
    ca_cert,
    profile: str,
    csr_pem: Optional[str],
    subject_payload: Optional[dict],
    days: int = 365,
):
    serial = x509.random_serial_number()
    not_before = datetime.utcnow() - timedelta(days=1)
    not_after = datetime.utcnow() + timedelta(days=days)

    eku_oids = []
    if "подпись" in profile or "sign" in profile:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if "шифр" in profile or "encrypt" in profile:
        eku_oids.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)
    if "VPN" in profile or "vpn" in profile:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    if csr_pem:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        subject = csr.subject
        public_key = csr.public_key()
    else:
        # Subject provided; public key will be generated later if needed
        subject = _build_subject(subject_payload, fallback_cn=str(serial))
        public_key = None

    builder = (
        x509.CertificateBuilder()
        .issuer_name(ca_cert.subject)
        .subject_name(subject)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)

    return builder, public_key


def generate_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_and_sign_cert(builder, public_key, ca_key):
    return builder.public_key(public_key).sign(private_key=ca_key, algorithm=hashes.SHA256())


def create_pkcs12(name: str, cert, key):
    return pkcs12.serialize_key_and_certificates(
        name.encode("utf-8"),
        key,
        cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )
