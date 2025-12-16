from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    full_name = Column(String, nullable=True)
    password_hash = Column(String, nullable=True)  # для MVP
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    roles = relationship("UserRole", back_populates="user")
    cert_requests = relationship("CertRequest", back_populates="user")
    public_keys = relationship("UserPublicKey", back_populates="user")


class Role(Base):
    __tablename__ = "roles"

    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)

    users = relationship("UserRole", back_populates="role")


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id = Column(String, ForeignKey("users.id"), primary_key=True)
    role_id = Column(String, ForeignKey("roles.id"), primary_key=True)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(String, primary_key=True)
    serial = Column(String, unique=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    profile = Column(String, nullable=False)
    status = Column(String, default="issued")
    pem = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(String, primary_key=True)
    kind = Column(String, nullable=False)
    url = Column(String, nullable=False)
    description = Column(String, nullable=True)
    owner_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User")


class Envelope(Base):
    __tablename__ = "envelopes"

    id = Column(String, primary_key=True)
    filename = Column(String, nullable=False)
    recipients = Column(Text, nullable=False)  # comma-separated for MVP
    storage_url = Column(String, nullable=True)
    direct_encrypt = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    keys = relationship("EnvelopeKey", back_populates="envelope")


class EnvelopeKey(Base):
    __tablename__ = "envelope_keys"

    id = Column(String, primary_key=True)
    envelope_id = Column(String, ForeignKey("envelopes.id"), nullable=False)
    recipient_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    recipient_serial = Column(String, nullable=True)
    recipient_label = Column(String, nullable=True)
    encrypted_key_b64 = Column(Text, nullable=False)

    envelope = relationship("Envelope", back_populates="keys")
    recipient_user = relationship("User")


class UserPublicKey(Base):
    __tablename__ = "user_public_keys"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    pem = Column(Text, nullable=False)
    label = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="public_keys")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True)
    actor = Column(String, nullable=True)
    action = Column(String, nullable=False)
    object_type = Column(String, nullable=True)
    object_id = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class CertRequest(Base):
    __tablename__ = "cert_requests"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    profile = Column(String, nullable=False)
    csr_pem = Column(Text, nullable=True)
    status = Column(String, default="pending")  # pending/approved/rejected/issued
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="cert_requests")


class Message(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True)
    sender_user_id = Column(String, ForeignKey("users.id"), nullable=False)
    subject = Column(String, nullable=True)
    recipients = Column(Text, nullable=False)  # comma-separated for MVP
    storage_url = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User")
    keys = relationship("MessageKey", back_populates="message")


class MessageKey(Base):
    __tablename__ = "message_keys"

    id = Column(String, primary_key=True)
    message_id = Column(String, ForeignKey("messages.id"), nullable=False)
    recipient_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    recipient_serial = Column(String, nullable=True)
    recipient_label = Column(String, nullable=True)
    encrypted_key_b64 = Column(Text, nullable=False)

    message = relationship("Message", back_populates="keys")
    recipient_user = relationship("User")
