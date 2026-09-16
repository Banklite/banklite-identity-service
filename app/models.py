import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """Tabla users del Identity DB: (id, email, phone, country, status)."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    phone: Mapped[str] = mapped_column(String(32), nullable=False)
    country: Mapped[str] = mapped_column(String(2), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending_verification")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    kyc_records: Mapped[list["KycRecord"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", order_by="KycRecord.created_at"
    )


class KycRecord(Base):
    """Tabla kyc_records. El numero de documento nunca se guarda en claro:
    se almacena su hash SHA-256 y solo los ultimos 4 digitos visibles."""

    __tablename__ = "kyc_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    document_type: Mapped[str] = mapped_column(String(32), nullable=False)
    document_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    document_last4: Mapped[str] = mapped_column(String(4), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_reference: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    user: Mapped["User"] = relationship(back_populates="kyc_records")
