import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import kyc_provider
from ..database import get_db
from ..events import EVENT_IDENTITY_VERIFIED, publish_event
from ..models import KycRecord, User
from ..schemas import KycOut, KycRequest, KycResult, UserCreate, UserOut

router = APIRouter(prefix="/users", tags=["users"])


def _get_user_or_404(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No existe un usuario con id {user_id}",
        )
    return user


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    """Registra un usuario. Queda en estado pending_verification hasta que pase el KYC."""
    user = User(
        email=payload.email.lower(),
        phone=payload.phone,
        country=payload.country,
        status="pending_verification",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"El email {payload.email} ya esta registrado",
        )
    db.refresh(user)
    return user


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    if status_filter:
        stmt = stmt.where(User.status == status_filter)
    return db.execute(stmt).scalars().all()


@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: uuid.UUID, db: Session = Depends(get_db)):
    """Endpoint consumido de forma SINCRONA por account-service antes de abrir una cuenta."""
    return _get_user_or_404(db, user_id)


@router.post("/{user_id}/kyc", response_model=KycResult)
def submit_kyc(user_id: uuid.UUID, payload: KycRequest, db: Session = Depends(get_db)):
    """Envia la identidad al proveedor externo. Si aprueba, publica identity.verified."""
    user = _get_user_or_404(db, user_id)

    if user.status == "verified":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El usuario ya completo la verificacion KYC",
        )

    verification_status, reference = kyc_provider.verify_identity(
        payload.document_type, payload.document_number
    )

    record = KycRecord(
        user_id=user.id,
        document_type=payload.document_type,
        document_hash=kyc_provider.hash_document(payload.document_number),
        document_last4=payload.document_number[-4:],
        verification_status=verification_status,
        provider_reference=reference,
    )
    user.status = "verified" if verification_status == "approved" else "rejected"

    db.add(record)
    db.commit()
    db.refresh(record)
    db.refresh(user)

    published = False
    if user.status == "verified":
        published = publish_event(
            EVENT_IDENTITY_VERIFIED,
            {
                "event": EVENT_IDENTITY_VERIFIED,
                "user_id": str(user.id),
                "email": user.email,
                "country": user.country,
                "verified_at": record.created_at.isoformat(),
                "provider_reference": reference,
            },
        )

    return KycResult(
        kyc=KycOut.model_validate(record),
        user_status=user.status,
        event_published=published,
        event_name=EVENT_IDENTITY_VERIFIED if user.status == "verified" else None,
    )


@router.get("/{user_id}/kyc", response_model=list[KycOut])
def list_kyc(user_id: uuid.UUID, db: Session = Depends(get_db)):
    _get_user_or_404(db, user_id)
    stmt = select(KycRecord).where(KycRecord.user_id == user_id).order_by(KycRecord.created_at.desc())
    return db.execute(stmt).scalars().all()
