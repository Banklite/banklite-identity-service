import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import kyc_provider
from ..database import get_db
from ..events import EVENT_IDENTITY_VERIFIED, publish_event
from ..models import DocumentoIdentidad, EvaluacionRiesgo, VerificacionKyc
from ..schemas import KycVerifyRequest, KycVerifyResult, VerificacionKycOut
from .users import get_usuario_or_404

router = APIRouter(prefix="/kyc", tags=["kyc"])


@router.post("/verify", response_model=KycVerifyResult)
def verificar_kyc(payload: KycVerifyRequest, db: Session = Depends(get_db)):
    """Flujo completo de KYC contra el modelo oficial:

    1) registra (o reutiliza) el documento_identidad del usuario,
    2) envia el documento al proveedor KYC externo simulado y crea la
       verificacion_kyc con su resultado,
    3) calcula la evaluacion_riesgo asociada a esa verificacion,
    4) si el resultado es aprobado, actualiza el estado del usuario y
       publica el evento asincrono identity.verified.
    """
    usuario = get_usuario_or_404(db, payload.id_usuario)

    if usuario.estado == "verificado":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El usuario ya completo la verificacion KYC",
        )

    documento = (
        db.execute(
            select(DocumentoIdentidad).where(
                DocumentoIdentidad.numero_documento == payload.numero_documento
            )
        )
        .scalars()
        .first()
    )
    if documento is None:
        documento = DocumentoIdentidad(
            id_usuario=usuario.id_usuario,
            tipo_documento=payload.tipo_documento,
            numero_documento=payload.numero_documento,
            pais_emision=payload.pais_emision,
            fecha_expiracion=payload.fecha_expiracion,
        )
        db.add(documento)
    elif documento.id_usuario != usuario.id_usuario:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ese numero_documento ya esta registrado para otro usuario",
        )

    resultado, proveedor_externo = kyc_provider.verify_identity(
        payload.tipo_documento, payload.numero_documento
    )
    verificacion = VerificacionKyc(
        id_usuario=usuario.id_usuario,
        proveedor_externo=proveedor_externo,
        resultado=resultado,
    )
    db.add(verificacion)
    db.flush()  # asigna id_verificacion antes de crear la evaluacion de riesgo

    nivel_riesgo, score = kyc_provider.evaluate_risk(payload.numero_documento, resultado)
    db.add(
        EvaluacionRiesgo(
            id_verificacion=verificacion.id_verificacion,
            nivel_riesgo=nivel_riesgo,
            score=score,
        )
    )

    usuario.estado = "verificado" if resultado == "aprobado" else "rechazado"

    db.commit()
    db.refresh(verificacion)
    db.refresh(usuario)

    published = False
    if usuario.estado == "verificado":
        published = publish_event(
            EVENT_IDENTITY_VERIFIED,
            {
                "event": EVENT_IDENTITY_VERIFIED,
                "id_usuario": str(usuario.id_usuario),
                "email": usuario.email,
                "pais_residencia": usuario.pais_residencia,
                "verificado_en": verificacion.fecha_verificacion.isoformat(),
                "proveedor_externo": proveedor_externo,
            },
        )

    return KycVerifyResult(
        verificacion=VerificacionKycOut.model_validate(verificacion),
        estado_usuario=usuario.estado,
        event_published=published,
        event_name=EVENT_IDENTITY_VERIFIED if usuario.estado == "verificado" else None,
    )


@router.get("/{id_usuario}", response_model=list[VerificacionKycOut])
def historial_kyc(id_usuario: uuid.UUID, db: Session = Depends(get_db)):
    """Historial de verificaciones de un usuario, con su evaluacion de riesgo."""
    get_usuario_or_404(db, id_usuario)
    stmt = (
        select(VerificacionKyc)
        .where(VerificacionKyc.id_usuario == id_usuario)
        .order_by(VerificacionKyc.fecha_verificacion.desc())
    )
    return db.execute(stmt).scalars().all()
