import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import DocumentoIdentidad, EvaluacionRiesgo, Usuario, VerificacionKyc
from ..schemas import CambiarClave, UsuarioCreate, UsuarioOut
from ..security import hash_password, verify_password
from .. import kyc_provider
from ..events import EVENT_IDENTITY_VERIFIED, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["usuarios"])


def get_usuario_or_404(db: Session, id_usuario: uuid.UUID) -> Usuario:
    usuario = db.get(Usuario, id_usuario)
    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No existe un usuario con id {id_usuario}",
        )
    return usuario


def _ejecutar_kyc(
    db: Session,
    usuario: Usuario,
    *,
    numero_doc: str,
    tipo_doc: str,
    pais_emision: str,
    fecha_vencimiento: str | None,
) -> Usuario:
    """Ejecuta (o reintenta) la verificación KYC de un usuario y actualiza su estado."""
    from datetime import datetime

    try:
        usuario.estado_kyc = "VERIFICANDO"
        db.commit()

        # Registrar o reutilizar documento
        documento = (
            db.execute(
                select(DocumentoIdentidad).where(
                    DocumentoIdentidad.numero_documento == numero_doc
                )
            )
            .scalars()
            .first()
        )
        if documento is None:
            from datetime import date, timedelta
            fecha_exp = date.today() + timedelta(days=365 * 5)
            if fecha_vencimiento:
                try:
                    fecha_exp = datetime.strptime(fecha_vencimiento, "%Y-%m-%d").date()
                except ValueError:
                    pass
            documento = DocumentoIdentidad(
                id_usuario=usuario.id_usuario,
                tipo_documento=tipo_doc,
                numero_documento=numero_doc,
                pais_emision=pais_emision,
                fecha_expiracion=fecha_exp,
            )
            db.add(documento)
        elif documento.id_usuario != usuario.id_usuario:
            # Documento ya registrado para otro usuario → rechazo
            usuario.estado = "rechazado"
            usuario.estado_kyc = "RECHAZADO"
            db.commit()
            db.refresh(usuario)
            return usuario

        # Llamar a la API de verificación
        resultado, proveedor_externo = kyc_provider.verify_identity(tipo_doc, numero_doc)

        verificacion = VerificacionKyc(
            id_usuario=usuario.id_usuario,
            proveedor_externo=proveedor_externo,
            resultado=resultado,
        )
        db.add(verificacion)
        db.flush()

        nivel_riesgo, score = kyc_provider.evaluate_risk(numero_doc, resultado)
        db.add(
            EvaluacionRiesgo(
                id_verificacion=verificacion.id_verificacion,
                nivel_riesgo=nivel_riesgo,
                score=score,
            )
        )

        usuario.estado = "verificado" if resultado == "aprobado" else "rechazado"
        usuario.estado_kyc = "VERIFICADO" if resultado == "aprobado" else "RECHAZADO"
        db.commit()
        db.refresh(usuario)

        if usuario.estado == "verificado":
            publish_event(
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
    except Exception as exc:
        logger.warning("Error en verificación automática KYC para usuario %s: %s", usuario.id_usuario, exc)
        try:
            usuario.estado_kyc = "ERROR_VERIFICACION"
            db.commit()
            db.refresh(usuario)
        except Exception:
            pass

    return usuario


@router.post("", response_model=UsuarioOut, status_code=status.HTTP_201_CREATED)
def crear_usuario(payload: UsuarioCreate, db: Session = Depends(get_db)):
    """Registra un usuario y ejecuta la verificación KYC automáticamente.

    Flujo:
    1) Crea el usuario con estado 'pendiente_verificacion'.
    2) Si tiene cédula/documento, llama automáticamente a la API de verificación.
    3) Actualiza el estado a 'verificado' o 'rechazado' según el resultado.

    El PRIMER usuario registrado recibe role='admin'.
    """
    total_usuarios = db.execute(select(Usuario)).scalars().first()
    role = "admin" if total_usuarios is None else "cliente"

    from datetime import datetime

    estado_kyc = "PENDIENTE"
    if payload.fecha_nacimiento:
        try:
            fn = datetime.strptime(payload.fecha_nacimiento, "%Y-%m-%d").date()
            today = datetime.now().date()
            edad = today.year - fn.year - ((today.month, today.day) < (fn.month, fn.day))
            if edad < 18:
                if not (
                    payload.representante_nombre
                    and payload.representante_documento
                    and payload.representante_parentesco
                    and payload.representante_telefono
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            "Para menores de 18 años es obligatorio proveer los datos del representante "
                            "(nombre, documento, parentesco y teléfono)"
                        ),
                    )
                estado_kyc = "MENOR_CON_REPRESENTANTE"
        except ValueError:
            pass

    usuario = Usuario(
        nombre=payload.nombre,
        apellido=payload.apellido,
        email=payload.email.lower(),
        telefono=payload.telefono,
        pais_residencia=payload.pais_residencia,
        estado="pendiente_verificacion",
        password_hash=hash_password(payload.password),
        fecha_nacimiento=payload.fecha_nacimiento,
        servicio_solicitado=payload.servicio_solicitado,
        cedula=payload.cedula,
        fecha_expedicion=payload.fecha_expedicion,
        fecha_vencimiento=payload.fecha_vencimiento,
        pais_expedicion=payload.pais_expedicion,
        representante_nombre=payload.representante_nombre,
        representante_documento=payload.representante_documento,
        representante_tipo_documento=payload.representante_tipo_documento,
        representante_parentesco=payload.representante_parentesco,
        representante_telefono=payload.representante_telefono,
        representante_email=payload.representante_email,
        tipo_documento=payload.tipo_documento,
        estado_kyc=estado_kyc,
        role=role,
    )
    db.add(usuario)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"El email {payload.email} ya esta registrado",
        )
    db.refresh(usuario)

    # ─── VERIFICACIÓN AUTOMÁTICA KYC ────────────────────────────────────────
    # Solo si el usuario tiene cédula y el rol es 'cliente'.
    # El admin no necesita pasar por KYC.
    if role == "admin":
        usuario.estado = "verificado"
        usuario.estado_kyc = "VERIFICADO"
        db.commit()
        db.refresh(usuario)
        return usuario

    numero_doc = payload.cedula or ""
    if not numero_doc:
        # Sin documento → queda en pendiente, deberá completar datos luego
        return usuario

    _ejecutar_kyc(
        db,
        usuario,
        numero_doc=numero_doc,
        tipo_doc=payload.tipo_documento or "cedula",
        pais_emision=payload.pais_residencia or "CO",
        fecha_vencimiento=payload.fecha_vencimiento,
    )
    return usuario


from ..security import hash_password, require_admin


@router.get("", response_model=list[UsuarioOut])
def listar_usuarios(
    db: Session = Depends(get_db),
    estado: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin_user: dict = Depends(require_admin),
):
    stmt = select(Usuario).order_by(Usuario.fecha_registro.desc()).limit(limit).offset(offset)
    if estado:
        stmt = stmt.where(Usuario.estado == estado)
    return db.execute(stmt).scalars().all()


@router.get("/{id_usuario}", response_model=UsuarioOut)
def consultar_usuario(id_usuario: uuid.UUID, db: Session = Depends(get_db)):
    """Endpoint consumido de forma SINCRONA por account-service antes de abrir una cuenta."""
    return get_usuario_or_404(db, id_usuario)


from ..schemas import UsuarioUpdate


@router.patch("/{id_usuario}", response_model=UsuarioOut)
def actualizar_usuario(id_usuario: uuid.UUID, payload: UsuarioUpdate, db: Session = Depends(get_db)):
    usuario = get_usuario_or_404(db, id_usuario)
    if payload.cedula:
        usuario.cedula = payload.cedula
    if payload.fecha_nacimiento:
        usuario.fecha_nacimiento = payload.fecha_nacimiento
    if payload.fecha_expedicion:
        usuario.fecha_expedicion = payload.fecha_expedicion
    if payload.fecha_vencimiento:
        usuario.fecha_vencimiento = payload.fecha_vencimiento
    if payload.pais_expedicion:
        usuario.pais_expedicion = payload.pais_expedicion
    usuario.estado_kyc = "EN_REVISION"
    db.commit()
    db.refresh(usuario)
    return usuario


@router.put("/{id_usuario}/cambiar-clave")
def cambiar_clave(id_usuario: uuid.UUID, payload: CambiarClave, db: Session = Depends(get_db)):
    usuario = get_usuario_or_404(db, id_usuario)
    if not usuario.password_hash or not verify_password(payload.clave_actual, usuario.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La contraseña actual es incorrecta",
        )
    usuario.password_hash = hash_password(payload.clave_nueva)
    db.commit()
    return {"mensaje": "Contraseña actualizada exitosamente"}


@router.post("/{id_usuario}/reverificar",response_model=UsuarioOut)
def reverificar_usuario(
    id_usuario: uuid.UUID,
    db: Session = Depends(get_db),
    admin_user: dict = Depends(require_admin),
):
    """Reintenta la verificación KYC de un usuario que quedó pendiente o con error."""
    usuario = get_usuario_or_404(db, id_usuario)
    if usuario.estado == "verificado":
        return usuario
    if not usuario.cedula:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El usuario no tiene documento registrado; debe completar su perfil primero",
        )
    return _ejecutar_kyc(
        db,
        usuario,
        numero_doc=usuario.cedula,
        tipo_doc=usuario.tipo_documento or "cedula",
        pais_emision=usuario.pais_residencia or "CO",
        fecha_vencimiento=usuario.fecha_vencimiento,
    )
