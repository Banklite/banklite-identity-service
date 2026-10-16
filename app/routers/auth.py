from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Usuario
import secrets
import uuid
from datetime import datetime, timedelta

from ..schemas import (
    LoginIniciarRequest,
    LoginIniciarResponse,
    LoginRequest,
    LoginResponse,
    LoginVerificarOTPRequest,
    OTPGenerarRequest,
    OTPResponse,
    OTPValidarRequest,
    ResetClave,
    SolicitarReset,
)
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["autenticacion"])


def _buscar_usuario_por_identificador(db: Session, ident: str) -> Usuario | None:
    ident = ident.strip()
    if "@" in ident:
        return db.execute(select(Usuario).where(Usuario.email == ident.lower())).scalar_one_or_none()

    digitos = "".join(ch for ch in ident if ch.isdigit())
    if not digitos:
        return db.execute(select(Usuario).where(Usuario.email == ident.lower())).scalar_one_or_none()

    stmt = select(Usuario).where(
        (Usuario.email == ident.lower())
        | (Usuario.telefono == ident)
        | (Usuario.telefono == f"+{digitos}")
        | (Usuario.telefono == f"+57{digitos}")
        | (Usuario.telefono.ilike(f"%{digitos[-10:]}"))
        | (Usuario.cedula == ident)
    )
    return db.execute(stmt).scalars().first()


def _enmascarar_email(email: str) -> str:
    if "@" not in email:
        return email
    user, domain = email.split("@", 1)
    if len(user) <= 2:
        return f"{user[0]}***@{domain}"
    return f"{user[:2]}***@{domain}"


def _enmascarar_telefono(tel: str | None) -> str:
    if not tel:
        return "No registrado"
    clean = "".join(ch for ch in tel if ch.isdigit())
    if len(clean) >= 4:
        return f"+57 *** *** {clean[-4:]}"
    return f"***{clean}"


def _notificar_codigo_login(id_usuario: uuid.UUID, codigo: str) -> None:
    import json
    import urllib.request
    from ..config import settings
    try:
        url = f"{settings.notification_service_url}/notifications"
        payload = json.dumps({
            "id_usuario": str(id_usuario),
            "tipo": "seguridad",
            "titulo": "Tu Código de Acceso BankLite",
            "mensaje": f"Tu código de confirmación para iniciar sesión en BankLite es: {codigo}. Válido por 5 minutos. No lo compartas con nadie.",
            "enviar_correo": True,
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass
    except Exception:
        pass


@router.post("/login/solicitar-codigo", response_model=LoginIniciarResponse)
def solicitar_codigo_login(payload: LoginIniciarRequest, db: Session = Depends(get_db)):
    """Paso 1 del Login 2FA: Valida credenciales, genera OTP y lo envia a WhatsApp y Correo."""
    usuario = _buscar_usuario_por_identificador(db, payload.identificador)
    credenciales_invalidas = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Correo/teléfono o contraseña incorrectos",
    )
    if usuario is None or usuario.password_hash is None:
        raise credenciales_invalidas
    if not verify_password(payload.password, usuario.password_hash):
        raise credenciales_invalidas

    # Si el usuario registro o actualizo su telefono durante el login
    if payload.telefono and payload.telefono.strip():
        tel_limpio = payload.telefono.strip()
        if not tel_limpio.startswith("+"):
            tel_limpio = f"+57{tel_limpio}" if len(tel_limpio) == 10 else f"+{tel_limpio}"
        usuario.telefono = tel_limpio

    codigo = f"{secrets.randbelow(1_000_000):06d}"
    usuario.reset_code = codigo
    usuario.reset_code_expires = datetime.utcnow() + timedelta(minutes=5)
    db.commit()

    # Envia a WhatsApp (Green API) y Correo (Gmail SMTP)
    _notificar_codigo_login(usuario.id_usuario, codigo)

    return LoginIniciarResponse(
        requiere_2fa=True,
        id_usuario=usuario.id_usuario,
        nombre=usuario.nombre,
        email_enmascarado=_enmascarar_email(usuario.email),
        telefono_enmascarado=_enmascarar_telefono(usuario.telefono),
        mensaje="Código de confirmación enviado exitosamente a tu WhatsApp y a tu correo electrónico.",
        codigo_debug=codigo,
    )


@router.post("/login/confirmar-codigo", response_model=LoginResponse)
def confirmar_codigo_login(payload: LoginVerificarOTPRequest, db: Session = Depends(get_db)):
    """Paso 2 del Login 2FA: Valida el codigo recibido por WhatsApp/Correo y emite el JWT."""
    usuario = db.get(Usuario, payload.id_usuario)
    invalido = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Código de confirmación inválido o expirado",
    )
    if (
        usuario is None
        or not usuario.reset_code
        or not usuario.reset_code_expires
        or not secrets.compare_digest(usuario.reset_code, payload.codigo)
        or usuario.reset_code_expires < datetime.utcnow()
    ):
        raise invalido

    usuario.reset_code = None
    usuario.reset_code_expires = None
    db.commit()

    token = create_access_token(usuario.id_usuario, usuario.email, usuario.role)
    return LoginResponse(access_token=token, usuario=usuario)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Valida email/telefono + contraseña contra la tabla usuario y devuelve un JWT."""
    ident = payload.identificador or payload.email
    if not ident:
        raise HTTPException(status_code=400, detail="Debe proporcionar email o identificador")

    usuario = _buscar_usuario_por_identificador(db, ident)

    credenciales_invalidas = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales incorrectas",
    )

    if usuario is None or usuario.password_hash is None:
        raise credenciales_invalidas
    if not verify_password(payload.password, usuario.password_hash):
        raise credenciales_invalidas

    # Si se envio codigo OTP, validarlo
    if payload.codigo_otp:
        if (
            not usuario.reset_code
            or not usuario.reset_code_expires
            or not secrets.compare_digest(usuario.reset_code, payload.codigo_otp)
            or usuario.reset_code_expires < datetime.utcnow()
        ):
            raise HTTPException(status_code=400, detail="Código de confirmación inválido o expirado")
        usuario.reset_code = None
        usuario.reset_code_expires = None
        db.commit()

    token = create_access_token(usuario.id_usuario, usuario.email, usuario.role)
    return LoginResponse(access_token=token, usuario=usuario)


@router.post("/solicitar-reset")
def solicitar_reset(payload: SolicitarReset, db: Session = Depends(get_db)):
    """Genera un código de 6 dígitos válido por 15 minutos.

    Modo simulado (sin servicio de correo): el código se devuelve en
    'codigo_debug'. Siempre responde 200 para no revelar si el correo existe.
    """
    mensaje = "Si el correo está registrado, recibirás un código de verificación."
    usuario = db.execute(select(Usuario).where(Usuario.email == payload.email.lower())).scalar_one_or_none()
    if usuario is None:
        return {"mensaje": mensaje}

    codigo = f"{secrets.randbelow(1_000_000):06d}"
    usuario.reset_code = codigo
    usuario.reset_code_expires = datetime.utcnow() + timedelta(minutes=15)
    db.commit()
    return {"mensaje": mensaje, "codigo_debug": codigo}


@router.post("/reset-clave")
def reset_clave(payload: ResetClave, db: Session = Depends(get_db)):
    usuario = db.execute(select(Usuario).where(Usuario.email == payload.email.lower())).scalar_one_or_none()
    invalido = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Código inválido o expirado",
    )
    if (
        usuario is None
        or not usuario.reset_code
        or not usuario.reset_code_expires
        or not secrets.compare_digest(usuario.reset_code, payload.codigo)
        or usuario.reset_code_expires < datetime.utcnow()
    ):
        raise invalido

    usuario.password_hash = hash_password(payload.nueva_clave)
    usuario.reset_code = None
    usuario.reset_code_expires = None
    db.commit()
    return {"mensaje": "Contraseña restablecida exitosamente"}


# ============================================================================
# CLAVE DINAMICA / OTP 2FA (NEQUI STYLE)
# ============================================================================

@router.post("/otp/generar", response_model=OTPResponse)
def generar_otp(payload: OTPGenerarRequest, db: Session = Depends(get_db)):
    """Genera una Clave Dinamica / OTP de 6 digitos (estilo Nequi) con expiracion de 5 minutos.
    
    Dispara la notificacion por Email y WhatsApp si el usuario los tiene registrados.
    """
    usuario = db.get(Usuario, payload.id_usuario)
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    codigo = f"{secrets.randbelow(1_000_000):06d}"
    usuario.reset_code = codigo
    usuario.reset_code_expires = datetime.utcnow() + timedelta(minutes=5)
    db.commit()

    # Disparar envio de notificacion a traves de notification-service
    import json
    import urllib.request
    from ..config import settings
    try:
        url = f"{settings.notification_service_url}/notifications"
        payload_data = json.dumps({
            "id_usuario": str(usuario.id_usuario),
            "tipo": "seguridad",
            "titulo": "Tu Clave Dinámica BankLite",
            "mensaje": f"Tu código de seguridad para {payload.operacion} es: {codigo}. Válido por 5 minutos. No lo compartas con nadie.",
            "enviar_correo": True,
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            pass
    except Exception:
        pass

    return OTPResponse(
        valido=True,
        mensaje="Clave dinámica enviada por correo y WhatsApp",
        codigo_debug=codigo,
    )


@router.post("/otp/validar", response_model=OTPResponse)
def validar_otp(payload: OTPValidarRequest, db: Session = Depends(get_db)):
    """Valida la Clave Dinamica ingresada por el usuario y la invalida si es correcta."""
    usuario = db.get(Usuario, payload.id_usuario)
    if not usuario or not usuario.reset_code or not usuario.reset_code_expires:
        return OTPResponse(valido=False, mensaje="No hay ninguna clave dinámica activa para este usuario")

    if usuario.reset_code_expires < datetime.utcnow():
        usuario.reset_code = None
        usuario.reset_code_expires = None
        db.commit()
        return OTPResponse(valido=False, mensaje="La clave dinámica ha expirado. Solicita una nueva")

    if not secrets.compare_digest(usuario.reset_code, payload.codigo):
        return OTPResponse(valido=False, mensaje="Clave dinámica incorrecta")

    # Invalida tras uso unico
    usuario.reset_code = None
    usuario.reset_code_expires = None
    db.commit()
    return OTPResponse(valido=True, mensaje="Clave dinámica verificada exitosamente")

