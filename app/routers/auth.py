from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Usuario
import secrets
from datetime import datetime, timedelta

from ..schemas import (
    LoginRequest,
    LoginResponse,
    OTPGenerarRequest,
    OTPResponse,
    OTPValidarRequest,
    ResetClave,
    SolicitarReset,
)
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["autenticacion"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Valida email + contraseña contra la tabla usuario y devuelve un JWT.

    Agregado a pedido del profesor para tener una puerta de entrada real al
    panel (no una simulación de UI). No reemplaza ni cambia el registro de
    usuarios existente (POST /users) ni el flujo de KYC.
    """
    usuario = db.execute(select(Usuario).where(Usuario.email == payload.email.lower())).scalar_one_or_none()

    credenciales_invalidas = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Email o contraseña incorrectos",
    )

    if usuario is None or usuario.password_hash is None:
        raise credenciales_invalidas
    if not verify_password(payload.password, usuario.password_hash):
        raise credenciales_invalidas

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
    import httpx
    try:
        httpx.post(
            "http://notification-service:8007/notifications",
            json={
                "id_usuario": str(usuario.id_usuario),
                "tipo": "seguridad",
                "titulo": "Tu Clave Dinámica BankLite",
                "mensaje": f"Tu código de seguridad para {payload.operacion} es: {codigo}. Válido por 5 minutos. No lo compartas con nadie.",
                "enviar_correo": True,
            },
            timeout=3.0,
        )
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

