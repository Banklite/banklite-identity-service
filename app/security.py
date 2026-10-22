"""Utilidades de autenticacion — hashing de contrasenas y tokens JWT.

Agregado a pedido del profesor para tener un login real (no simulado):
el password se guarda con hash bcrypt (nunca en texto plano) y el login
devuelve un JWT firmado que el panel guarda para saber que hay sesion
activa. Esto no estaba en el documento oficial del proyecto, pero no
modifica ni rompe ninguno de los endpoints ni contratos ya existentes.
"""

import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from .config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(id_usuario: uuid.UUID, email: str, role: str = "cliente") -> str:
    expira = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": str(id_usuario),
        "email": email,
        "role": role,
        "exp": expira,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = decode_access_token(token)
        return payload
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Estas credenciales no tienen permisos de administrador."
        )
    return user



# --- Clave dinamica (token de 6 digitos que rota cada 60 s) -------------------
VENTANA_CLAVE_DINAMICA = 60


def _clave_para_ventana(id_usuario: uuid.UUID, ventana: int) -> str:
    mensaje = f"clave-dinamica:{id_usuario}:{ventana}".encode("utf-8")
    digest = hmac.new(settings.jwt_secret.encode("utf-8"), mensaje, hashlib.sha256).digest()
    return f"{int.from_bytes(digest[:8], 'big') % 1_000_000:06d}"


def generar_clave_dinamica(id_usuario: uuid.UUID) -> tuple[str, int]:
    """Devuelve (codigo, segundos_restantes) para la ventana actual."""
    ahora = int(time.time())
    ventana = ahora // VENTANA_CLAVE_DINAMICA
    restantes = VENTANA_CLAVE_DINAMICA - (ahora % VENTANA_CLAVE_DINAMICA)
    return _clave_para_ventana(id_usuario, ventana), restantes


def clave_dinamica_valida(id_usuario: uuid.UUID, codigo: str) -> bool:
    """Acepta la ventana actual y la anterior (tolera el cambio justo al digitar)."""
    ventana = int(time.time()) // VENTANA_CLAVE_DINAMICA
    return any(
        hmac.compare_digest(_clave_para_ventana(id_usuario, v), str(codigo))
        for v in (ventana, ventana - 1)
    )


# --- Clave dinamica emitida por el servidor (estilo Nequi) -------------------
# Antes el codigo se derivaba solo de HMAC(id, hora // 60): dentro de la misma
# ventana de 60 s el servidor devolvia SIEMPRE los mismos 6 digitos, por lo que
# pulsar "Generar nueva" no cambiaba nada. Ahora el servidor emite un codigo
# aleatorio, lo guarda en la BD con su expiracion y lo valida contra ese
# registro: cada pulsacion produce una clave distinta y sigue siendo verificable.


def emitir_clave_dinamica(db, id_usuario: uuid.UUID, forzar: bool = False) -> tuple[str, int]:
    """Devuelve (codigo, segundos_restantes) de la clave dinamica vigente.

    Si no hay clave, expiro o forzar=True, genera una nueva y la persiste.
    """
    from .models import Usuario

    usuario = db.get(Usuario, id_usuario)
    if usuario is None:
        raise ValueError("Usuario no encontrado para emitir clave dinamica")

    ahora = datetime.utcnow()
    if (
        not forzar
        and usuario.clave_dinamica_codigo
        and usuario.clave_dinamica_expira
        and usuario.clave_dinamica_expira > ahora
    ):
        restantes = max(1, int((usuario.clave_dinamica_expira - ahora).total_seconds()))
        return usuario.clave_dinamica_codigo, restantes

    codigo = f"{secrets.randbelow(1_000_000):06d}"
    usuario.clave_dinamica_codigo = codigo
    usuario.clave_dinamica_expira = ahora + timedelta(seconds=VENTANA_CLAVE_DINAMICA)
    db.commit()
    return codigo, VENTANA_CLAVE_DINAMICA


def clave_dinamica_vigente_valida(db, id_usuario: uuid.UUID, codigo: str) -> bool:
    """True si el codigo coincide con la clave vigente y aun no expiro."""
    from .models import Usuario

    usuario = db.get(Usuario, id_usuario)
    if not usuario or not usuario.clave_dinamica_codigo or not usuario.clave_dinamica_expira:
        return False
    if usuario.clave_dinamica_expira < datetime.utcnow():
        return False
    return hmac.compare_digest(usuario.clave_dinamica_codigo, str(codigo))
