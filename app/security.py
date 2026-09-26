"""Utilidades de autenticacion — hashing de contrasenas y tokens JWT.

Agregado a pedido del profesor para tener un login real (no simulado):
el password se guarda con hash bcrypt (nunca en texto plano) y el login
devuelve un JWT firmado que el panel guarda para saber que hay sesion
activa. Esto no estaba en el documento oficial del proyecto, pero no
modifica ni rompe ninguno de los endpoints ni contratos ya existentes.
"""

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
