from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Usuario
from ..schemas import LoginRequest, LoginResponse
from ..security import create_access_token, verify_password

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

    token = create_access_token(usuario.id_usuario, usuario.email)
    return LoginResponse(access_token=token, usuario=usuario)
