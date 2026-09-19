import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Usuario
from ..schemas import UsuarioCreate, UsuarioOut

router = APIRouter(prefix="/users", tags=["usuarios"])


def get_usuario_or_404(db: Session, id_usuario: uuid.UUID) -> Usuario:
    usuario = db.get(Usuario, id_usuario)
    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No existe un usuario con id {id_usuario}",
        )
    return usuario


@router.post("", response_model=UsuarioOut, status_code=status.HTTP_201_CREATED)
def crear_usuario(payload: UsuarioCreate, db: Session = Depends(get_db)):
    """Registra un usuario en la tabla usuario. Queda pendiente_verificacion
    hasta que pase el KYC en POST /kyc/verify."""
    usuario = Usuario(
        nombre=payload.nombre,
        apellido=payload.apellido,
        email=payload.email.lower(),
        telefono=payload.telefono,
        pais_residencia=payload.pais_residencia,
        estado="pendiente_verificacion",
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
    return usuario


@router.get("", response_model=list[UsuarioOut])
def listar_usuarios(
    db: Session = Depends(get_db),
    estado: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Usuario).order_by(Usuario.fecha_registro.desc()).limit(limit).offset(offset)
    if estado:
        stmt = stmt.where(Usuario.estado == estado)
    return db.execute(stmt).scalars().all()


@router.get("/{id_usuario}", response_model=UsuarioOut)
def consultar_usuario(id_usuario: uuid.UUID, db: Session = Depends(get_db)):
    """Endpoint consumido de forma SINCRONA por account-service antes de abrir una cuenta."""
    return get_usuario_or_404(db, id_usuario)
