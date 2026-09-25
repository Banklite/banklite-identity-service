import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UsuarioCreate(BaseModel):
    nombre: str = Field(min_length=1, max_length=120)
    apellido: str | None = Field(default=None, max_length=120)
    email: EmailStr
    telefono: str = Field(min_length=7, max_length=32, examples=["+573001234567"])
    pais_residencia: str = Field(min_length=2, max_length=2, examples=["CO"])
    password: str = Field(min_length=6, max_length=72, description="Contraseña para iniciar sesión en el panel.")
    fecha_nacimiento: str | None = Field(default=None, description="Fecha de nacimiento en formato YYYY-MM-DD")
    servicio_solicitado: str | None = Field(default=None, description="Servicio bancario inicial solicitado")

    @field_validator("pais_residencia")
    @classmethod
    def pais_upper(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError("pais_residencia debe ser un codigo ISO de 2 letras, por ejemplo CO")
        return v.upper()

    @field_validator("telefono")
    @classmethod
    def telefono_digitos(cls, v: str) -> str:
        cleaned = v.replace(" ", "")
        if not cleaned.lstrip("+").isdigit():
            raise ValueError("telefono solo admite digitos y un + inicial")
        return cleaned


class UsuarioOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_usuario: uuid.UUID
    nombre: str
    apellido: str | None
    email: EmailStr
    telefono: str
    pais_residencia: str
    estado: str
    fecha_registro: datetime
    fecha_nacimiento: str | None = None
    servicio_solicitado: str | None = None


class KycVerifyRequest(BaseModel):
    id_usuario: uuid.UUID
    tipo_documento: Literal["cedula", "pasaporte", "licencia"]
    numero_documento: str = Field(min_length=5, max_length=32)
    pais_emision: str = Field(min_length=2, max_length=2, examples=["CO"])
    fecha_expiracion: date

    @field_validator("numero_documento")
    @classmethod
    def doc_alnum(cls, v: str) -> str:
        if not v.isalnum():
            raise ValueError("numero_documento debe ser alfanumerico")
        return v

    @field_validator("pais_emision")
    @classmethod
    def pais_emision_upper(cls, v: str) -> str:
        return v.upper()


class EvaluacionRiesgoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_evaluacion: uuid.UUID
    nivel_riesgo: str
    score: Decimal
    fecha_evaluacion: datetime


class VerificacionKycOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_verificacion: uuid.UUID
    id_usuario: uuid.UUID
    proveedor_externo: str
    resultado: str
    fecha_verificacion: datetime
    evaluaciones: list[EvaluacionRiesgoOut] = []


class KycVerifyResult(BaseModel):
    verificacion: VerificacionKycOut
    estado_usuario: str
    event_published: bool
    event_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=72)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    usuario: UsuarioOut
