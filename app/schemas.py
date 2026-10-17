import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


TIPOS_DOCUMENTO = ("cedula", "tarjeta_identidad", "cedula_extranjeria", "pasaporte")


def _validar_numero_documento(v: str | None, tipo: str) -> str | None:
    """Cedula / TI / CE: solo digitos (6-10). Pasaporte: letras y numeros (6-12)."""
    if v is None or v.strip() == "":
        return None
    v = v.strip()
    if tipo == "pasaporte":
        if not v.isalnum() or not (6 <= len(v) <= 12):
            raise ValueError("el pasaporte debe tener entre 6 y 12 letras o numeros")
        return v.upper()
    if not v.isdigit() or not (6 <= len(v) <= 10):
        raise ValueError("el documento debe tener solo numeros, entre 6 y 10 digitos")
    return v


class UsuarioCreate(BaseModel):
    nombre: str = Field(min_length=1, max_length=120)
    apellido: str | None = Field(default=None, max_length=120)
    email: EmailStr
    telefono: str = Field(min_length=7, max_length=32, examples=["+573001234567"])
    pais_residencia: str = Field(min_length=2, max_length=2, examples=["CO"])
    password: str = Field(min_length=6, max_length=72, description="ContraseÃ±a para iniciar sesiÃ³n en el panel.")
    fecha_nacimiento: str | None = Field(default=None, description="Fecha de nacimiento en formato YYYY-MM-DD")
    servicio_solicitado: str | None = Field(default=None, description="Servicio bancario inicial solicitado")
    cedula: str | None = Field(default=None, description="Cedula de ciudadania o documento")
    fecha_expedicion: str | None = Field(default=None, description="Fecha de expediciÃ³n")
    fecha_vencimiento: str | None = Field(default=None, description="Fecha de vencimiento")
    pais_expedicion: str | None = Field(default=None, description="PaÃ­s de expediciÃ³n")
    tipo_documento: str = Field(default="cedula", description="cedula, tarjeta_identidad, cedula_extranjeria o pasaporte")
    representante_nombre: str | None = Field(default=None, description="Nombre del representante legal (para menores)")
    representante_documento: str | None = Field(default=None, description="Documento del representante legal")
    representante_tipo_documento: str | None = Field(default=None)
    representante_parentesco: str | None = Field(default=None, description="padre, madre, tutor u otro")
    representante_telefono: str | None = Field(default=None, max_length=32)
    representante_email: str | None = Field(default=None, max_length=120)

    @field_validator("pais_residencia")
    @classmethod
    def pais_upper(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError("pais_residencia debe ser un codigo ISO de 2 letras, por ejemplo CO")
        return v.upper()

    @field_validator("tipo_documento", "representante_tipo_documento")
    @classmethod
    def tipo_doc_valido(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if v not in TIPOS_DOCUMENTO:
            raise ValueError(f"tipo de documento invalido; use uno de: {', '.join(TIPOS_DOCUMENTO)}")
        return v

    @model_validator(mode="after")
    def validar_documentos(self):
        self.cedula = _validar_numero_documento(self.cedula, self.tipo_documento)
        self.representante_documento = _validar_numero_documento(
            self.representante_documento, self.representante_tipo_documento or "cedula"
        )
        return self

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
    cedula: str | None = None
    role: str = "cliente"
    fecha_expedicion: str | None = None
    fecha_vencimiento: str | None = None
    pais_expedicion: str | None = None
    estado_kyc: str | None = None
    representante_nombre: str | None = None
    representante_documento: str | None = None
    tipo_documento: str | None = None
    representante_tipo_documento: str | None = None
    representante_parentesco: str | None = None
    representante_telefono: str | None = None
    representante_email: str | None = None


class KycVerifyRequest(BaseModel):
    id_usuario: uuid.UUID
    tipo_documento: Literal["cedula", "tarjeta_identidad", "cedula_extranjeria", "pasaporte", "licencia"]
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
    identificador: str | None = None
    email: str | None = None
    password: str = Field(min_length=1, max_length=72)
    codigo_otp: str | None = None


class LoginIniciarRequest(BaseModel):
    identificador: str = Field(description="Correo electronico o numero de celular")
    password: str = Field(min_length=1, max_length=72)
    telefono: str | None = Field(default=None, description="Telefono opcional a registrar si el usuario no tiene")


class LoginIniciarResponse(BaseModel):
    requiere_2fa: bool = True
    id_usuario: uuid.UUID
    nombre: str
    email_enmascarado: str
    telefono_enmascarado: str
    mensaje: str
    codigo_debug: str | None = None


class LoginVerificarOTPRequest(BaseModel):
    id_usuario: uuid.UUID
    codigo: str = Field(min_length=6, max_length=6)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    usuario: UsuarioOut

class CambiarClave(BaseModel):
    clave_actual: str
    clave_nueva: str = Field(min_length=6)


class SolicitarReset(BaseModel):
    email: EmailStr


class ResetClave(BaseModel):
    email: EmailStr
    codigo: str
    nueva_clave: str = Field(min_length=6)


class UsuarioUpdate(BaseModel):
    nombre: str | None = None
    apellido: str | None = None
    email: EmailStr | None = None
    fecha_nacimiento: str | None = None
    pais_residencia: str | None = None
    servicio_solicitado: str | None = None
    cedula: str | None = None
    fecha_expedicion: str | None = None
    fecha_vencimiento: str | None = None
    pais_expedicion: str | None = None


class OTPGenerarRequest(BaseModel):
    id_usuario: uuid.UUID
    operacion: str = "general"


class OTPValidarRequest(BaseModel):
    id_usuario: uuid.UUID
    codigo: str = Field(min_length=6, max_length=6)
    operacion: str = "general"


class OTPResponse(BaseModel):
    valido: bool
    mensaje: str
    codigo_debug: str | None = None


# ============================================================================
# PIN (Nequi-style 4-digit PIN)
# ============================================================================

class PINSetRequest(BaseModel):
    id_usuario: uuid.UUID
    pin: str = Field(min_length=4, max_length=4, pattern=r"^\d{4}$", description="PIN de 4 digitos numericos")


class PINLoginRequest(BaseModel):
    identificador: str = Field(description="Correo, telefono o cedula")
    pin: str = Field(min_length=4, max_length=4, pattern=r"^\d{4}$")


class PINStatusResponse(BaseModel):
    tiene_pin: bool
    mensaje: str
