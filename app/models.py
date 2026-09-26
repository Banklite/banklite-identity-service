import uuid
from datetime import date, datetime, timezone
from decimal import Decimal

from sqlalchemy import CheckConstraint, Date, DateTime, ForeignKey, Index, Numeric, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Usuario(Base):
    """Tabla usuario — entidad raiz del microservicio de Identidad y KYC.

    Coincide con el modelo entidad-relacion oficial del proyecto (documento
    Actividad_Momento_1, seccion "Diseno del modelo de datos relacional"):
    USUARIO(id_usuario, nombre, apellido, email, telefono, pais_residencia,
    fecha_registro, estado).
    """

    __tablename__ = "usuario"
    __table_args__ = (Index("idx_usuario_email", "email"),)

    id_usuario: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    nombre: Mapped[str] = mapped_column(String(120), nullable=False)
    apellido: Mapped[str] = mapped_column(String(120), nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    telefono: Mapped[str] = mapped_column(String(32), nullable=True)
    pais_residencia: Mapped[str] = mapped_column(String(2), nullable=False)
    fecha_registro: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    estado: Mapped[str] = mapped_column(String(32), nullable=False, default="pendiente_verificacion")
    # Agregado a pedido del profesor para permitir login real (no estaba en
    # el documento oficial). Nullable porque usuarios creados antes de este
    # cambio no tienen contrasena; no pueden iniciar sesion hasta que se les
    # asigne una.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fecha_nacimiento: Mapped[str | None] = mapped_column(String(20), nullable=True)
    servicio_solicitado: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cedula: Mapped[str | None] = mapped_column(String(50), nullable=True)
    fecha_expedicion: Mapped[str | None] = mapped_column(String(20), nullable=True)
    fecha_vencimiento: Mapped[str | None] = mapped_column(String(20), nullable=True)
    pais_expedicion: Mapped[str | None] = mapped_column(String(10), nullable=True)
    estado_kyc: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Rol del usuario: 'admin' o 'cliente'. El primer usuario registrado es admin.
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="cliente")

    documentos: Mapped[list["DocumentoIdentidad"]] = relationship(
        back_populates="usuario", cascade="all, delete-orphan"
    )
    verificaciones: Mapped[list["VerificacionKyc"]] = relationship(
        back_populates="usuario",
        cascade="all, delete-orphan",
        order_by="VerificacionKyc.fecha_verificacion",
    )


class DocumentoIdentidad(Base):
    """Tabla documento_identidad.

    DOCUMENTO_IDENTIDAD(id_documento, id_usuario FK, tipo_documento,
    numero_documento, pais_emision, fecha_expiracion). Relacion: un usuario
    puede tener varios documentos (Usuario 1:N Documento_Identidad).
    """

    __tablename__ = "documento_identidad"
    __table_args__ = (
        CheckConstraint(
            "tipo_documento IN ('cedula','pasaporte','licencia')", name="ck_documento_tipo"
        ),
        Index("idx_documento_usuario", "id_usuario"),
    )

    id_documento: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_usuario: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False
    )
    tipo_documento: Mapped[str] = mapped_column(String(32), nullable=False)
    numero_documento: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    pais_emision: Mapped[str] = mapped_column(String(2), nullable=True)
    fecha_expiracion: Mapped[date] = mapped_column(Date, nullable=False)

    usuario: Mapped["Usuario"] = relationship(back_populates="documentos")


class VerificacionKyc(Base):
    """Tabla verificacion_kyc.

    VERIFICACION_KYC(id_verificacion, id_usuario FK, proveedor_externo,
    resultado, fecha_verificacion). Relacion: Usuario 1:N Verificacion_KYC.
    """

    __tablename__ = "verificacion_kyc"
    __table_args__ = (
        CheckConstraint(
            "resultado IN ('pendiente','aprobado','rechazado')", name="ck_verificacion_resultado"
        ),
        Index("idx_verificacion_usuario", "id_usuario"),
    )

    id_verificacion: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_usuario: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False
    )
    proveedor_externo: Mapped[str] = mapped_column(String(64), nullable=False)
    resultado: Mapped[str] = mapped_column(String(32), nullable=False)
    fecha_verificacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    usuario: Mapped["Usuario"] = relationship(back_populates="verificaciones")
    evaluaciones: Mapped[list["EvaluacionRiesgo"]] = relationship(
        back_populates="verificacion", cascade="all, delete-orphan"
    )


class EvaluacionRiesgo(Base):
    """Tabla evaluacion_riesgo.

    EVALUACION_RIESGO(id_evaluacion, id_verificacion FK, nivel_riesgo, score,
    fecha_evaluacion). Relacion: Verificacion_KYC 1:N Evaluacion_Riesgo.
    """

    __tablename__ = "evaluacion_riesgo"
    __table_args__ = (
        CheckConstraint("nivel_riesgo IN ('bajo','medio','alto')", name="ck_evaluacion_nivel"),
        Index("idx_evaluacion_verificacion", "id_verificacion"),
    )

    id_evaluacion: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_verificacion: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("verificacion_kyc.id_verificacion", ondelete="CASCADE"), nullable=False
    )
    nivel_riesgo: Mapped[str] = mapped_column(String(16), nullable=False)
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    fecha_evaluacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    verificacion: Mapped["VerificacionKyc"] = relationship(back_populates="evaluaciones")
