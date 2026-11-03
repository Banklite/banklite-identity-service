"""Busqueda de usuario por llave Bre-B (correo, documento o celular) con una base SQLite en memoria."""
import os
import uuid
from datetime import date

os.environ["DATABASE_URL"] = "sqlite://"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import DocumentoIdentidad, Usuario  # noqa: E402

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
Sesion = sessionmaker(bind=engine)
Base.metadata.create_all(engine)


def _override():
    db = Sesion()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override
c = TestClient(app)

with Sesion() as s:
    u = Usuario(id_usuario=uuid.uuid4(), nombre="Camilo", apellido="Beltran", email="Camilo@Mail.com",
                telefono="+573136530762", pais_residencia="CO", cedula="78028895")
    otro = Usuario(id_usuario=uuid.uuid4(), nombre="Eliana", apellido="Verdeza", email="eliana@mail.com",
                   telefono="3001112233", pais_residencia="CO")
    s.add_all([u, otro])
    s.flush()
    s.add(DocumentoIdentidad(id_usuario=otro.id_usuario, tipo_documento="cedula", numero_documento="1065000111",
                             pais_emision="CO", fecha_expiracion=date(2035, 1, 1)))
    s.commit()


def test_por_cedula_del_usuario():
    r = c.get("/users/by-llave/78028895")
    assert r.status_code == 200 and r.json()["nombre"] == "Camilo"


def test_por_cedula_con_puntos():
    assert c.get("/users/by-llave/78.028.895").json()["nombre"] == "Camilo"


def test_por_numero_de_documento_registrado():
    assert c.get("/users/by-llave/1065000111").json()["nombre"] == "Eliana"


def test_por_correo_sin_importar_mayusculas():
    assert c.get("/users/by-llave/camilo@mail.com").json()["nombre"] == "Camilo"


def test_por_celular():
    assert c.get("/users/by-llave/3136530762").json()["nombre"] == "Camilo"


def test_llave_inexistente_y_llave_invalida():
    assert c.get("/users/by-llave/99999999").status_code == 404
    assert c.get("/users/by-llave/abc").status_code == 400
