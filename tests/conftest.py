"""Fixtures compartidas por todas las pruebas del servicio.

- `sesiones`: base de datos SQLite en memoria, nueva y vacia para cada prueba (un "fake" de PostgreSQL).
- `client`: TestClient de FastAPI conectado a esa base en lugar de la real.

Ninguna prueba necesita PostgreSQL, RabbitMQ ni los otros microservicios: las
dependencias externas se reemplazan con mocks.
"""
import os

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg2://u:p@localhost:5432/db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def sesiones():
    """Fabrica de sesiones sobre una base SQLite en memoria (se destruye al terminar la prueba)."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, autoflush=False, autocommit=False)
    engine.dispose()


@pytest.fixture
def client(sesiones):
    """Cliente HTTP de prueba: la app usa la base en memoria en vez de PostgreSQL."""

    def _get_db_de_prueba():
        db = sesiones()
        try:
            yield db
        finally:
            db.close()

    anteriores = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = _get_db_de_prueba
    yield TestClient(app)
    app.dependency_overrides.clear()
    app.dependency_overrides.update(anteriores)
