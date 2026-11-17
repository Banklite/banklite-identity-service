import os

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg2://u:p@localhost:5432/db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def test_health_responde_ok():
    """Prueba minima de humo: el servicio arranca y /health responde (sin base de datos)."""
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
