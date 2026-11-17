"""Prueba de INTEGRACION del monitoreo: el servicio expone sus metricas en /metrics para Prometheus."""
import os

os.environ.setdefault("DATABASE_URL", "postgresql+psycopg2://u:p@localhost:5432/db")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def _valor(texto: str, serie: str) -> float:
    """Lee el valor de una serie en el formato de texto de Prometheus."""
    for linea in texto.splitlines():
        if linea.startswith(serie + " "):
            return float(linea.rsplit(" ", 1)[1])
    return 0.0


def test_metrics_cuenta_las_peticiones_por_ruta_y_estado():
    client = TestClient(app)
    serie_ok = 'http_requests_total{method="GET",path="/health",status="200"}'
    serie_404 = 'http_requests_total{method="GET",path="sin_ruta",status="404"}'
    antes = client.get("/metrics").text

    client.get("/health")
    client.get("/health")
    client.get("/esta-ruta-no-existe")

    r = client.get("/metrics")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert _valor(r.text, serie_ok) == _valor(antes, serie_ok) + 2
    assert _valor(r.text, serie_404) == _valor(antes, serie_404) + 1


def test_metrics_publica_latencia_y_peticiones_en_curso():
    client = TestClient(app)
    client.get("/health")

    texto = client.get("/metrics").text

    assert 'http_request_duration_seconds_bucket{le="0.5",method="GET",path="/health"}' in texto
    assert 'http_request_duration_seconds_count{method="GET",path="/health"}' in texto
    assert "http_requests_in_progress 0.0" in texto


def test_las_consultas_de_prometheus_no_se_cuentan_a_si_mismas():
    client = TestClient(app)
    client.get("/metrics")
    client.get("/metrics")

    assert 'path="/metrics"' not in client.get("/metrics").text
