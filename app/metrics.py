"""Metricas del servicio para Prometheus, expuestas en GET /metrics.

Cubre las cuatro senales doradas:
  - Trafico:    http_requests_total (contador por metodo, ruta y codigo de estado)
  - Errores:    el mismo contador filtrado por status 5xx
  - Latencia:   http_request_duration_seconds (histograma por metodo y ruta)
  - Saturacion: http_requests_in_progress (peticiones en curso) y las metricas de
                proceso que prometheus_client publica solo (CPU, memoria, descriptores)
"""
import time

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

PETICIONES = Counter(
    "http_requests_total",
    "Peticiones HTTP atendidas",
    ["method", "path", "status"],
)
DURACION = Histogram(
    "http_request_duration_seconds",
    "Duracion de las peticiones HTTP en segundos",
    ["method", "path"],
)
EN_CURSO = Gauge(
    "http_requests_in_progress",
    "Peticiones HTTP que se estan atendiendo en este momento",
)

RUTA_METRICAS = "/metrics"


def _plantilla_de_ruta(request: Request) -> str:
    """Devuelve la ruta declarada (/accounts/{id_cuenta}) y no la URL real.

    Si se usara la URL, cada id distinto crearia una serie nueva en Prometheus.
    Las peticiones que no coinciden con ninguna ruta (404) se agrupan en una sola etiqueta.
    """
    ruta = request.scope.get("route")
    return getattr(ruta, "path", None) or "sin_ruta"


def instrumentar(app: FastAPI) -> None:
    """Registra el middleware que mide cada peticion y publica el endpoint /metrics."""

    @app.middleware("http")
    async def medir_peticion(request: Request, call_next):
        if request.url.path == RUTA_METRICAS:
            return await call_next(request)  # las consultas de Prometheus no se cuentan

        inicio = time.perf_counter()
        status = 500  # si la peticion termina en una excepcion no controlada, cuenta como 5xx
        EN_CURSO.inc()
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            EN_CURSO.dec()
            ruta = _plantilla_de_ruta(request)
            PETICIONES.labels(request.method, ruta, str(status)).inc()
            DURACION.labels(request.method, ruta).observe(time.perf_counter() - inicio)

    @app.get(RUTA_METRICAS, include_in_schema=False)
    def metricas() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
