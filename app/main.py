import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import settings
from .database import Base, engine
from .routers import auth, kyc, users

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(settings.service_name)


def _migrar_password_hash() -> None:
    """Agrega la columna password_hash si la tabla usuario ya existia sin ella.

    Base.metadata.create_all() solo crea tablas nuevas: no altera tablas que
    ya existen en la base de datos (como la de produccion en Render, creada
    antes de agregar el login real). Este ALTER es idempotente y seguro de
    correr en cada arranque.
    """
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE usuario ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    _migrar_password_hash()
    logger.info("%s iniciado", settings.service_name)
    yield


app = FastAPI(
    title="BankLite - Identity Service",
    description=(
        "Microservicio de identidad y KYC. Registra usuarios, verifica su identidad "
        "contra un proveedor externo y publica el evento identity.verified."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # solo para desarrollo local; en produccion se restringe al dominio del panel
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users.router)
app.include_router(kyc.router)
app.include_router(auth.router)


@app.get("/health", tags=["infra"])
def health():
    return {"status": "ok", "service": settings.service_name}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Error no controlado en %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servicio"},
    )
