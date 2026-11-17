# Identity Service — BankLite

Usuarios, autenticacion (JWT, MFA por correo, PIN) y verificacion de identidad (KYC) contra proveedores externos.

Parte del proyecto **BankLite** (banca digital con microservicios) de *Arquitectura y Modelamiento de Software*, Universidad Cooperativa de Colombia. Cada microservicio tiene su propio repositorio y su propia base de datos (`identity_db`).

## Responsabilidad en la arquitectura

Usuarios, autenticacion (JWT, MFA por correo, PIN) y verificacion de identidad (KYC) contra proveedores externos. Se comunica con los demas servicios por **REST** (operaciones que necesitan respuesta inmediata) y por **eventos** en RabbitMQ (exchange `banklite.events`, tipo topic).

| Eventos publicados | Eventos consumidos |
|---|---|
| `identity.verified` | — |

## Tecnologias

FastAPI, SQLAlchemy, PostgreSQL, RabbitMQ (pika), bcrypt/JWT. KYC externo: Verifik (y Truora como respaldo). Python 3.12, Docker.

## Despliegue

- URL publica: <https://banklite-identity-service-kc5q.onrender.com>
- Salud: <https://banklite-identity-service-kc5q.onrender.com/health>
- Documentacion interactiva (Swagger): <https://banklite-identity-service-kc5q.onrender.com/docs>

Desplegado en Render (plan gratuito: tarda hasta ~1 minuto en responder si estuvo inactivo). Las credenciales se configuran como variables de entorno en la plataforma, no en el codigo.

## Endpoints principales

| Metodo | Ruta | Descripcion |
|---|---|---|
| `POST` | `/users` | Registro de usuario |
| `GET` | `/users/{id}` | Consulta de usuario |
| `POST` | `/kyc/verify` | Verificacion KYC contra el proveedor |
| `GET` | `/kyc/{id_usuario}` | Historial KYC del usuario |
| `POST` | `/auth/login` | Inicio de sesion (JWT) |
| `POST` | `/auth/login/solicitar-codigo` | Codigo 2FA por correo |
| `POST` | `/auth/otp/generar` | OTP de operaciones |
| `GET` | `/users/validar-identidad/{numero_documento}` | Validacion de identidad publica |
| `GET` | `/health` | Estado del servicio |
| `GET` | `/stats` | Contadores del servicio |

La lista completa esta en `/docs`.

## Variables de entorno

Copia `.env.example` a `.env` y completa los valores.

| Variable | Descripcion |
|---|---|
| `DATABASE_URL` | Conexion PostgreSQL (SQLAlchemy) |
| `JWT_SECRET` | Secreto de firma de tokens (obligatorio cambiarlo) |
| `JWT_EXPIRE_MINUTES` | Vigencia del token |
| `NOTIFICATION_SERVICE_URL` | URL de notification-service (envio de codigos) |
| `VERIFIK_TOKEN` | Token de Verifik (KYC) |
| `TRUORA_API_KEY` | API key de Truora (respaldo KYC) |
| `RABBITMQ_URL` | URL del bus de eventos |
| `EVENTS_EXCHANGE` | Exchange de eventos |
| `ENABLE_EVENTS` | Publicar eventos |

## Base de datos

Motor: PostgreSQL. Base: `identity_db`.

- `db/schema.sql`: creacion de tablas, indices y restricciones.
- `db/seed.sql`: datos de ejemplo.

El servicio tambien crea las tablas solo al arrancar (`create_all`). Para restaurar a mano:

```bash
createdb identity_db
psql -d identity_db -f db/schema.sql
psql -d identity_db -f db/seed.sql
```

Respaldo completo (para entregar o restaurar): `pg_dump -Fc identity_db > identity_db.dump` y `pg_restore -d identity_db identity_db.dump`.

## Instalacion y ejecucion

Con Docker:

```bash
docker build -t banklite-identity-service .
docker run --env-file .env -p 8001:8001 -e PORT=8001 banklite-identity-service
```

Sin Docker:

```bash
python -m venv .venv && source .venv/bin/activate   # en Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

Prueba: abre <http://localhost:8001/docs>.

## Pruebas automatizadas

```bash
pip install -r requirements-dev.txt
python -m pytest tests -v --cov=app --cov-report=term-missing --cov-report=html
```

No necesitan PostgreSQL, RabbitMQ ni los otros microservicios: la base es SQLite en memoria y las dependencias externas se reemplazan con mocks (`unittest.mock`). El reporte navegable queda en `htmlcov/index.html`.

| Tipo | Archivo | Que verifica |
|---|---|---|
| Unitaria | `tests/unit/test_seguridad.py` | Hash bcrypt de contrasenas, emision y validacion de JWT (vencido, firma ajena), control de rol admin y clave dinamica por ventana de tiempo (reloj simulado). |
| Unitaria (mocks) | `tests/unit/test_proveedores_externos.py` | Have I Been Pwned con k-anonymity (`httpx` simulado), cadena de proveedores KYC Verifik -> Truora, nivel de riesgo y digito de verificacion DIAN. |
| Integracion | `tests/integration/test_identidad_api.py` | Registro con KYC automatico y evento `identity.verified`, login en dos pasos con codigo por correo, restablecimiento de clave y permisos (admin / cliente), contra la base. |
| Integracion | `tests/integration/test_claves_y_kyc_api.py` | PIN de 4 digitos, clave dinamica, OTP de un solo uso y verificacion KYC manual. |
| Integracion | `tests/integration/test_llave.py` | Busqueda de usuario por llave (cedula, correo o celular). |

Resultado actual: **69 pruebas** (28 unitarias y 41 de integracion), todas aprobadas, con **79 % de cobertura** de `app/`.

En GitHub Actions las pruebas corren en cada `push` y `pull request`. Si una falla, la imagen no se construye y no se despliega. El reporte de cobertura queda en el resumen de la ejecucion y como artefacto descargable `coverage-banklite-identity-service`.

## Repositorios del proyecto

`banklite-identity-service`, `banklite-account-service`, `banklite-ledger-service`, `banklite-transfer-service`, `banklite-card-service`, `banklite-fraud-service`, `banklite-notification-service`, `banklite-compliance-service`. Panel web: `services/web-panel` en el repositorio `banklite-microservicios`.
