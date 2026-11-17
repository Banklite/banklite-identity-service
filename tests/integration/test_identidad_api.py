"""Pruebas de INTEGRACION de identity-service: endpoint + reglas de negocio + base de datos.

Recorren el registro con KYC, el login con doble factor, el restablecimiento de clave y
los permisos. La base es SQLite en memoria; el proveedor KYC, Have I Been Pwned,
RabbitMQ y notification-service se reemplazan con mocks.
"""
import uuid
from unittest.mock import patch

import pytest

from app.models import DocumentoIdentidad, EvaluacionRiesgo, Usuario, VerificacionKyc
from app.security import decode_access_token

CLAVE = "Monteria2026*"


@pytest.fixture(autouse=True)
def externos():
    with (
        patch("app.routers.users.password_comprometida", return_value=0) as pwned_registro,
        patch("app.routers.auth.password_comprometida", return_value=0) as pwned_reset,
        patch("app.routers.users.kyc_provider.verify_identity", return_value=("aprobado", "VERIFIK")) as kyc,
        patch("app.routers.users.publish_event", return_value=True) as publicar,
        patch("app.routers.auth._entregar_codigo") as entregar_codigo,
    ):
        yield {"pwned": pwned_registro, "pwned_reset": pwned_reset, "kyc": kyc, "publicar": publicar, "codigo": entregar_codigo}


def _registrar(client, email="cliente@example.com", cedula="1065000111", telefono="+573001234567", **extra):
    return client.post("/users", json={
        "nombre": "Juan", "apellido": "Rhenals", "email": email, "telefono": telefono,
        "pais_residencia": "co", "password": CLAVE, "cedula": cedula, **extra,
    })


@pytest.fixture
def admin(client):
    """El primer usuario registrado es el administrador (no pasa por KYC)."""
    r = _registrar(client, email="admin@example.com", cedula=None, telefono="+573000000001")
    assert r.status_code == 201 and r.json()["role"] == "admin"
    return r.json()


def _token(client, email: str) -> dict:
    r = client.post("/auth/login", json={"email": email, "password": CLAVE})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- Registro y KYC --------------------------------------------------------------------------

def test_registro_de_cliente_ejecuta_el_kyc_y_publica_identity_verified(client, sesiones, admin, externos):
    r = _registrar(client)

    assert r.status_code == 201
    usuario = r.json()
    assert usuario["role"] == "cliente" and usuario["estado"] == "verificado" and usuario["estado_kyc"] == "VERIFICADO"
    assert usuario["pais_residencia"] == "CO" and "password" not in usuario and "password_hash" not in usuario
    externos["kyc"].assert_called_once_with("cedula", "1065000111")
    with sesiones() as db:
        guardado = db.get(Usuario, uuid.UUID(usuario["id_usuario"]))
        assert guardado.password_hash != CLAVE and guardado.password_hash.startswith("$2")
        assert db.query(DocumentoIdentidad).one().numero_documento == "1065000111"
        assert db.query(VerificacionKyc).one().proveedor_externo == "VERIFIK"
        assert db.query(EvaluacionRiesgo).one().nivel_riesgo == "bajo"
    # El evento es lo que permite a account-service abrir la cuenta (comunicacion asincrona)
    evento, datos = externos["publicar"].call_args.args
    assert evento == "identity.verified" and datos["id_usuario"] == usuario["id_usuario"] and datos["pais_residencia"] == "CO"


def test_kyc_rechazado_deja_al_usuario_rechazado_y_no_publica_evento(client, sesiones, admin, externos):
    externos["kyc"].return_value = ("rechazado", "VERIFIK")

    r = _registrar(client)

    assert r.json()["estado"] == "rechazado" and r.json()["estado_kyc"] == "RECHAZADO"
    with sesiones() as db:
        assert db.query(EvaluacionRiesgo).one().nivel_riesgo == "alto"
    externos["publicar"].assert_not_called()


def test_proveedor_kyc_caido_deja_el_registro_en_error_de_verificacion(client, admin, externos):
    externos["kyc"].side_effect = RuntimeError("Verifik: HTTP 503")

    r = _registrar(client)

    assert r.status_code == 201
    assert r.json()["estado"] != "verificado" and r.json()["estado_kyc"] == "ERROR_VERIFICACION"
    externos["publicar"].assert_not_called()


def test_documento_ya_usado_por_otra_persona_se_rechaza(client, admin, externos):
    assert _registrar(client).json()["estado"] == "verificado"

    r = _registrar(client, email="suplantador@example.com", telefono="+573009998877")

    assert r.json()["estado"] == "rechazado"
    assert externos["kyc"].call_count == 1  # ni siquiera se consulta al proveedor


def test_correo_repetido_responde_409(client, admin):
    assert _registrar(client).status_code == 201
    r = _registrar(client, cedula="1065000222")
    assert r.status_code == 409 and "ya esta registrado" in r.json()["detail"]


def test_contrasena_filtrada_impide_el_registro(client, sesiones, admin, externos):
    externos["pwned"].return_value = 209972

    r = _registrar(client)

    assert r.status_code == 400 and "209,972 filtraciones" in r.json()["detail"]
    with sesiones() as db:
        assert db.query(Usuario).count() == 1  # solo el admin


def test_menor_de_edad_necesita_representante_legal(client, admin):
    sin_representante = _registrar(client, fecha_nacimiento="2015-03-10")
    con_representante = _registrar(
        client, fecha_nacimiento="2015-03-10", representante_nombre="Ana Florez", representante_documento="30111222",
        representante_parentesco="madre", representante_telefono="+573005556677",
    )

    assert sin_representante.status_code == 400 and "representante" in sin_representante.json()["detail"]
    assert con_representante.status_code == 201


@pytest.mark.parametrize("cambio", [{"email": "no-es-correo"}, {"pais_residencia": "C1"}, {"password": "123"}])
def test_datos_de_registro_invalidos_responden_422(client, cambio):
    cuerpo = {"nombre": "Juan", "email": "a@example.com", "telefono": "+573001234567", "pais_residencia": "CO", "password": CLAVE}
    assert client.post("/users", json={**cuerpo, **cambio}).status_code == 422


# --- Login con doble factor ------------------------------------------------------------------

def test_login_en_dos_pasos_entrega_el_codigo_y_emite_el_jwt(client, admin, externos):
    usuario = _registrar(client).json()

    paso1 = client.post("/auth/login/solicitar-codigo", json={"identificador": "cliente@example.com", "password": CLAVE})

    assert paso1.status_code == 200 and paso1.json()["requiere_2fa"] is True
    assert paso1.json()["email_enmascarado"] == "cl***@example.com" and paso1.json()["codigo_debug"] is None
    # El codigo solo viaja por notification-service (mock): se toma del mensaje enviado
    id_usuario, _titulo, mensaje = externos["codigo"].call_args.args
    assert str(id_usuario) == usuario["id_usuario"]
    codigo = next(palabra.strip(".") for palabra in mensaje.split() if palabra.strip(".").isdigit() and len(palabra.strip(".")) == 6)

    incorrecto = client.post("/auth/login/confirmar-codigo", json={"id_usuario": usuario["id_usuario"], "codigo": "000000" if codigo != "000000" else "111111"})
    paso2 = client.post("/auth/login/confirmar-codigo", json={"id_usuario": usuario["id_usuario"], "codigo": codigo})
    repetido = client.post("/auth/login/confirmar-codigo", json={"id_usuario": usuario["id_usuario"], "codigo": codigo})

    assert incorrecto.status_code == 400
    assert paso2.status_code == 200
    datos = decode_access_token(paso2.json()["access_token"])
    assert datos["sub"] == usuario["id_usuario"] and datos["role"] == "cliente"
    assert repetido.status_code == 400  # el codigo es de un solo uso


@pytest.mark.parametrize("identificador", ["cliente@example.com", "CLIENTE@EXAMPLE.COM", "3001234567", "+573001234567", "1065000111"])
def test_se_puede_entrar_con_correo_celular_o_cedula(client, admin, identificador):
    _registrar(client)
    r = client.post("/auth/login", json={"identificador": identificador, "password": CLAVE})
    assert r.status_code == 200 and r.json()["usuario"]["email"] == "cliente@example.com"


def test_credenciales_incorrectas_responden_401_sin_enviar_codigo(client, admin, externos):
    _registrar(client)

    mala_clave = client.post("/auth/login/solicitar-codigo", json={"identificador": "cliente@example.com", "password": "otra-clave"})
    no_existe = client.post("/auth/login", json={"email": "nadie@example.com", "password": CLAVE})

    assert mala_clave.status_code == 401 and no_existe.status_code == 401
    externos["codigo"].assert_not_called()


# --- Restablecer y cambiar la contrasena -----------------------------------------------------

def test_restablecer_la_contrasena_con_el_codigo_del_correo(client, admin, externos):
    _registrar(client)

    client.post("/auth/solicitar-reset", json={"email": "cliente@example.com"})
    mensaje = externos["codigo"].call_args.args[2]
    codigo = next(p.strip(".") for p in mensaje.split() if p.strip(".").isdigit() and len(p.strip(".")) == 6)

    mal = client.post("/auth/reset-clave", json={"email": "cliente@example.com", "codigo": "abcdef", "nueva_clave": "NuevaClave2026*"})
    bien = client.post("/auth/reset-clave", json={"email": "cliente@example.com", "codigo": codigo, "nueva_clave": "NuevaClave2026*"})

    assert mal.status_code == 400 and bien.status_code == 200
    assert client.post("/auth/login", json={"email": "cliente@example.com", "password": CLAVE}).status_code == 401
    assert client.post("/auth/login", json={"email": "cliente@example.com", "password": "NuevaClave2026*"}).status_code == 200


def test_solicitar_reset_no_revela_si_el_correo_existe(client, admin, externos):
    r = client.post("/auth/solicitar-reset", json={"email": "nadie@example.com"})
    assert r.status_code == 200 and "Si el correo está registrado" in r.json()["mensaje"]
    externos["codigo"].assert_not_called()


def test_cambiar_clave_exige_la_clave_actual(client, admin):
    id_usuario = _registrar(client).json()["id_usuario"]

    mal = client.put(f"/users/{id_usuario}/cambiar-clave", json={"clave_actual": "no-es", "clave_nueva": "NuevaClave2026*"})
    bien = client.put(f"/users/{id_usuario}/cambiar-clave", json={"clave_actual": CLAVE, "clave_nueva": "NuevaClave2026*"})

    assert mal.status_code == 401 and bien.status_code == 200


# --- Permisos --------------------------------------------------------------------------------

def test_solo_el_administrador_puede_listar_usuarios(client, admin):
    _registrar(client)

    assert client.get("/users").status_code == 401                                              # sin token
    assert client.get("/users", headers=_token(client, "cliente@example.com")).status_code == 403  # cliente
    lista = client.get("/users", headers=_token(client, "admin@example.com"))                  # admin
    assert lista.status_code == 200 and len(lista.json()) == 2
    assert len(client.get("/users", params={"estado": "rechazado"}, headers=_token(client, "admin@example.com")).json()) == 0


def test_un_cliente_solo_puede_modificar_su_propio_perfil(client, admin):
    propio = _registrar(client).json()["id_usuario"]
    cabeceras = _token(client, "cliente@example.com")

    actualizado = client.patch(f"/users/{propio}", json={"nombre": "Juan David", "telefono": "+573012223344"}, headers=cabeceras)
    ajeno = client.patch(f"/users/{admin['id_usuario']}", json={"nombre": "Hackeado"}, headers=cabeceras)
    correo_en_uso = client.patch(f"/users/{propio}", json={"email": "admin@example.com"}, headers=cabeceras)

    assert actualizado.status_code == 200 and actualizado.json()["nombre"] == "Juan David"
    assert ajeno.status_code == 403
    assert correo_en_uso.status_code == 400
    assert client.get(f"/users/{propio}").json()["telefono"] == "+573012223344"
    assert client.get(f"/users/{uuid.uuid4()}").status_code == 404
