"""Pruebas de INTEGRACION: PIN, clave dinamica y verificacion KYC manual (endpoint + base de datos)."""
import uuid
from unittest.mock import patch

import pytest

from app import kyc_provider
from app.models import Usuario, VerificacionKyc

CLAVE = "Monteria2026*"


@pytest.fixture(autouse=True)
def externos():
    with (
        patch("app.routers.users.password_comprometida", return_value=0),
        patch("app.kyc_provider.verify_identity", return_value=("aprobado", "VERIFIK")) as kyc,
        patch("app.routers.users.publish_event", return_value=True),
        patch("app.routers.kyc.publish_event", return_value=True) as publicar,
        patch("app.routers.auth._entregar_codigo") as entregar_codigo,
    ):
        yield {"kyc": kyc, "publicar": publicar, "codigo": entregar_codigo}


@pytest.fixture
def cliente(client):
    """Un administrador (primer registro) y un cliente sin documento, todavia pendiente de KYC."""
    base = {"nombre": "Admin", "telefono": "+573000000001", "pais_residencia": "CO", "password": CLAVE}
    client.post("/users", json={**base, "email": "admin@example.com"})
    r = client.post("/users", json={**base, "nombre": "Juan", "email": "cliente@example.com", "telefono": "+573001234567"})
    assert r.status_code == 201 and r.json()["estado"] == "pendiente_verificacion"
    return r.json()


def _cabeceras(client) -> dict:
    token = client.post("/auth/login", json={"email": "cliente@example.com", "password": CLAVE}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _codigo_enviado(externos) -> str:
    mensaje = externos["codigo"].call_args.args[2]
    return next(p.strip(".") for p in mensaje.split() if p.strip(".").isdigit() and len(p.strip(".")) == 6)


# --- PIN -------------------------------------------------------------------------------------

def test_configurar_el_pin_y_entrar_con_el(client, sesiones, cliente):
    id_usuario = cliente["id_usuario"]
    assert client.get(f"/auth/pin/status/{id_usuario}").json()["tiene_pin"] is False

    assert client.post("/auth/pin/configurar", json={"id_usuario": id_usuario, "pin": "4821"}).json()["tiene_pin"] is True

    with sesiones() as db:
        guardado = db.get(Usuario, uuid.UUID(id_usuario)).pin_hash
        assert guardado != "4821" and guardado.startswith("$2")  # el PIN tambien se guarda con hash
    entra = client.post("/auth/pin/login", json={"identificador": "3001234567", "pin": "4821"})
    no_entra = client.post("/auth/pin/login", json={"identificador": "3001234567", "pin": "0000"})
    assert entra.status_code == 200 and entra.json()["usuario"]["id_usuario"] == id_usuario
    assert no_entra.status_code == 401


def test_pin_login_con_telefono_repetido_entra_en_la_cuenta_correcta(client, cliente):
    """Regresion: dos cuentas con el MISMO telefono, cada una con su PIN.

    El telefono no es unico, asi que un numero puede quedar asociado a varias
    cuentas. El login por telefono + PIN debe entrar en la cuenta cuyo PIN
    coincide, no siempre en la primera. Antes del fix, la segunda cuenta recibia
    401 ('PIN incorrecto') aunque su PIN fuera correcto.
    """
    tel = "+573001234567"  # mismo telefono del cliente de la fixture
    id_a = cliente["id_usuario"]
    client.post("/auth/pin/configurar", json={"id_usuario": id_a, "pin": "1111"})

    id_b = client.post(
        "/users",
        json={"nombre": "Otro", "email": "otro@example.com", "telefono": tel,
              "pais_residencia": "CO", "password": CLAVE},
    ).json()["id_usuario"]
    client.post("/auth/pin/configurar", json={"id_usuario": id_b, "pin": "2222"})

    entra_a = client.post("/auth/pin/login", json={"identificador": "3001234567", "pin": "1111"})
    entra_b = client.post("/auth/pin/login", json={"identificador": "3001234567", "pin": "2222"})

    assert entra_a.status_code == 200 and entra_a.json()["usuario"]["id_usuario"] == id_a
    assert entra_b.status_code == 200 and entra_b.json()["usuario"]["id_usuario"] == id_b


def test_pin_con_segundo_factor_envia_el_codigo(client, cliente, externos):
    client.post("/auth/pin/configurar", json={"id_usuario": cliente["id_usuario"], "pin": "4821"})

    r = client.post("/auth/pin/solicitar-codigo", json={"identificador": "cliente@example.com", "pin": "4821"})
    confirmado = client.post("/auth/login/confirmar-codigo", json={"id_usuario": cliente["id_usuario"], "codigo": _codigo_enviado(externos)})

    assert r.status_code == 200 and r.json()["requiere_2fa"] is True
    assert confirmado.status_code == 200 and confirmado.json()["token_type"] == "bearer"


@pytest.mark.parametrize("pin", ["123", "12345", "12a4"])
def test_el_pin_debe_tener_cuatro_digitos(client, cliente, pin):
    assert client.post("/auth/pin/configurar", json={"id_usuario": cliente["id_usuario"], "pin": pin}).status_code == 422


def test_pin_de_usuario_inexistente_o_sin_pin(client, cliente):
    assert client.post("/auth/pin/configurar", json={"id_usuario": str(uuid.uuid4()), "pin": "1234"}).status_code == 404
    assert client.get(f"/auth/pin/status/{uuid.uuid4()}").status_code == 404
    assert client.post("/auth/pin/login", json={"identificador": "cliente@example.com", "pin": "1234"}).status_code == 401


# --- Clave dinamica y OTP --------------------------------------------------------------------

def test_clave_dinamica_se_mantiene_hasta_que_se_pide_una_nueva(client, cliente):
    cabeceras = _cabeceras(client)

    primera = client.get("/auth/clave-dinamica", headers=cabeceras).json()
    misma = client.get("/auth/clave-dinamica", headers=cabeceras).json()

    assert len(primera["codigo"]) == 6 and primera["ventana_segundos"] == 60
    assert misma["codigo"] == primera["codigo"]
    valida = client.post("/auth/otp/validar", json={"id_usuario": cliente["id_usuario"], "codigo": primera["codigo"]})
    assert valida.json()["valido"] is True
    assert client.get("/auth/clave-dinamica", params={"nueva": True}, headers=cabeceras).status_code == 200
    assert client.get("/auth/clave-dinamica").status_code == 401  # exige sesion


def test_otp_por_correo_es_de_un_solo_uso(client, cliente, externos):
    id_usuario = cliente["id_usuario"]

    generado = client.post("/auth/otp/generar", json={"id_usuario": id_usuario, "operacion": "transferencia"})
    assert generado.json()["valido"] is True and generado.json()["codigo_debug"] is None
    assert "transferencia" in externos["codigo"].call_args.args[2]
    codigo = _codigo_enviado(externos)

    equivocado = client.post("/auth/otp/validar", json={"id_usuario": id_usuario, "codigo": "000000" if codigo != "000000" else "111111"})
    correcto = client.post("/auth/otp/validar", json={"id_usuario": id_usuario, "codigo": codigo})
    reutilizado = client.post("/auth/otp/validar", json={"id_usuario": id_usuario, "codigo": codigo})

    assert equivocado.json()["valido"] is False
    assert correcto.json()["valido"] is True
    assert reutilizado.json()["valido"] is False
    assert client.post("/auth/otp/generar", json={"id_usuario": str(uuid.uuid4())}).status_code == 404


# --- KYC manual ------------------------------------------------------------------------------

def _verificar(client, id_usuario, numero="1065000111"):
    return client.post("/kyc/verify", json={
        "id_usuario": id_usuario, "tipo_documento": "cedula", "numero_documento": numero,
        "pais_emision": "CO", "fecha_expiracion": "2035-01-01",
    })


def test_kyc_aprobado_verifica_al_usuario_y_publica_el_evento(client, sesiones, cliente, externos):
    r = _verificar(client, cliente["id_usuario"])

    assert r.status_code == 200
    assert r.json()["estado_usuario"] == "verificado" and r.json()["event_published"] is True
    assert r.json()["event_name"] == "identity.verified"
    assert externos["publicar"].call_args.args[1]["proveedor_externo"] == "VERIFIK"
    historial = client.get(f"/kyc/{cliente['id_usuario']}").json()
    assert len(historial) == 1 and historial[0]["resultado"] == "aprobado"
    # Un usuario ya verificado no se vuelve a verificar
    assert _verificar(client, cliente["id_usuario"]).status_code == 409


def test_kyc_rechazado_no_publica_evento(client, cliente, externos):
    externos["kyc"].return_value = ("rechazado", "VERIFIK")

    r = _verificar(client, cliente["id_usuario"])

    assert r.json()["estado_usuario"] == "rechazado" and r.json()["event_published"] is False
    externos["publicar"].assert_not_called()


def test_kyc_con_proveedor_caido_responde_503_y_no_registra_verificacion(client, sesiones, cliente, externos):
    externos["kyc"].side_effect = kyc_provider.KycProviderError("Verifik: timeout")

    r = _verificar(client, cliente["id_usuario"])

    assert r.status_code == 503
    with sesiones() as db:
        assert db.query(VerificacionKyc).count() == 0
    assert client.get(f"/users/{cliente['id_usuario']}").json()["estado"] == "pendiente_verificacion"


def test_kyc_de_usuario_inexistente_responde_404(client, cliente):
    assert _verificar(client, str(uuid.uuid4())).status_code == 404
    assert client.get(f"/kyc/{uuid.uuid4()}").status_code == 404
