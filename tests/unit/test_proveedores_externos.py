"""Pruebas UNITARIAS de las integraciones externas de identidad, con mocks.

- Have I Been Pwned (contrasenas filtradas): httpx.get simulado.
- Proveedores KYC (Verifik / Truora): funciones del proveedor simuladas.
- Digito de verificacion DIAN y nivel de riesgo: logica pura.
"""
import hashlib
from unittest.mock import patch

import httpx
import pytest

from app import kyc_provider, pwned
from app.routers.users import calcular_digito_verificacion_dian

# --- Have I Been Pwned -----------------------------------------------------------------------

CLAVE = "123456"
SHA1 = hashlib.sha1(CLAVE.encode()).hexdigest().upper()


def _hibp(texto: str) -> httpx.Response:
    return httpx.Response(200, text=texto, request=httpx.Request("GET", "https://api.pwnedpasswords.com"))


def test_contrasena_filtrada_devuelve_el_numero_de_filtraciones():
    cuerpo = f"0000000000000000000000000000000000A:3\r\n{SHA1[5:]}:209972\r\n"
    with patch("app.pwned.httpx.get", return_value=_hibp(cuerpo)) as mock_get:
        assert pwned.password_comprometida(CLAVE) == 209972

    # k-anonymity: al servicio externo solo viajan los 5 primeros caracteres del SHA-1
    url = mock_get.call_args.args[0]
    assert url.endswith(f"/range/{SHA1[:5]}") and SHA1[5:] not in url and CLAVE not in url


def test_contrasena_que_no_aparece_es_segura():
    with patch("app.pwned.httpx.get", return_value=_hibp("0000000000000000000000000000000000A:3\r\n")):
        assert pwned.password_comprometida("Xk9#mP2$vL8@qR5") == 0


def test_si_hibp_no_responde_se_permite_continuar():
    with patch("app.pwned.httpx.get", side_effect=httpx.ConnectTimeout("timeout")):
        assert pwned.veces_filtrada(CLAVE) is None
        assert pwned.password_comprometida(CLAVE) is None


# --- KYC -------------------------------------------------------------------------------------

@pytest.fixture
def sin_proveedores(monkeypatch):
    monkeypatch.delenv("VERIFIK_TOKEN", raising=False)
    monkeypatch.delenv("TRUORA_API_KEY", raising=False)
    monkeypatch.setattr(kyc_provider, "VERIFIK_TOKEN", None)
    monkeypatch.setattr(kyc_provider, "TRUORA_API_KEY", None)


@pytest.mark.parametrize("documento, resultado", [
    ("1065000111", "aprobado"), ("78.028.895", "aprobado"),
    ("12345", "rechazado"), ("999999", "rechazado"), ("123456789012", "rechazado"), ("", "rechazado"),
])
def test_sin_proveedor_solo_se_valida_el_formato_y_queda_etiquetado(sin_proveedores, documento, resultado):
    assert kyc_provider.verify_identity("cedula", documento) == (resultado, kyc_provider.PROVEEDOR_LOCAL)


def test_con_token_se_consulta_a_verifik(sin_proveedores, monkeypatch):
    monkeypatch.setenv("VERIFIK_TOKEN", "token-de-prueba")
    with patch("app.kyc_provider._verify_with_verifik", return_value=("aprobado", "VERIFIK")) as verifik:
        assert kyc_provider.verify_identity("cedula", "1065000111") == ("aprobado", "VERIFIK")
    verifik.assert_called_once_with("cedula", "1065000111")


def test_si_verifik_falla_se_usa_truora(sin_proveedores, monkeypatch):
    monkeypatch.setenv("VERIFIK_TOKEN", "token-de-prueba")
    monkeypatch.setenv("TRUORA_API_KEY", "clave-de-prueba")
    with (
        patch("app.kyc_provider._verify_with_verifik", side_effect=RuntimeError("HTTP 500")),
        patch("app.kyc_provider._verify_with_truora", return_value=("aprobado", "TRUORA")),
    ):
        assert kyc_provider.verify_identity("cedula", "1065000111") == ("aprobado", "TRUORA")


def test_si_todos_los_proveedores_fallan_nunca_se_aprueba_por_defecto(sin_proveedores, monkeypatch):
    monkeypatch.setenv("VERIFIK_TOKEN", "token-de-prueba")
    with patch("app.kyc_provider._verify_with_verifik", side_effect=RuntimeError("HTTP 401")):
        with pytest.raises(kyc_provider.KycProviderError, match="Verifik"):
            kyc_provider.verify_identity("cedula", "1065000111")


@pytest.mark.parametrize("resultado, proveedor, esperado", [
    ("rechazado", "VERIFIK", ("alto", 90.0)),
    ("aprobado", "VERIFIK", ("bajo", 10.0)),
    ("aprobado", kyc_provider.PROVEEDOR_LOCAL, ("medio", 50.0)),  # identidad sin verificar de verdad
])
def test_nivel_de_riesgo_segun_el_resultado_y_el_proveedor(resultado, proveedor, esperado):
    assert kyc_provider.evaluate_risk("1065000111", resultado, proveedor) == esperado


# --- Digito de verificacion DIAN -------------------------------------------------------------

@pytest.mark.parametrize("nit, digito", [
    ("800197268", 4),      # DIAN: 800.197.268-4
    ("890903938", 8),      # Bancolombia: 890.903.938-8
    ("890.903.938", 8),    # se ignoran los puntos
    ("", 0),
])
def test_digito_de_verificacion_dian(nit, digito):
    assert calcular_digito_verificacion_dian(nit) == digito
