"""Pruebas UNITARIAS de seguridad: hash de contrasenas, tokens JWT y clave dinamica (logica pura)."""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt
import pytest
from fastapi import HTTPException

from app import security
from app.config import settings

ID_USUARIO = uuid.uuid4()


def test_la_contrasena_se_guarda_con_hash_bcrypt_y_nunca_en_texto_plano():
    guardado = security.hash_password("Monteria2026*")

    assert guardado != "Monteria2026*" and guardado.startswith("$2")
    assert security.verify_password("Monteria2026*", guardado) is True
    assert security.verify_password("monteria2026*", guardado) is False


def test_dos_hashes_de_la_misma_contrasena_son_distintos():
    assert security.hash_password("Monteria2026*") != security.hash_password("Monteria2026*")  # sal aleatoria


@pytest.mark.parametrize("hash_invalido", ["", "no-es-un-hash"])
def test_un_hash_corrupto_no_autentica_ni_lanza_error(hash_invalido):
    assert security.verify_password("cualquiera", hash_invalido) is False


def test_el_jwt_lleva_el_usuario_su_correo_y_su_rol():
    token = security.create_access_token(ID_USUARIO, "juan@example.com", "admin")

    datos = security.decode_access_token(token)

    assert datos["sub"] == str(ID_USUARIO) and datos["email"] == "juan@example.com" and datos["role"] == "admin"
    vence_en = datetime.fromtimestamp(datos["exp"], timezone.utc) - datetime.now(timezone.utc)
    assert timedelta(minutes=settings.jwt_expire_minutes - 1) < vence_en <= timedelta(minutes=settings.jwt_expire_minutes)


def test_token_vencido_o_firmado_con_otra_clave_responde_401():
    vencido = jwt.encode(
        {"sub": str(ID_USUARIO), "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        settings.jwt_secret, algorithm=settings.jwt_algorithm,
    )
    ajeno = jwt.encode({"sub": str(ID_USUARIO)}, "otra-clave-secreta-de-al-menos-32-bytes", algorithm="HS256")

    for token in (vencido, ajeno, "esto.no.esunjwt"):
        with pytest.raises(HTTPException) as error:
            security.get_current_user(token)
        assert error.value.status_code == 401


def test_solo_el_rol_admin_pasa_el_control_de_administrador():
    assert security.require_admin({"sub": "1", "role": "admin"})["role"] == "admin"
    with pytest.raises(HTTPException) as error:
        security.require_admin({"sub": "2", "role": "cliente"})
    assert error.value.status_code == 403


def test_la_clave_dinamica_tiene_seis_digitos_y_depende_del_usuario():
    with patch("app.security.time.time", return_value=1_800_000_000):
        clave, restantes = security.generar_clave_dinamica(ID_USUARIO)
        de_otro, _ = security.generar_clave_dinamica(uuid.uuid4())

    assert len(clave) == 6 and clave.isdigit()
    assert 1 <= restantes <= security.VENTANA_CLAVE_DINAMICA
    assert clave != de_otro


def test_la_clave_dinamica_vale_en_su_ventana_y_en_la_siguiente_pero_no_despues():
    t0 = 1_800_000_000
    with patch("app.security.time.time", return_value=t0):
        clave, _ = security.generar_clave_dinamica(ID_USUARIO)
        assert security.clave_dinamica_valida(ID_USUARIO, clave) is True
        assert security.clave_dinamica_valida(ID_USUARIO, "000000" if clave != "000000" else "111111") is False
    with patch("app.security.time.time", return_value=t0 + 60):   # ventana siguiente: aun se tolera
        assert security.clave_dinamica_valida(ID_USUARIO, clave) is True
    with patch("app.security.time.time", return_value=t0 + 180):  # tres minutos despues: vencida
        assert security.clave_dinamica_valida(ID_USUARIO, clave) is False
