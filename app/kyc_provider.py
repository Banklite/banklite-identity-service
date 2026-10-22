"""Proveedor KYC externo + evaluacion de riesgo.

Proveedores REALES (se usan si su credencial esta configurada):

1. VERIFIK  — variable VERIFIK_TOKEN. Registraduria/Procuraduria/DIAN/ADRES.
2. TRUORA   — variable TRUORA_API_KEY. Background checks gubernamentales.

Si hay un proveedor configurado y TODOS fallan, se lanza KycProviderError: el
usuario NO se aprueba "por defecto". Solo cuando no hay ningun proveedor
configurado se hace una validacion local de formato, claramente etiquetada como
tal (proveedor_externo = VALIDACION_LOCAL_FORMATO) y con riesgo "medio", porque
no verifica la identidad contra ninguna fuente oficial.
"""

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

VERIFIK_TOKEN = os.getenv("VERIFIK_TOKEN")
TRUORA_API_KEY = os.getenv("TRUORA_API_KEY")

# Mapeo de tipos de documento
VERIFIK_DOC_TYPES = {
    "cedula": "CC",
    "cc": "CC",
    "cedula_ciudadania": "CC",
    "cedula_extranjeria": "CE",
    "ce": "CE",
    "pasaporte": "PAS",
    "tarjeta_identidad": "TI",
    "nit": "NIT",
    "ppt": "PPT",
    "pep": "PEP",
}


def _verify_with_verifik(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Verificacion via Verifik oficial — una sola llamada GET instantanea."""
    token = os.getenv("VERIFIK_TOKEN") or VERIFIK_TOKEN
    doc_type = VERIFIK_DOC_TYPES.get(tipo_documento.lower(), "CC")
    doc_number = "".join(ch for ch in numero_documento if ch.isdigit())

    url = (
        f"https://api.verifik.co/v2/co/cedula"
        f"?documentType={doc_type}"
        f"&documentNumber={doc_number}"
    )
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            data = res_data.get("data", {})
            full_name = data.get("fullName", "")
            ref_id = res_data.get("id", "verifik-live")

            if full_name:
                logger.info("[VERIFIK-REAL] Documento %s %s verificado: %s", doc_type, doc_number[-4:], full_name)
                return "aprobado", f"VERIFIK-{ref_id}"
            else:
                logger.warning("[VERIFIK-REAL] Respuesta sin nombre para %s", doc_number[-4:])
                return "rechazado", f"VERIFIK-{ref_id}"

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 404:
            return "rechazado", "VERIFIK-NOT_FOUND"
        elif e.code == 401:
            logger.error("Verifik 401: Token invalido o agotado")
            raise RuntimeError("Verifik: token invalido")
        else:
            logger.error("Verifik HTTP %d: %s", e.code, body[:200])
            raise RuntimeError(f"Verifik error HTTP {e.code}")


def _verify_with_truora(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Verificacion via Truora oficial."""
    url_create = "https://api.checks.truora.com/v1/checks"
    data = urllib.parse.urlencode({
        "type": "person",
        "country": "CO",
        "national_id": numero_documento,
        "user_authorized": "true",
    }).encode("utf-8")

    req_create = urllib.request.Request(url_create, data=data, method="POST")
    req_create.add_header("Truora-API-Key", TRUORA_API_KEY)
    req_create.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urllib.request.urlopen(req_create, timeout=10) as response:
        res_data = json.loads(response.read().decode("utf-8"))
        check_id = res_data.get("check", {}).get("check_id")

    if not check_id:
        raise RuntimeError("Truora no devolvio check_id")

    url_get = f"https://api.checks.truora.com/v1/checks/{check_id}"
    req_get = urllib.request.Request(url_get, method="GET")
    req_get.add_header("Truora-API-Key", TRUORA_API_KEY)

    for _ in range(6):
        time.sleep(2)
        with urllib.request.urlopen(req_get, timeout=10) as get_res:
            get_data = json.loads(get_res.read().decode("utf-8"))
            status = get_data.get("check", {}).get("status")
            if status == "completed":
                scores = get_data.get("check", {}).get("scores", [])
                for score_obj in scores:
                    if score_obj.get("score", 1.0) < 0.6:
                        return "rechazado", f"TRUORA-{check_id}"
                return "aprobado", f"TRUORA-{check_id}"
            elif status == "error":
                break

    raise RuntimeError(f"Truora no completo la verificacion a tiempo ({check_id})")


class KycProviderError(RuntimeError):
    """Ningun proveedor KYC configurado pudo dar una respuesta."""


PROVEEDOR_LOCAL = "VALIDACION_LOCAL_FORMATO"


def _validacion_local_formato(numero_documento: str) -> tuple[str, str]:
    """Solo valida longitud y rango de una cedula colombiana. NO verifica identidad."""
    clean_num = "".join(ch for ch in numero_documento if ch.isdigit())
    if len(clean_num) < 6 or len(clean_num) > 11 or int(clean_num or 0) < 1_000_000:
        return "rechazado", PROVEEDOR_LOCAL
    return "aprobado", PROVEEDOR_LOCAL


def verify_identity(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Devuelve (resultado, proveedor_externo).

    - Con VERIFIK_TOKEN y/o TRUORA_API_KEY: usa esos proveedores en ese orden; si
      todos fallan lanza KycProviderError (nunca aprueba por defecto).
    - Sin ningun proveedor configurado: validacion local de formato, etiquetada.
    """
    token_v = os.getenv("VERIFIK_TOKEN") or VERIFIK_TOKEN
    token_t = os.getenv("TRUORA_API_KEY") or TRUORA_API_KEY

    if not token_v and not token_t:
        logger.warning("KYC sin proveedor configurado: solo validacion local de formato")
        return _validacion_local_formato(numero_documento)

    errores: list[str] = []
    if token_v:
        try:
            return _verify_with_verifik(tipo_documento, numero_documento)
        except Exception as e:  # noqa: BLE001
            logger.error("Error llamando Verifik: %s", e)
            errores.append(f"Verifik: {e}")
    if token_t:
        try:
            return _verify_with_truora(tipo_documento, numero_documento)
        except Exception as e:  # noqa: BLE001
            logger.error("Error llamando Truora: %s", e)
            errores.append(f"Truora: {e}")
    raise KycProviderError("; ".join(errores))


def evaluate_risk(numero_documento: str, resultado: str, proveedor_externo: str = "") -> tuple[str, float]:
    """Devuelve (nivel_riesgo, score) derivados de la verificacion real, sin azar.

    - rechazado                         -> alto  (90)
    - aprobado por un proveedor oficial -> bajo  (10)
    - aprobado solo por formato local   -> medio (50): identidad sin verificar
    """
    if resultado == "rechazado":
        return "alto", 90.0
    if proveedor_externo == PROVEEDOR_LOCAL:
        return "medio", 50.0
    return "bajo", 10.0
