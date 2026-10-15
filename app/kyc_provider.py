"""Proveedor KYC externo + motor de evaluacion de riesgo.

Soporta TRES modos de verificacion (en orden de prioridad):

1. VERIFIK (recomendado) — variable VERIFIK_TOKEN
   Consulta la Registraduria Nacional, Procuraduria, DIAN y ADRES de Colombia
   en una sola llamada GET. Respuesta instantanea, sin polling.
   Docs: https://docs.verifik.co/identity-validation/colombia/colombian-citizen/

2. TRUORA — variable TRUORA_API_KEY
   Crea un background check y hace polling hasta que Truora complete.
   Consulta antecedentes judiciales y bases gubernamentales.

3. SIMULADO — si no hay ninguna API key configurada
   Para desarrollo local. Cedulas terminadas en 0000/1111 son rechazadas.
"""

import os
import hashlib
import json
import urllib.request
import urllib.parse
import urllib.error
import time
import logging

logger = logging.getLogger(__name__)

VERIFIK_TOKEN = os.getenv("VERIFIK_TOKEN")
TRUORA_API_KEY = os.getenv("TRUORA_API_KEY")

# ── Mapeo de tipos de documento del frontend al formato de Verifik ──
VERIFIK_DOC_TYPES = {
    "cedula": "CC",
    "cc": "CC",
    "cedula_ciudadania": "CC",
    "cedula_extranjeria": "CE",
    "ce": "CE",
    "pasaporte": "CC",       # Verifik no valida pasaportes, fallback a CC
    "tarjeta_identidad": "CC",  # Menores: se valida como CC
    "nit": "NIT",
    "ppt": "PPT",
    "pep": "PEP",
}


def _verify_with_verifik(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Verificacion via Verifik — una sola llamada GET, respuesta instantanea."""
    doc_type = VERIFIK_DOC_TYPES.get(tipo_documento.lower(), "CC")
    # Solo digitos, sin puntos ni espacios
    doc_number = "".join(ch for ch in numero_documento if ch.isdigit())

    url = (
        f"https://api.verifik.co/v2/co/cedula"
        f"?documentType={doc_type}"
        f"&documentNumber={doc_number}"
    )
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    req.add_header("Authorization", f"Bearer {VERIFIK_TOKEN}")

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            data = res_data.get("data", {})
            full_name = data.get("fullName", "")
            ref_id = res_data.get("id", "unknown")

            if full_name:
                # Documento encontrado en fuentes oficiales → aprobado
                logger.info(
                    "Verifik: documento %s %s verificado — %s",
                    doc_type, doc_number[-4:], full_name,
                )
                return "aprobado", f"VERIFIK-{ref_id}"
            else:
                # Respuesta 200 pero sin nombre → datos incompletos
                logger.warning("Verifik: respuesta sin fullName para %s", doc_number[-4:])
                return "rechazado", f"VERIFIK-{ref_id}"

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        if e.code == 404:
            # Documento no encontrado en la Registraduria
            logger.info("Verifik: documento %s no encontrado (404)", doc_number[-4:])
            return "rechazado", f"VERIFIK-NOT_FOUND"
        elif e.code == 401:
            logger.error("Verifik: token invalido o expirado (401)")
            raise RuntimeError("Verifik: token invalido — revisa VERIFIK_TOKEN")
        else:
            logger.error("Verifik HTTP %d: %s", e.code, body[:200])
            raise RuntimeError(f"Verifik error HTTP {e.code}")


def _verify_with_truora(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Verificacion via Truora — crea check + polling."""
    # 1. Crear el background check
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

    # 2. Polling hasta que Truora complete
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

    raise RuntimeError(f"Truora no completo la verificacion a tiempo (check {check_id})")


def verify_identity(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Devuelve (resultado, proveedor_externo).

    Prioridad: Verifik > Truora > Simulador local.
    Si una API key esta configurada y la llamada falla, NO se aprueba
    por simulacion: se propaga el error.
    """
    # ── VERIFIK (prioridad 1) ──
    if VERIFIK_TOKEN:
        try:
            return _verify_with_verifik(tipo_documento, numero_documento)
        except Exception as e:
            logger.error("Error en Verifik: %s", e)
            raise

    # ── TRUORA (prioridad 2) ──
    if TRUORA_API_KEY:
        try:
            return _verify_with_truora(tipo_documento, numero_documento)
        except Exception as e:
            logger.error("Error en Truora: %s", e)
            raise

    # ── SIMULACION LOCAL (sin API keys) ──
    referencia = f"SIMULADO-{hashlib.sha1(numero_documento.encode('utf-8')).hexdigest()[:8].upper()}"

    # Regla 1: Terminacion 0000 = Documento invalido / fraude de identidad
    if numero_documento.endswith("0000"):
        return "rechazado", referencia

    # Regla 2: Terminacion 1111 = TIENE ANTECEDENTES JUDICIALES
    if numero_documento.endswith("1111"):
        return "rechazado", referencia

    # El resto se aprueba
    return "aprobado", referencia


def evaluate_risk(numero_documento: str, resultado: str) -> tuple[str, float]:
    """Devuelve (nivel_riesgo, score) para poblar evaluacion_riesgo."""
    score = int(hashlib.md5(numero_documento.encode("utf-8")).hexdigest(), 16) % 100
    if resultado == "rechazado":
        return "alto", float(max(score, 71))
    if score < 30:
        return "bajo", float(score)
    if score < 70:
        return "medio", float(score)
    return "alto", float(score)
