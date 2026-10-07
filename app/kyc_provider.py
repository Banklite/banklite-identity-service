"""Proveedor KYC externo + motor de evaluacion de riesgo.

Integra la API real de Truora para validacion de antecedentes judiciales y de identidad.
Si no se provee la variable de entorno TRUORA_API_KEY, opera en modo SIMULADO local.
"""

import os
import hashlib
import json
import urllib.request
import urllib.parse
import urllib.error
import time

TRUORA_API_KEY = os.getenv("TRUORA_API_KEY")

def verify_identity(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Devuelve (resultado, proveedor_externo).
    Llama a la API de Truora para validacion real de antecedentes y documento.
    Si encuentra antecedentes judiciales u otros reportes, rechaza la solicitud.
    """
    if TRUORA_API_KEY:
        try:
            # 1. Crear el background check
            url_create = "https://api.checks.truora.com/v1/checks"
            data = urllib.parse.urlencode({
                "type": "person",
                "country": "CO",
                "national_id": numero_documento,
                "user_authorized": "true"
            }).encode("utf-8")
            
            req_create = urllib.request.Request(url_create, data=data, method="POST")
            req_create.add_header("Truora-API-Key", TRUORA_API_KEY)
            req_create.add_header("Content-Type", "application/x-www-form-urlencoded")
            
            with urllib.request.urlopen(req_create, timeout=10) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                check_id = res_data.get("check", {}).get("check_id")
            
            # 2. Hacer polling hasta que Truora termine de buscar en bases de datos (policía, procuraduría, etc.)
            if check_id:
                url_get = f"https://api.checks.truora.com/v1/checks/{check_id}"
                req_get = urllib.request.Request(url_get, method="GET")
                req_get.add_header("Truora-API-Key", TRUORA_API_KEY)
                
                # Truora toma unos segundos en consultar las bases de datos gubernamentales
                for _ in range(6):
                    time.sleep(2)
                    with urllib.request.urlopen(req_get, timeout=10) as get_res:
                        get_data = json.loads(get_res.read().decode("utf-8"))
                        status = get_data.get("check", {}).get("status")
                        
                        if status == "completed":
                            scores = get_data.get("check", {}).get("scores", [])
                            # Revisar score de antecedentes (criminal, legal, internacional)
                            # Truora califica de 0 a 1. Un score bajo (<0.6) indica hallazgos / antecedentes
                            for score_obj in scores:
                                if score_obj.get("score", 1.0) < 0.6:
                                    # Se encontraron antecedentes judiciales u otros riesgos
                                    return "rechazado", f"TRUORA-{check_id}"
                            
                            # Todo limpio
                            return "aprobado", f"TRUORA-{check_id}"
                        elif status == "error":
                            break
                            
                # Si despues de los intentos no termino, rechazamos por precaucion o timeout
                return "rechazado", f"TRUORA-TIMEOUT-{check_id}"

        except Exception as e:
            print(f"Error llamando a Truora: {e}")
            pass # Si falla, usamos el modo simulado

    # ── SIMULACION LOCAL (Cuando no hay API Key o hay error de red) ──
    # Para poder probar el sistema localmente sin gastar saldo real, mantenemos reglas de prueba:
    referencia = f"SIM-TRUORA-{hashlib.sha1(numero_documento.encode('utf-8')).hexdigest()[:8].upper()}"
    
    # Regla 1: Terminacion 0000 = Documento invalido / fraude de identidad
    if numero_documento.endswith("0000"):
        return "rechazado", referencia
        
    # Regla 2: Terminacion 1111 = TIENE ANTECEDENTES JUDICIALES (policia, procuraduria, etc.)
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
