"""Proveedor KYC externo simulado + motor de evaluacion de riesgo.

En BankLite la verificacion de identidad la hace un proveedor externo
especializado, y cada verificacion alimenta una evaluacion de riesgo (tabla
evaluacion_riesgo). Ambos se simulan aqui de forma determinista para poder
demostrar los distintos caminos sin depender de un tercero real.

Regla de simulacion KYC: un numero_documento que termine en '0000' se
rechaza; el resto se aprueba.

Regla de simulacion de riesgo: el score (0-100, entre mas alto mas
riesgoso) se deriva de un hash del numero_documento, para que sea
reproducible en las pruebas. Un resultado 'rechazado' siempre se clasifica
como riesgo 'alto'.
"""

import hashlib


def verify_identity(tipo_documento: str, numero_documento: str) -> tuple[str, str]:
    """Devuelve (resultado, proveedor_externo)."""
    referencia = f"KYC-{hashlib.sha1(numero_documento.encode('utf-8')).hexdigest()[:12].upper()}"
    if numero_documento.endswith("0000"):
        return "rechazado", referencia
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
