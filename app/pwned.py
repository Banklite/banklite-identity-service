"""Verificacion real de contrasenas filtradas con Have I Been Pwned (HIBP).

Usa k-anonymity: solo se envia el prefijo SHA-1 de 5 caracteres; la contrasena
completa NUNCA sale del servidor. API publica y gratuita:
https://api.pwnedpasswords.com/range/{prefijo}
"""

import hashlib
import logging

import httpx

logger = logging.getLogger(__name__)

HIBP_URL = "https://api.pwnedpasswords.com/range/{prefijo}"
UMBRAL_BLOQUEO = 1


def veces_filtrada(password: str) -> int | None:
    """Devuelve cuantas filtraciones conocidas incluyen la contrasena.

    None si el servicio no esta disponible (se permite continuar: fail-open).
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefijo, sufijo = sha1[:5], sha1[5:]
        r = httpx.get(
            HIBP_URL.format(prefijo=prefijo),
            headers={"Add-Padding": "true", "User-Agent": "BankLite-Security"},
            timeout=6.0,
        )
        r.raise_for_status()
        for linea in r.text.splitlines():
            partes = linea.strip().split(":")
            if len(partes) == 2 and partes[0].upper() == sufijo:
                return int(partes[1])
        return 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("[HIBP] Consulta no disponible: %s", exc)
        return None


def password_comprometida(password: str) -> int | None:
    """Cantidad de apariciones si supera el umbral de bloqueo; 0/None si es segura."""
    veces = veces_filtrada(password)
    if veces is None:
        return None
    return veces if veces >= UMBRAL_BLOQUEO else 0
