"""Proveedor KYC externo simulado.

En BankLite la verificacion de identidad la hace un proveedor externo
especializado. Aqui se simula de forma determinista para poder demostrar
los dos caminos (aprobado y rechazado) sin depender de un tercero real.

Regla de simulacion: si el numero de documento termina en '0000' se rechaza.
"""

import hashlib
import uuid


def hash_document(document_number: str) -> str:
    return hashlib.sha256(document_number.encode("utf-8")).hexdigest()


def verify_identity(document_type: str, document_number: str) -> tuple[str, str]:
    """Devuelve (verification_status, provider_reference)."""
    reference = f"KYC-{uuid.uuid4().hex[:12].upper()}"
    if document_number.endswith("0000"):
        return "rejected", reference
    return "approved", reference
