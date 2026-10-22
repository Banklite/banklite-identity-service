import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import DocumentoIdentidad, EvaluacionRiesgo, Usuario, VerificacionKyc
from ..schemas import CambiarClave, UsuarioCreate, UsuarioOut
from ..security import get_current_user, hash_password, verify_password
from .. import kyc_provider
from ..pwned import password_comprometida
from ..events import EVENT_IDENTITY_VERIFIED, publish_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["usuarios"])


def get_usuario_or_404(db: Session, id_usuario: uuid.UUID) -> Usuario:
    usuario = db.get(Usuario, id_usuario)
    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No existe un usuario con id {id_usuario}",
        )
    return usuario


def _ejecutar_kyc(
    db: Session,
    usuario: Usuario,
    *,
    numero_doc: str,
    tipo_doc: str,
    pais_emision: str,
    fecha_vencimiento: str | None,
) -> Usuario:
    """Ejecuta (o reintenta) la verificación KYC de un usuario y actualiza su estado."""
    from datetime import datetime

    try:
        usuario.estado_kyc = "VERIFICANDO"
        db.commit()

        # Registrar o reutilizar documento
        documento = (
            db.execute(
                select(DocumentoIdentidad).where(
                    DocumentoIdentidad.numero_documento == numero_doc
                )
            )
            .scalars()
            .first()
        )
        if documento is None:
            from datetime import date, timedelta
            fecha_exp = date.today() + timedelta(days=365 * 5)
            if fecha_vencimiento:
                try:
                    fecha_exp = datetime.strptime(fecha_vencimiento, "%Y-%m-%d").date()
                except ValueError:
                    pass
            documento = DocumentoIdentidad(
                id_usuario=usuario.id_usuario,
                tipo_documento=tipo_doc,
                numero_documento=numero_doc,
                pais_emision=pais_emision,
                fecha_expiracion=fecha_exp,
            )
            db.add(documento)
        elif documento.id_usuario != usuario.id_usuario:
            # Documento ya registrado para otro usuario → rechazo
            usuario.estado = "rechazado"
            usuario.estado_kyc = "RECHAZADO"
            db.commit()
            db.refresh(usuario)
            return usuario

        # Llamar a la API de verificación
        resultado, proveedor_externo = kyc_provider.verify_identity(tipo_doc, numero_doc)

        verificacion = VerificacionKyc(
            id_usuario=usuario.id_usuario,
            proveedor_externo=proveedor_externo,
            resultado=resultado,
        )
        db.add(verificacion)
        db.flush()

        nivel_riesgo, score = kyc_provider.evaluate_risk(numero_doc, resultado, proveedor_externo)
        db.add(
            EvaluacionRiesgo(
                id_verificacion=verificacion.id_verificacion,
                nivel_riesgo=nivel_riesgo,
                score=score,
            )
        )

        usuario.estado = "verificado" if resultado == "aprobado" else "rechazado"
        usuario.estado_kyc = "VERIFICADO" if resultado == "aprobado" else "RECHAZADO"
        db.commit()
        db.refresh(usuario)

        if usuario.estado == "verificado":
            publish_event(
                EVENT_IDENTITY_VERIFIED,
                {
                    "event": EVENT_IDENTITY_VERIFIED,
                    "id_usuario": str(usuario.id_usuario),
                    "email": usuario.email,
                    "pais_residencia": usuario.pais_residencia,
                    "verificado_en": verificacion.fecha_verificacion.isoformat(),
                    "proveedor_externo": proveedor_externo,
                },
            )
    except Exception as exc:
        logger.warning("Error en verificación automática KYC para usuario %s: %s", usuario.id_usuario, exc)
        try:
            usuario.estado_kyc = "ERROR_VERIFICACION"
            db.commit()
            db.refresh(usuario)
        except Exception:
            pass

    return usuario


@router.post("", response_model=UsuarioOut, status_code=status.HTTP_201_CREATED)
def crear_usuario(payload: UsuarioCreate, db: Session = Depends(get_db)):
    """Registra un usuario y ejecuta la verificación KYC automáticamente.

    Flujo:
    1) Crea el usuario con estado 'pendiente_verificacion'.
    2) Si tiene cédula/documento, llama automáticamente a la API de verificación.
    3) Actualiza el estado a 'verificado' o 'rechazado' según el resultado.

    El PRIMER usuario registrado recibe role='admin'.
    """
    total_usuarios = db.execute(select(Usuario)).scalars().first()
    role = "admin" if total_usuarios is None else "cliente"

    from datetime import datetime

    estado_kyc = "PENDIENTE"
    if payload.fecha_nacimiento:
        try:
            fn = datetime.strptime(payload.fecha_nacimiento, "%Y-%m-%d").date()
            today = datetime.now().date()
            edad = today.year - fn.year - ((today.month, today.day) < (fn.month, fn.day))
            if edad < 18:
                if not (
                    payload.representante_nombre
                    and payload.representante_documento
                    and payload.representante_parentesco
                    and payload.representante_telefono
                ):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            "Para menores de 18 años es obligatorio proveer los datos del representante "
                            "(nombre, documento, parentesco y teléfono)"
                        ),
                    )
                estado_kyc = "MENOR_CON_REPRESENTANTE"
        except ValueError:
            pass

    veces = password_comprometida(payload.password)
    if veces:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Esa contraseña apareció en {veces:,} filtraciones de datos conocidas "
                "(Have I Been Pwned). Elige una contraseña distinta."
            ),
        )

    usuario = Usuario(
        nombre=payload.nombre,
        apellido=payload.apellido,
        email=payload.email.lower(),
        telefono=payload.telefono,
        pais_residencia=payload.pais_residencia,
        estado="pendiente_verificacion",
        password_hash=hash_password(payload.password),
        fecha_nacimiento=payload.fecha_nacimiento,
        servicio_solicitado=payload.servicio_solicitado,
        cedula=payload.cedula,
        fecha_expedicion=payload.fecha_expedicion,
        fecha_vencimiento=payload.fecha_vencimiento,
        pais_expedicion=payload.pais_expedicion,
        representante_nombre=payload.representante_nombre,
        representante_documento=payload.representante_documento,
        representante_tipo_documento=payload.representante_tipo_documento,
        representante_parentesco=payload.representante_parentesco,
        representante_telefono=payload.representante_telefono,
        representante_email=payload.representante_email,
        tipo_documento=payload.tipo_documento,
        estado_kyc=estado_kyc,
        role=role,
    )
    db.add(usuario)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"El email {payload.email} ya esta registrado",
        )
    db.refresh(usuario)

    # ─── VERIFICACIÓN AUTOMÁTICA KYC ────────────────────────────────────────
    # Solo si el usuario tiene cédula y el rol es 'cliente'.
    # El admin no necesita pasar por KYC.
    if role == "admin":
        usuario.estado = "verificado"
        usuario.estado_kyc = "VERIFICADO"
        db.commit()
        db.refresh(usuario)
        return usuario

    numero_doc = payload.cedula or ""
    if not numero_doc:
        # Sin documento → queda en pendiente, deberá completar datos luego
        return usuario

    _ejecutar_kyc(
        db,
        usuario,
        numero_doc=numero_doc,
        tipo_doc=payload.tipo_documento or "cedula",
        pais_emision=payload.pais_residencia or "CO",
        fecha_vencimiento=payload.fecha_vencimiento,
    )
    return usuario


from ..security import hash_password, require_admin


@router.get("", response_model=list[UsuarioOut])
def listar_usuarios(
    db: Session = Depends(get_db),
    estado: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin_user: dict = Depends(require_admin),
):
    stmt = select(Usuario).order_by(Usuario.fecha_registro.desc()).limit(limit).offset(offset)
    if estado:
        stmt = stmt.where(Usuario.estado == estado)
    return db.execute(stmt).scalars().all()


@router.get("/by-telefono/{telefono}")
def buscar_por_telefono(telefono: str, db: Session = Depends(get_db)):
    """Busca un usuario por su número de celular para transferencias estilo Nequi/Bre-B."""
    clean = "".join(ch for ch in telefono if ch.isdigit())
    if not clean or len(clean) < 7:
        raise HTTPException(status_code=400, detail="Número de teléfono inválido")

    stmt = select(Usuario).where(
        (Usuario.telefono == telefono)
        | (Usuario.telefono == f"+{clean}")
        | (Usuario.telefono == f"+57{clean}")
        | (Usuario.telefono.ilike(f"%{clean[-10:]}"))
    )
    usuario = db.execute(stmt).scalars().first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado con ese número de celular")

    return {
        "id_usuario": str(usuario.id_usuario),
        "nombre": usuario.nombre,
        "apellido": usuario.apellido,
        "telefono": usuario.telefono,
        "email": usuario.email,
        "estado": usuario.estado,
    }




from ..schemas import UsuarioUpdate


@router.patch("/{id_usuario}", response_model=UsuarioOut)
def actualizar_usuario(
    id_usuario: uuid.UUID,
    payload: UsuarioUpdate,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    # Solo el propio usuario o un administrador pueden modificar un perfil.
    if user.get("sub") != str(id_usuario) and user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No puedes modificar el perfil de otro usuario.",
        )
    usuario = get_usuario_or_404(db, id_usuario)

    if payload.nombre is not None and payload.nombre.strip():
        usuario.nombre = payload.nombre.strip()
    if payload.apellido is not None:
        usuario.apellido = payload.apellido.strip() if payload.apellido else None
    if payload.email is not None and str(payload.email).strip():
        nuevo_email = str(payload.email).strip().lower()
        # Verificar que otro usuario no tenga ya este email
        existente = db.execute(
            select(Usuario).where(Usuario.email == nuevo_email, Usuario.id_usuario != id_usuario)
        ).scalars().first()
        if existente:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"El correo electrónico {nuevo_email} ya se encuentra registrado por otra persona",
            )
        usuario.email = nuevo_email
    if payload.pais_residencia is not None and payload.pais_residencia.strip():
        usuario.pais_residencia = payload.pais_residencia.strip().upper()
    if payload.servicio_solicitado is not None:
        usuario.servicio_solicitado = payload.servicio_solicitado

    # Datos de documento / KYC (solo editable si aún no tenía cédula)
    if payload.cedula and not usuario.cedula:
        usuario.cedula = payload.cedula
    if payload.fecha_nacimiento:
        usuario.fecha_nacimiento = payload.fecha_nacimiento
    if payload.fecha_expedicion:
        usuario.fecha_expedicion = payload.fecha_expedicion
    if payload.fecha_vencimiento:
        usuario.fecha_vencimiento = payload.fecha_vencimiento
    if payload.pais_expedicion:
        usuario.pais_expedicion = payload.pais_expedicion
    if payload.telefono is not None:
        usuario.telefono = payload.telefono

    db.commit()
    db.refresh(usuario)
    return usuario


@router.put("/{id_usuario}/cambiar-clave")
def cambiar_clave(id_usuario: uuid.UUID, payload: CambiarClave, db: Session = Depends(get_db)):
    usuario = get_usuario_or_404(db, id_usuario)
    if not usuario.password_hash or not verify_password(payload.clave_actual, usuario.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La contraseña actual es incorrecta",
        )

    veces = password_comprometida(payload.clave_nueva)
    if veces:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Esa contraseña apareció en {veces:,} filtraciones de datos conocidas "
                "(Have I Been Pwned). Elige una contraseña distinta."
            ),
        )

    usuario.password_hash = hash_password(payload.clave_nueva)
    db.commit()
    return {"mensaje": "Contraseña actualizada exitosamente"}


@router.post("/{id_usuario}/reverificar",response_model=UsuarioOut)
def reverificar_usuario(
    id_usuario: uuid.UUID,
    db: Session = Depends(get_db),
    admin_user: dict = Depends(require_admin),
):
    """Reintenta la verificación KYC de un usuario que quedó pendiente o con error."""
    usuario = get_usuario_or_404(db, id_usuario)
    if usuario.estado == "verificado":
        return usuario
    if not usuario.cedula:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El usuario no tiene documento registrado; debe completar su perfil primero",
        )
    return _ejecutar_kyc(
        db,
        usuario,
        numero_doc=usuario.cedula,
        tipo_doc=usuario.tipo_documento or "cedula",
        pais_emision=usuario.pais_residencia or "CO",
        fecha_vencimiento=usuario.fecha_vencimiento,
    )


# ============================================================================
# APIS GRATUITAS: VALIDACION DE IDENTIDAD Y DATOS ABIERTOS DE COLOMBIA
# ============================================================================

def calcular_digito_verificacion_dian(nit_o_cedula: str) -> int:
    """Calculo oficial del Digito de Verificacion (DV) segun el Art. 555-2 del Estatuto Tributario DIAN.
    
    Aplica el algoritmo ponderado oficial de la Direccion de Impuestos y Aduanas Nacionales de Colombia.
    """
    clean_num = "".join(ch for ch in str(nit_o_cedula) if ch.isdigit())
    if not clean_num:
        return 0

    pesos = [71, 67, 59, 53, 47, 43, 41, 37, 29, 23, 19, 17, 13, 7, 3]
    total = 0
    clean_padded = clean_num.zfill(15)

    for i in range(15):
        total += int(clean_padded[i]) * pesos[i]

    residuo = total % 11
    if residuo == 0 or residuo == 1:
        return residuo
    return 11 - residuo


@router.get("/validar-identidad/{numero_documento}", tags=["identidad_publica"])
def validar_identidad_colombiana(numero_documento: str):
    """Validacion de FORMATO de un documento colombiano (digito de verificacion DIAN).

    Esto NO consulta antecedentes ni verifica que la persona exista: no hay una
    fuente publica gratuita que lo permita (el dataset de datos.gov.co que se usaba
    dejo de existir y el endpoint respondia "LIMPIO" cuando la consulta fallaba).
    La verificacion real de identidad la hace el proveedor KYC (Verifik/Truora) al
    registrar al usuario, y el screening de sanciones lo hace compliance-service
    (POST /compliance/screenings) por nombre.
    """
    clean_num = "".join(ch for ch in numero_documento if ch.isdigit())
    if len(clean_num) < 6 or len(clean_num) > 11:
        raise HTTPException(status_code=400, detail="Longitud de documento invalida (debe tener entre 6 y 10 digitos)")

    dv_oficial = calcular_digito_verificacion_dian(clean_num)
    return {
        "documento": clean_num,
        "pais": "CO",
        "digito_verificacion_dian": dv_oficial,
        "formato_rut": f"{clean_num}-{dv_oficial}",
        "resultado_validacion": "FORMATO_VALIDO",
        "antecedentes_sancionatorios": "NO_VERIFICADO",
        "nota": "Solo valida el formato. La identidad se verifica con el proveedor KYC al registrarse.",
        "fuentes_consultadas": [
            {
                "nombre": "DIAN (Direccion de Impuestos y Aduanas Nacionales)",
                "tipo": "Algoritmo matematico oficial modulo 11 (solo digito de verificacion)",
                "url": "https://www.dian.gov.co",
            },
        ],
    }


@router.get("/ciudades-colombia", tags=["identidad_publica"])
def listar_municipios_colombia():
    """Consulta en tiempo real la lista oficial de municipios y departamentos de Colombia (DANE DIVIPOLA).
    
    Fuente 100% gratuita y oficial: Departamento Administrativo Nacional de Estadistica (DANE).
    URL API: https://www.datos.gov.co/resource/gdxc-w37w.json
    """
    import urllib.request
    import json
    url = "https://www.datos.gov.co/resource/gdxc-w37w.json?$limit=50&$order=nom_mpio%20ASC"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BankLite-DANE/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return {
                "total": len(data),
                "fuente": "DANE - Codificacion de la Division Politico-Administrativa de Colombia (DIVIPOLA)",
                "enlace_oficial": "https://www.datos.gov.co/Mapas-y-Georreferenciaci-n/DIVIPOLA-Municipios/gdxc-w37w",
                "municipios": [
                    {
                        "departamento": m.get("dpto"),
                        "municipio": m.get("nom_mpio"),
                        "codigo_municipio": m.get("cod_mpio"),
                        "tipo": m.get("tipo_municipio"),
                    }
                    for m in data
                ],
            }
    except Exception as exc:
        pass

    # Fallback con las principales ciudades si la red tarda
    return {
        "total": 5,
        "fuente": "DANE DIVIPOLA (Cache)",
        "enlace_oficial": "https://www.datos.gov.co/Mapas-y-Georreferenciaci-n/DIVIPOLA-Municipios/gdxc-w37w",
        "municipios": [
            {"departamento": "BOGOTA D.C.", "municipio": "BOGOTA D.C.", "codigo_municipio": "11001"},
            {"departamento": "ANTIOQUIA", "municipio": "MEDELLIN", "codigo_municipio": "05001"},
            {"departamento": "VALLE DEL CAUCA", "municipio": "CALI", "codigo_municipio": "76001"},
            {"departamento": "ATLANTICO", "municipio": "BARRANQUILLA", "codigo_municipio": "08001"},
            {"departamento": "SANTANDER", "municipio": "BUCARAMANGA", "codigo_municipio": "68001"},
        ],
    }


@router.get("/{id_usuario}", response_model=UsuarioOut)
def consultar_usuario(id_usuario: uuid.UUID, db: Session = Depends(get_db)):
    """Endpoint consumido de forma SINCRONA por account-service antes de abrir una cuenta."""
    return get_usuario_or_404(db, id_usuario)


