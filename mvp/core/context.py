"""T2 y T3: contexto de recurso e historial de patron.

Las dos capacidades que el sistema serverless promete en su ficha de caso de uso y
todavia no implementa. Ambas leen de SQLite en modo solo lectura y con consultas
parametrizadas. El modelo nunca ve SQL: recibe el resultado ya estructurado.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_CORE_DIR = Path(__file__).resolve().parent
_MVP_ROOT = _CORE_DIR.parent
for _ruta in (str(_MVP_ROOT), str(_CORE_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

from config import MINIMO_OCURRENCIAS_PATRON, VENTANA_HISTORIAL_DIAS  # noqa: E402
from db import conectar_lectura  # noqa: E402
from models import PatternHistory, ResourceContext  # noqa: E402


def consultar_contexto_recurso(
    resource_id: str,
    db_path: Path | None = None,
) -> ResourceContext:
    """T2. Si el recurso no esta inventariado, lo dice explicitamente.

    Devolver `encontrado = False` no es un fallo: es informacion. El motor de
    politica la usa para exigir revision manual, porque sin inventario no se puede
    valorar la explotabilidad de nada.
    """
    identificador = (resource_id or "").strip()
    if not identificador:
        return ResourceContext(resource_id="", encontrado=False)

    with conectar_lectura(db_path) as conexion:
        fila = conexion.execute(
            """
            SELECT resource_id, environment, tags, expuesto_internet, criticidad
            FROM inventario_recurso
            WHERE resource_id = ?
            """,
            (identificador,),
        ).fetchone()

    if fila is None:
        return ResourceContext(resource_id=identificador, encontrado=False)

    return ResourceContext(
        resource_id=fila["resource_id"],
        encontrado=True,
        environment=fila["environment"],
        tags=_tags(fila["tags"]),
        expuesto_internet=bool(fila["expuesto_internet"]),
        criticidad=fila["criticidad"],
    )


def consultar_historial_patron(
    finding_type: str,
    resource_id: str,
    ventana_dias: int | None = None,
    puerto: int | None = None,
    origen: str | None = None,
    db_path: Path | None = None,
) -> PatternHistory:
    """T3. Historial de un finding_type sobre un recurso dentro de una ventana.

    `variacion_detectada` es True cuando hay un patron recurrente y el puerto o el
    origen actuales no aparecen en ese historico. Exigimos que exista patron
    (`MINIMO_OCURRENCIAS_PATRON` ocurrencias) a proposito: sin ocurrencias previas
    no hay nada de lo que variar, y marcar variacion en la primera aparicion de un
    finding convertiria la regla en ruido.
    """
    ventana = int(ventana_dias if ventana_dias is not None else VENTANA_HISTORIAL_DIAS)
    corte = (datetime.now(timezone.utc) - timedelta(days=ventana)).isoformat()

    with conectar_lectura(db_path) as conexion:
        filas = conexion.execute(
            """
            SELECT puerto, origen, fecha
            FROM finding_historico
            WHERE finding_type = ?
              AND resource_id = ?
              AND fecha >= ?
            ORDER BY fecha DESC
            """,
            (finding_type, resource_id, corte),
        ).fetchall()

    ocurrencias = len(filas)
    puertos = sorted({int(f["puerto"]) for f in filas if f["puerto"] is not None})
    origenes = sorted({str(f["origen"]) for f in filas if f["origen"]})
    ultima_vez = str(filas[0]["fecha"]) if filas else None
    patron_recurrente = ocurrencias >= MINIMO_OCURRENCIAS_PATRON

    variaciones: list[str] = []
    if patron_recurrente:
        if puerto is not None and puerto not in puertos:
            variaciones.append(
                f"puerto {puerto} nunca visto antes (historico: "
                f"{', '.join(str(p) for p in puertos) or 'sin puertos registrados'})"
            )
        if origen and origen not in origenes:
            variaciones.append(
                f"origen {origen} nunca visto antes (historico: "
                f"{', '.join(origenes) or 'sin origenes registrados'})"
            )

    return PatternHistory(
        finding_type=finding_type,
        resource_id=resource_id,
        ventana_dias=ventana,
        ocurrencias=ocurrencias,
        puertos_observados=puertos,
        origenes_observados=origenes,
        ultima_vez=ultima_vez,
        patron_recurrente=patron_recurrente,
        variacion_detectada=bool(variaciones),
        variaciones=variaciones,
    )


def extraer_puerto_y_origen(raw_event: dict[str, Any]) -> tuple[int | None, str | None]:
    """Saca puerto y origen del sobre de EventBridge de un finding de GuardDuty.

    Solo los findings de sondeo de puerto los traen. Cuando no estan, T3 se ejecuta
    igual y simplemente no puede evaluar variacion.
    """
    detalle = raw_event.get("detail", raw_event)
    if not isinstance(detalle, dict):
        return None, None

    accion = detalle.get("service", {}).get("action", {})
    if not isinstance(accion, dict):
        return None, None

    detalles_sondeo = accion.get("portProbeAction", {}).get("portProbeDetails") or []
    if not detalles_sondeo:
        return None, None

    primero = detalles_sondeo[0]
    puerto = primero.get("localPortDetails", {}).get("port")
    origen = primero.get("remoteIpDetails", {}).get("ipAddressV4")

    try:
        puerto = int(puerto) if puerto is not None else None
    except (TypeError, ValueError):
        puerto = None

    return puerto, (str(origen) if origen else None)


def _tags(bruto: Any) -> dict[str, str]:
    if not bruto:
        return {}
    try:
        cargado = json.loads(bruto) if isinstance(bruto, str) else bruto
    except json.JSONDecodeError:
        return {}
    if not isinstance(cargado, dict):
        return {}
    return {str(k): str(v) for k, v in cargado.items()}


def base_disponible(db_path: Path | None = None) -> bool:
    """Comprueba que la base existe y se puede leer. La usa la capa MCP."""
    try:
        with conectar_lectura(db_path) as conexion:
            conexion.execute("SELECT 1 FROM inventario_recurso LIMIT 1").fetchone()
        return True
    except (FileNotFoundError, sqlite3.Error):
        return False
