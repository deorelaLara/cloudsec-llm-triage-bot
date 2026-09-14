"""Servidor MCP del MVP. Expone UNA sola tool.

Una sola capacidad, como exige la regla central de la guia: el agente puede pedir
el triage de un finding y nada mas. No hay tool para suprimir, ni para cerrar, ni
para tocar la infraestructura, porque esas acciones no deben estar al alcance de un
modelo.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_MVP_ROOT = Path(__file__).resolve().parent
for _ruta in (str(_MVP_ROOT), str(_MVP_ROOT / "core")):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

from fastmcp import FastMCP  # noqa: E402

import config  # noqa: E402
import llm_factory  # noqa: E402
from context import base_disponible  # noqa: E402
from db import asegurar_base  # noqa: E402
from samples import cargar_evento, identificadores_disponibles  # noqa: E402
from triage import triagear  # noqa: E402

mcp = FastMCP("cloudsec-triage-mvp")

FUENTE = "Samples sinteticos de GuardDuty e Inspector en mvp/data/samples/"


def _error(mensaje: str) -> dict[str, Any]:
    return {"ok": False, "error": mensaje, "advertencia": config.ADVERTENCIA_DATOS}


@mcp.tool
def triagear_finding(finding_id: str) -> dict:
    """Ejecuta el triage completo de un finding de GuardDuty o Inspector.

    Dado el identificador de un finding, normaliza el evento, consulta el contexto
    del recurso y el historial del patron, enriquece con KEV/EPSS, pide una
    clasificacion al modelo y aplica el motor de politica determinista. Devuelve la
    decision con su razon.

    Usala cuando pregunten por el triage, el riesgo, la decision o el motivo de un
    finding concreto.

    No suprime findings, no cierra casos y no toca la infraestructura: solo lee y
    devuelve una recomendacion. La decision final la toma el motor determinista, no
    el modelo.

    Args:
        finding_id: identificador del finding, tal como aparece en la lista de
            findings disponibles.

    Returns:
        Un diccionario con `ok`. Si es True, incluye `finding`, `enrichment`,
        `llm_analysis`, `policy_decision`, `resource_context`, `pattern_history`,
        `llamadas_al_modelo`, `registro_id`, `fuente` y `advertencia`. Si es False,
        incluye `error` con el motivo.
    """
    identificador = (finding_id or "").strip()
    if not identificador:
        return _error(
            "No se indico ningun finding_id. Pide al usuario el identificador del "
            "finding que quiere revisar."
        )

    try:
        asegurar_base()
    except Exception as exc:  # noqa: BLE001 - nunca propagamos hacia el agente
        return _error(f"La base de datos del MVP no esta disponible: {type(exc).__name__}.")

    if not base_disponible():
        return _error(
            "La base de datos del MVP no esta disponible o no se puede leer. "
            "No se ejecuto ningun triage."
        )

    evento, ruta = cargar_evento(identificador)
    if ruta is None:
        conocidos = [e["finding_id"] for e in identificadores_disponibles()]
        return _error(
            f"No existe ningun finding con identificador {identificador!r} entre los "
            f"samples de demostracion. Disponibles: {', '.join(conocidos)}."
        )
    if evento is None:
        return _error(f"No se pudo leer el sample {ruta.name}.")

    try:
        caso = triagear(evento)
    except Exception as exc:  # noqa: BLE001 - la tool nunca lanza sin controlar
        return _error(f"El triage fallo: {type(exc).__name__}: {exc}")

    if caso.fuera_de_alcance is not None:
        return {
            "ok": True,
            "decision": "out_of_scope",
            "policy_decision": {
                "decision": "out_of_scope",
                "final_risk_level": "unknown",
                "reason_codes": ["event_out_of_scope"],
                "recommended_action": caso.fuera_de_alcance.motivo,
                "candidate_for_suppression": False,
            },
            "finding": None,
            "enrichment": None,
            "llm_analysis": None,
            "resource_context": None,
            "pattern_history": None,
            "llamadas_al_modelo": 0,
            "registro_id": None,
            "fuente": FUENTE,
            "proveedor_modelo": llm_factory.descripcion_proveedor(),
            "advertencia": config.ADVERTENCIA_DATOS,
        }

    resultado = caso.resultado
    assert resultado is not None  # un caso en alcance siempre trae resultado

    return {
        "ok": True,
        "decision": resultado.policy_decision.decision,
        "finding": resultado.finding.model_dump(mode="json", exclude={"raw_event"}),
        "enrichment": resultado.enrichment.model_dump(mode="json") if resultado.enrichment else None,
        "llm_analysis": resultado.llm_analysis.model_dump(mode="json"),
        "policy_decision": resultado.policy_decision.model_dump(mode="json"),
        "resource_context": caso.resource_context.model_dump(mode="json") if caso.resource_context else None,
        "pattern_history": caso.pattern_history.model_dump(mode="json") if caso.pattern_history else None,
        "llamadas_al_modelo": caso.llamadas_al_modelo,
        "registro_id": caso.registro_id,
        "fuente": FUENTE,
        "proveedor_modelo": llm_factory.descripcion_proveedor(),
        "advertencia": config.ADVERTENCIA_DATOS,
    }
