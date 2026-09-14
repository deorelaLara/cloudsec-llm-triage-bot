"""Acceso a los samples de demostracion de `data/samples/`.

Lo comparten la tool MCP y la API de chat. Vive aparte para que el backend de chat
no tenga que importar fastmcp solo para listar identificadores.
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

_CORE_DIR = Path(__file__).resolve().parent
_MVP_ROOT = _CORE_DIR.parent
for _ruta in (str(_MVP_ROOT), str(_CORE_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

import config  # noqa: E402
from finding_normalizer import normalize_finding_event  # noqa: E402

FUENTES_EN_ALCANCE = {"aws.guardduty", "aws.inspector2"}


def _leer(ruta: Path) -> dict[str, Any] | None:
    try:
        cargado = json.loads(ruta.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return cargado if isinstance(cargado, dict) else None


def _finding_id(evento: dict[str, Any]) -> str:
    detalle = evento.get("detail", {})
    detalle = detalle if isinstance(detalle, dict) else {}
    return str(detalle.get("id") or detalle.get("findingArn") or evento.get("id") or "")


@lru_cache(maxsize=1)
def indice_samples() -> dict[str, Path]:
    """Indexa los samples por identificador.

    Se aceptan tres formas del mismo identificador, porque el evaluador puede
    escribir cualquiera: el `finding_id` normalizado, el `id` del sobre de
    EventBridge y el nombre del fichero sin extension.
    """
    indice: dict[str, Path] = {}
    for ruta in sorted(config.SAMPLES_DIR.glob("*.json")):
        evento = _leer(ruta)
        if evento is None:
            continue
        detalle = evento.get("detail", {})
        detalle = detalle if isinstance(detalle, dict) else {}
        for clave in (
            ruta.stem,
            str(evento.get("id") or ""),
            str(detalle.get("id") or ""),
            str(detalle.get("findingArn") or ""),
        ):
            if clave:
                indice[clave] = ruta
    return indice


def _resumen_normalizado(evento: dict[str, Any]) -> dict[str, Any]:
    """Severidad, entorno, recurso y tipo tal como los ve el triage.

    Se calcula con el normalizador copiado para que la tarjeta de la pagina y la
    decision hablen del mismo finding. Si el evento no es normalizable (fuera de
    alcance), los cuatro campos quedan a None: la pagina lo pinta como tal.
    """
    try:
        finding = normalize_finding_event(evento)
    except (ValueError, AttributeError, TypeError, KeyError):
        return {"severidad": None, "entorno": None, "recurso": None, "tipo": None}
    return {
        "severidad": finding.severity,
        "entorno": finding.environment,
        "recurso": finding.resource_id,
        "tipo": finding.finding_type,
    }


def identificadores_disponibles() -> list[dict[str, Any]]:
    """Los identificadores que el frontend muestra como tarjetas clicables."""
    entradas: list[dict[str, Any]] = []
    for ruta in sorted(config.SAMPLES_DIR.glob("*.json")):
        evento = _leer(ruta)
        if evento is None:
            continue
        detalle = evento.get("detail", {})
        detalle = detalle if isinstance(detalle, dict) else {}
        fuente = str(evento.get("source") or "desconocida")
        entradas.append(
            {
                "finding_id": _finding_id(evento),
                "fichero": ruta.name,
                "titulo": str(detalle.get("title") or evento.get("detail-type") or ruta.stem),
                "fuente_aws": fuente,
                "en_alcance": fuente in FUENTES_EN_ALCANCE,
                **_resumen_normalizado(evento),
            }
        )
    return entradas


def cargar_evento(identificador: str) -> tuple[dict[str, Any] | None, Path | None]:
    """Devuelve (evento, ruta) o (None, None) si el identificador no existe."""
    ruta = indice_samples().get(identificador)
    if ruta is None:
        return None, None
    return _leer(ruta), ruta
