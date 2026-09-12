"""T4 local: misma firma que `enrichment.enrich_finding`, sin salir a internet.

El modulo original consulta CISA y FIRST por red. Aqui leemos la tabla `kev_epss`
de SQLite, para que el MVP funcione sin conectividad y de siempre el mismo
resultado en una demo. `enrichment.py` queda intacto.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

_CORE_DIR = Path(__file__).resolve().parent
_MVP_ROOT = _CORE_DIR.parent
for _ruta in (str(_MVP_ROOT), str(_CORE_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

from db import conectar_lectura  # noqa: E402
from enrichment import extract_cve_id  # noqa: E402
from logger import log_event  # noqa: E402
from models import FindingEnrichment, NormalizedFinding  # noqa: E402


def enrich_finding(
    finding: NormalizedFinding,
    logger,
    timeout: float = 5.0,
    db_path: Path | None = None,
) -> FindingEnrichment:
    """Misma firma que el original. `timeout` se acepta y se ignora: no hay red.

    Fail-open igual que el original: si la base no esta disponible degradamos a
    "unavailable" en vez de bloquear el triage.
    """
    del timeout  # sin red, no hay nada que temporizar

    if finding.source != "inspector":
        return FindingEnrichment(source="none")

    cve = extract_cve_id(finding)
    if not cve:
        return FindingEnrichment(source="none")

    try:
        with conectar_lectura(db_path) as conexion:
            fila = conexion.execute(
                "SELECT in_cisa_kev, epss_score FROM kev_epss WHERE cve_id = ?",
                (cve.upper(),),
            ).fetchone()
    except (FileNotFoundError, sqlite3.Error) as exc:
        log_event(
            logger,
            "warning",
            "Catalogo local KEV/EPSS no disponible; continuamos sin enriquecer.",
            cve=cve,
            error=str(exc),
        )
        return FindingEnrichment(cve_id=cve, source="unavailable")

    if fila is None:
        # El CVE no esta en el catalogo local. No es un fallo: es un CVE que no
        # figura en KEV y del que no tenemos EPSS.
        return FindingEnrichment(cve_id=cve, in_cisa_kev=False, source="kev_epss")

    return FindingEnrichment(
        cve_id=cve,
        in_cisa_kev=bool(fila["in_cisa_kev"]),
        epss_score=fila["epss_score"],
        source="kev_epss",
    )
