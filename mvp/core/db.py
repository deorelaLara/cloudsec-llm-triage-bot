"""Base SQLite sintetica del MVP.

Cuatro tablas:

  inventario_recurso  que sabemos de cada recurso (T2)
  finding_historico   ocurrencias previas de cada finding_type por recurso (T3)
  kev_epss            catalogo local que sustituye la salida a CISA y a FIRST (T4)
  decision_triage     unico punto de escritura del MVP (T6)

Los datos salen de los samples de `data/samples/`, para que inventario, historial y
catalogo sean coherentes con lo que el evaluador ve en pantalla.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_MVP_ROOT = Path(__file__).resolve().parents[1]
if str(_MVP_ROOT) not in sys.path:
    sys.path.insert(0, str(_MVP_ROOT))

from config import DB_PATH  # noqa: E402

ESQUEMA = """
CREATE TABLE IF NOT EXISTS inventario_recurso (
    resource_id       TEXT PRIMARY KEY,
    environment       TEXT NOT NULL,
    tags              TEXT NOT NULL DEFAULT '{}',
    expuesto_internet INTEGER NOT NULL DEFAULT 0,
    criticidad        TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS finding_historico (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_type TEXT NOT NULL,
    resource_id  TEXT NOT NULL,
    puerto       INTEGER,
    origen       TEXT,
    fecha        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_historico_tipo_recurso
    ON finding_historico (finding_type, resource_id);

CREATE TABLE IF NOT EXISTS kev_epss (
    cve_id      TEXT PRIMARY KEY,
    in_cisa_kev INTEGER NOT NULL DEFAULT 0,
    epss_score  REAL,
    snapshot    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decision_triage (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id       TEXT NOT NULL,
    registrado_en    TEXT NOT NULL,
    decision         TEXT NOT NULL,
    final_risk_level TEXT NOT NULL,
    reason_codes     TEXT NOT NULL,
    caso_completo    TEXT NOT NULL
);
"""

# Cuatro de los cinco samples originales. `i-0sandboxhoneypot999` se deja fuera a
# proposito: es el que dispara `resource_context_not_found`.
INVENTARIO: list[tuple[str, str, dict[str, str], int, str]] = [
    (
        "AKIAEXAMPLE1234",
        "production",
        {"Owner": "platform-team", "Servicio": "billing-api"},
        1,
        "critical",
    ),
    (
        "i-0devportprobe12345",
        "dev",
        {"Environment": "dev", "Owner": "app-team", "Servicio": "ephemeral-testing"},
        1,
        "low",
    ),
    (
        "i-0criticalprod123456",
        "production",
        {"Environment": "production", "Owner": "platform-team", "Servicio": "core-api"},
        1,
        "critical",
    ),
    (
        "sha256:devimage1234567890",
        "dev",
        {"Environment": "dev", "Owner": "app-team", "Servicio": "build-pipeline"},
        0,
        "medium",
    ),
]

# Sondeo recurrente sobre el host de desarrollo: siempre el mismo puerto y el mismo
# origen. Las fechas son relativas al dia de ejecucion para que caigan dentro de la
# ventana de T3.
HISTORICO_DIAS_ATRAS = [2, 5, 9, 14, 20]
HISTORICO_FINDING_TYPE = "Recon:EC2/PortProbeUnprotectedPort"
HISTORICO_RECURSO = "i-0devportprobe12345"
HISTORICO_PUERTO = 22
HISTORICO_ORIGEN = "203.0.113.45"

# El CVE del sample de Inspector, marcado como presente en KEV, mas uno fuera de KEV.
KEV_EPSS: list[tuple[str, int, float]] = [
    ("CVE-2026-12345", 1, 0.94312),
    ("CVE-2026-54321", 0, 0.00131),
]


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def conectar_escritura(db_path: Path | None = None) -> sqlite3.Connection:
    """Conexion de escritura. Solo la usan la creacion del esquema y T6."""
    ruta = Path(db_path or DB_PATH)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(str(ruta))
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON")
    return conexion


def conectar_lectura(db_path: Path | None = None) -> sqlite3.Connection:
    """Conexion en modo solo lectura: un INSERT por esta via falla.

    T2, T3 y T4 usan exclusivamente esta funcion.
    """
    ruta = Path(db_path or DB_PATH)
    if not ruta.exists():
        raise FileNotFoundError(
            f"La base {ruta} no existe. Ejecuta `python -m core.db` o llama a "
            "`asegurar_base()` para crearla."
        )
    conexion = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True)
    conexion.row_factory = sqlite3.Row
    return conexion


def crear_base(db_path: Path | None = None) -> Path:
    """Crea el esquema y siembra los datos sinteticos. Idempotente."""
    ruta = Path(db_path or DB_PATH)
    with conectar_escritura(ruta) as conexion:
        conexion.executescript(ESQUEMA)
        _sembrar_inventario(conexion)
        _sembrar_historico(conexion)
        _sembrar_kev_epss(conexion)
        conexion.commit()
    return ruta


def asegurar_base(db_path: Path | None = None) -> Path:
    """Crea la base si no existe. Es lo que llama el orquestador al arrancar."""
    ruta = Path(db_path or DB_PATH)
    if not ruta.exists():
        return crear_base(ruta)
    return ruta


def _sembrar_inventario(conexion: sqlite3.Connection) -> None:
    conexion.executemany(
        """
        INSERT OR REPLACE INTO inventario_recurso
            (resource_id, environment, tags, expuesto_internet, criticidad)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (rid, env, json.dumps(tags, sort_keys=True), expuesto, crit)
            for rid, env, tags, expuesto, crit in INVENTARIO
        ],
    )


def _sembrar_historico(conexion: sqlite3.Connection) -> None:
    # Idempotente: solo siembra si esa combinacion no tiene ya filas.
    (ya_hay,) = conexion.execute(
        "SELECT COUNT(*) FROM finding_historico WHERE finding_type = ? AND resource_id = ?",
        (HISTORICO_FINDING_TYPE, HISTORICO_RECURSO),
    ).fetchone()
    if ya_hay:
        return

    base = _ahora()
    conexion.executemany(
        """
        INSERT INTO finding_historico (finding_type, resource_id, puerto, origen, fecha)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                HISTORICO_FINDING_TYPE,
                HISTORICO_RECURSO,
                HISTORICO_PUERTO,
                HISTORICO_ORIGEN,
                (base - timedelta(days=dias)).isoformat(),
            )
            for dias in HISTORICO_DIAS_ATRAS
        ],
    )


def _sembrar_kev_epss(conexion: sqlite3.Connection) -> None:
    snapshot = _ahora().date().isoformat()
    conexion.executemany(
        """
        INSERT OR REPLACE INTO kev_epss (cve_id, in_cisa_kev, epss_score, snapshot)
        VALUES (?, ?, ?, ?)
        """,
        [(cve, kev, epss, snapshot) for cve, kev, epss in KEV_EPSS],
    )


def registrar_decision(
    finding_id: str,
    decision: str,
    final_risk_level: str,
    reason_codes: list[str],
    caso_completo: dict,
    db_path: Path | None = None,
) -> int:
    """T6. Unico punto de escritura del MVP. Devuelve el id de la fila."""
    with conectar_escritura(db_path) as conexion:
        cursor = conexion.execute(
            """
            INSERT INTO decision_triage
                (finding_id, registrado_en, decision, final_risk_level,
                 reason_codes, caso_completo)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                _ahora().isoformat(),
                decision,
                final_risk_level,
                json.dumps(reason_codes),
                json.dumps(caso_completo, default=str),
            ),
        )
        conexion.commit()
        return int(cursor.lastrowid)


if __name__ == "__main__":
    destino = crear_base()
    with conectar_lectura(destino) as c:
        conteos = {
            tabla: c.execute(f"SELECT COUNT(*) FROM {tabla}").fetchone()[0]
            for tabla in (
                "inventario_recurso",
                "finding_historico",
                "kev_epss",
                "decision_triage",
            )
        }
    print(f"Base creada en {destino}")
    for tabla, n in conteos.items():
        print(f"  {tabla}: {n} filas")
