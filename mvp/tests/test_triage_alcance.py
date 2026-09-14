"""Tests del orquestador con eventos fuera de alcance y de la tool con entradas invalidas.

Cubren el criterio de aceptacion c (fuera de alcance: cero llamadas al modelo y
ninguna fila en `decision_triage`) y el d (tool con `finding_id` vacio o inexistente).

El caso c salio a la luz en la verificacion de extremo a extremo: un AWS Health
Event trae `detail.service` como cadena y `inspect_event_shape`, copiado del sistema
serverless, hace `.get` sobre ella. La correccion vive en `triage._metadata_segura`;
el modulo copiado no se toca.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

MVP_ROOT = Path(__file__).resolve().parents[1]
for _ruta in (MVP_ROOT, MVP_ROOT / "core"):
    if str(_ruta) not in sys.path:
        sys.path.insert(0, str(_ruta))

import config  # noqa: E402
import db  # noqa: E402
import triage  # noqa: E402
from finding_normalizer import inspect_event_shape  # noqa: E402

SAMPLES = MVP_ROOT / "data" / "samples"


class _ModeloProhibido:
    """Si el orquestador intenta construir el analizador, el test falla."""

    def __init__(self, *args, **kwargs):
        raise AssertionError("Se intento llamar al modelo para un evento fuera de alcance.")


@pytest.fixture
def base_temporal(tmp_path, monkeypatch):
    """Base SQLite propia del test, para no tocar `data/mvp_triage.db`."""
    ruta = tmp_path / "triage_test.db"
    monkeypatch.setattr(config, "DB_PATH", ruta)
    monkeypatch.setattr(db, "DB_PATH", ruta)
    db.crear_base(ruta)
    return ruta


def _filas_decision(ruta: Path) -> int:
    with sqlite3.connect(str(ruta)) as conexion:
        return conexion.execute("SELECT COUNT(*) FROM decision_triage").fetchone()[0]


def _sample(nombre: str) -> dict:
    return json.loads((SAMPLES / nombre).read_text())


# --- Criterio c: fuera de alcance ------------------------------------------


def test_health_event_queda_fuera_de_alcance_sin_modelo_ni_registro(base_temporal, monkeypatch):
    monkeypatch.setattr(triage, "LLMAnalyzer", _ModeloProhibido)

    caso = triage.triagear(_sample("unsupported_health_event.json"), db_path=base_temporal)

    assert caso.resultado is None
    assert caso.fuera_de_alcance is not None
    assert caso.fuera_de_alcance.decision == "out_of_scope"
    assert caso.fuera_de_alcance.fuente_evento == "aws.health"
    assert "AWS Health Event" in caso.fuera_de_alcance.motivo
    assert caso.llamadas_al_modelo == 0
    assert caso.registro_id is None
    assert _filas_decision(base_temporal) == 0


def test_detail_que_no_es_diccionario_tambien_queda_fuera_de_alcance(base_temporal, monkeypatch):
    monkeypatch.setattr(triage, "LLMAnalyzer", _ModeloProhibido)
    evento = {
        "id": "evt-raro-001",
        "source": "aws.config",
        "detail-type": "Config Rules Compliance Change",
        "detail": "texto plano",
    }

    caso = triage.triagear(evento, db_path=base_temporal)

    assert caso.fuera_de_alcance is not None
    assert caso.fuera_de_alcance.fuente_evento == "aws.config"
    assert caso.llamadas_al_modelo == 0
    assert _filas_decision(base_temporal) == 0


def test_metadata_segura_degrada_cuando_inspect_event_shape_falla():
    evento = _sample("unsupported_health_event.json")
    with pytest.raises(AttributeError):
        inspect_event_shape(evento)  # el modulo copiado falla con este evento

    metadata = triage._metadata_segura(evento)

    assert metadata.source == "aws.health"
    assert metadata.detail_type == "AWS Health Event"
    assert metadata.event_id == "evt-unsupported-001"
    assert metadata.event_shape == "unknown"
    assert metadata.has_eventbridge_envelope is True


def test_metadata_segura_delega_en_el_original_cuando_puede():
    evento = _sample("guardduty_high_credential_compromise.json")
    assert triage._metadata_segura(evento) == inspect_event_shape(evento)


def test_metadata_segura_con_algo_que_no_es_diccionario():
    metadata = triage._metadata_segura("no soy un evento")
    assert metadata.source == "unknown"
    assert metadata.has_eventbridge_envelope is False


# --- Criterio d: tool con entradas invalidas -------------------------------


def _tool():
    from mcp_server import triagear_finding

    # `@mcp.tool` envuelve la funcion en un FunctionTool; la original esta en `.fn`.
    return getattr(triagear_finding, "fn", triagear_finding)


def test_tool_con_finding_id_vacio_devuelve_error_controlado(base_temporal):
    resultado = _tool()("   ")

    assert resultado["ok"] is False
    assert "finding_id" in resultado["error"]
    assert _filas_decision(base_temporal) == 0


def test_tool_con_finding_id_inexistente_devuelve_error_controlado(base_temporal):
    resultado = _tool()("finding-que-no-existe-xyz")

    assert resultado["ok"] is False
    assert "finding-que-no-existe-xyz" in resultado["error"]
    assert _filas_decision(base_temporal) == 0


def test_tool_con_evento_fuera_de_alcance_devuelve_out_of_scope(base_temporal, monkeypatch):
    monkeypatch.setattr(triage, "LLMAnalyzer", _ModeloProhibido)

    resultado = _tool()("evt-unsupported-001")

    assert resultado["ok"] is True
    assert resultado["decision"] == "out_of_scope"
    assert resultado["policy_decision"]["reason_codes"] == ["event_out_of_scope"]
    assert resultado["llamadas_al_modelo"] == 0
    assert resultado["registro_id"] is None
    assert _filas_decision(base_temporal) == 0
