"""Tests de la capa HTTP: lo que la pagina consume y como se traducen los errores.

Cubren el criterio de aceptacion e (MCP caido -> JSON legible, sin traza ni
secretos) sin levantar ningun servidor, y el contrato de `/api/findings` que las
tarjetas del frontend necesitan.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

MVP_ROOT = Path(__file__).resolve().parents[1]
for _ruta in (MVP_ROOT, MVP_ROOT / "core"):
    if str(_ruta) not in sys.path:
        sys.path.insert(0, str(_ruta))

from fastapi.testclient import TestClient  # noqa: E402

import api.chat as chat_api  # noqa: E402
from agent import AgenteNoDisponible, MCPNoDisponible  # noqa: E402

SEVERIDADES = {"low", "medium", "high", "critical"}


@pytest.fixture
def cliente() -> TestClient:
    return TestClient(chat_api.app)


def test_pagina_y_estaticos_responden(cliente):
    inicio = cliente.get("/")
    assert inicio.status_code == 200
    assert "text/html" in inicio.headers["content-type"]
    assert cliente.get("/static/app.js").status_code == 200
    assert cliente.get("/static/style.css").status_code == 200


def test_lista_de_findings_trae_lo_que_la_pagina_necesita(cliente):
    datos = cliente.get("/api/findings").json()

    assert "proveedor" in datos
    assert datos["advertencia"]

    findings = datos["findings"]
    assert len(findings) == len(list((MVP_ROOT / "data" / "samples").glob("*.json")))

    claves = {"finding_id", "fichero", "titulo", "fuente_aws", "en_alcance", "severidad", "entorno", "recurso", "tipo"}
    for finding in findings:
        assert claves <= set(finding), finding["fichero"]
        assert finding["finding_id"]

    en_alcance = [f for f in findings if f["en_alcance"]]
    fuera = [f for f in findings if not f["en_alcance"]]
    assert len(fuera) == 1
    assert fuera[0]["severidad"] is None and fuera[0]["recurso"] is None
    assert all(f["severidad"] in SEVERIDADES for f in en_alcance)
    assert all(f["recurso"] for f in en_alcance)


def test_pregunta_vacia_es_400(cliente):
    respuesta = cliente.post("/api/chat", json={"pregunta": "   "})
    assert respuesta.status_code == 400
    assert respuesta.json() == {"ok": False, "error": "La pregunta esta vacia."}


def test_mcp_caido_devuelve_503_legible(cliente, monkeypatch):
    async def falla(pregunta: str) -> str:
        raise MCPNoDisponible("No se pudo contactar con el servidor MCP en http://127.0.0.1:8001/")

    monkeypatch.setattr(chat_api, "responder", falla)
    respuesta = cliente.post("/api/chat", json={"pregunta": "Haz el triage del finding x"})

    assert respuesta.status_code == 503
    cuerpo = respuesta.json()
    assert cuerpo["ok"] is False
    assert "MCP" in cuerpo["error"] and "uvicorn api.mcp:app" in cuerpo["error"]
    assert "Traceback" not in respuesta.text


def test_proveedor_mal_configurado_devuelve_503(cliente, monkeypatch):
    async def falla(pregunta: str) -> str:
        raise AgenteNoDisponible("LLM_PROVIDER='otro' no soportado.")

    monkeypatch.setattr(chat_api, "responder", falla)
    respuesta = cliente.post("/api/chat", json={"pregunta": "Haz el triage del finding x"})

    assert respuesta.status_code == 503
    assert "LLM_PROVIDER" in respuesta.json()["error"]


def test_error_inesperado_devuelve_500_sin_filtrar_el_detalle(cliente, monkeypatch):
    async def explota(pregunta: str) -> str:
        raise RuntimeError("detalle interno con sk-secreto-que-no-debe-salir")

    monkeypatch.setattr(chat_api, "responder", explota)
    respuesta = cliente.post("/api/chat", json={"pregunta": "Haz el triage del finding x"})

    assert respuesta.status_code == 500
    assert respuesta.json()["ok"] is False
    assert "sk-secreto" not in respuesta.text
