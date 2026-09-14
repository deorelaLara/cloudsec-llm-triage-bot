"""Backend HTTP del MVP.

    uvicorn api.chat:app --reload --port 8000

Sirve la pagina y expone `POST /api/chat`. No contiene logica del agente ni SQL:
solo traduce entre HTTP y `agent.responder()`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

_MVP_ROOT = Path(__file__).resolve().parents[1]
for _ruta in (str(_MVP_ROOT), str(_MVP_ROOT / "core")):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

import config  # noqa: E402
import llm_factory  # noqa: E402
from agent import AgenteNoDisponible, MCPNoDisponible, responder  # noqa: E402
from samples import identificadores_disponibles  # noqa: E402

app = FastAPI(
    title="MVP CloudSec Triage",
    description="Triage asistido por LLM de findings de GuardDuty e Inspector. Datos sinteticos.",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


class PeticionChat(BaseModel):
    pregunta: str = Field(default="", max_length=4000)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(config.INDEX_HTML), media_type="text/html")


def _descripcion_proveedor() -> str | None:
    """Una linea legible del proveedor configurado, sin credenciales. None si es invalido."""
    try:
        return llm_factory.descripcion_proveedor()
    except Exception:  # noqa: BLE001 - la pagina no debe caerse por un .env mal puesto
        return None


@app.get("/api/findings")
def findings() -> JSONResponse:
    """Lo que la pagina necesita para pintar las tarjetas y la cabecera."""
    return JSONResponse(
        {
            "findings": identificadores_disponibles(),
            "proveedor": _descripcion_proveedor(),
            "advertencia": config.ADVERTENCIA_DATOS,
        }
    )


@app.post("/api/chat")
async def chat(peticion: PeticionChat) -> JSONResponse:
    pregunta = (peticion.pregunta or "").strip()
    if not pregunta:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "La pregunta esta vacia."},
        )

    try:
        respuesta = await responder(pregunta)
    except MCPNoDisponible:
        # Mensaje accionable, sin traza cruda y sin filtrar configuracion sensible.
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": (
                    "El servidor MCP no responde. Levantalo con "
                    "`uvicorn api.mcp:app --port 8001` desde la carpeta mvp/ y vuelve "
                    "a intentarlo. No se ejecuto ningun triage."
                ),
            },
        )
    except AgenteNoDisponible:
        return JSONResponse(
            status_code=503,
            content={
                "ok": False,
                "error": (
                    "El proveedor de modelo no esta configurado correctamente. "
                    "Revisa LLM_PROVIDER y sus credenciales en mvp/.env. "
                    "No se ejecuto ningun triage."
                ),
            },
        )
    except Exception:  # noqa: BLE001 - nunca devolvemos una excepcion sin manejar
        return JSONResponse(
            status_code=500,
            content={
                "ok": False,
                "error": (
                    "Error interno al procesar la consulta. Revisa los logs del "
                    "servidor para el detalle."
                ),
            },
        )

    return JSONResponse({"ok": True, "respuesta": respuesta})
