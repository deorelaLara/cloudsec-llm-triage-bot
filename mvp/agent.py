"""Agente conversacional del MVP.

Construido con `create_agent` de LangChain sobre el cliente que devuelve
`llm_factory`. Descubre las tools por HTTP contra `MCP_URL` con
`MultiServerMCPClient`: no importa la funcion de la tool directamente, para que la
frontera MCP sea real y no un atajo.
"""

from __future__ import annotations

import sys
from pathlib import Path

_MVP_ROOT = Path(__file__).resolve().parent
for _ruta in (str(_MVP_ROOT), str(_MVP_ROOT / "core")):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

import config  # noqa: E402
import llm_factory  # noqa: E402
from prompts import SYSTEM_PROMPT  # noqa: E402


class MCPNoDisponible(RuntimeError):
    """No se pudo hablar con el servidor MCP."""


class AgenteNoDisponible(RuntimeError):
    """No se pudo construir el agente (proveedor mal configurado, por ejemplo)."""


def _cliente_mcp():
    from langchain_mcp_adapters.client import MultiServerMCPClient

    return MultiServerMCPClient(
        {
            "cloudsec_triage": {
                "url": config.MCP_URL,
                "transport": "streamable_http",
            }
        }
    )


async def _construir_agente():
    """Descubre las tools por HTTP y arma el agente.

    Se construye en cada peticion a proposito: asi un servidor MCP que se cae y
    vuelve no obliga a reiniciar el backend, y el fallo se detecta en el momento.
    """
    from langchain.agents import create_agent

    try:
        herramientas = await _cliente_mcp().get_tools()
    except Exception as exc:  # noqa: BLE001 - lo traducimos a un error del dominio
        raise MCPNoDisponible(
            f"No se pudo contactar con el servidor MCP en {config.MCP_URL}"
        ) from exc

    if not herramientas:
        raise MCPNoDisponible(
            f"El servidor MCP en {config.MCP_URL} no expone ninguna herramienta."
        )

    try:
        modelo = llm_factory.crear_cliente_chat()
    except Exception as exc:  # noqa: BLE001
        raise AgenteNoDisponible(str(exc)) from exc

    return create_agent(model=modelo, tools=herramientas, system_prompt=SYSTEM_PROMPT)


async def responder(pregunta: str) -> str:
    """Responde a una pregunta del usuario usando el agente.

    Lanza `MCPNoDisponible` o `AgenteNoDisponible`; la capa HTTP las traduce a JSON.
    """
    texto = (pregunta or "").strip()
    if not texto:
        return "No he recibido ninguna pregunta. Indicame el identificador del finding que quieres revisar."

    agente = await _construir_agente()
    estado = await agente.ainvoke({"messages": [{"role": "user", "content": texto}]})

    mensajes = estado.get("messages", []) if isinstance(estado, dict) else []
    for mensaje in reversed(mensajes):
        contenido = getattr(mensaje, "content", None)
        if not contenido:
            continue
        if isinstance(contenido, str):
            return contenido
        # Algunos proveedores devuelven bloques; Bedrock entre ellos.
        partes = [
            bloque.get("text", "")
            for bloque in contenido
            if isinstance(bloque, dict) and bloque.get("type") == "text"
        ]
        unido = "\n".join(p for p in partes if p).strip()
        if unido:
            return unido

    return "El agente no devolvio ninguna respuesta."
