"""Fabrica unica de proveedor de modelo.

Las dos capas que llaman al modelo (el analizador de triage y el agente
conversacional) se sirven de aqui, asi que **siempre** usan el mismo proveedor.

Ese acoplamiento es deliberado. El agente recibe el resultado de la tool, y ese
resultado contiene el finding completo. Si el analizador fuera por Bedrock pero el
agente por OpenAI, el finding saldria igual de AWS hacia un tercero y el argumento
de privacidad se caeria. Por eso hay una sola variable, `LLM_PROVIDER`, y una sola
fabrica.

`agent.py` consume esta fabrica y nunca instancia un cliente de modelo directamente.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_MVP_ROOT = Path(__file__).resolve().parent
for _ruta in (str(_MVP_ROOT), str(_MVP_ROOT / "core")):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

import config  # noqa: E402


class ProveedorNoSoportado(ValueError):
    """LLM_PROVIDER no es ni openai ni bedrock."""


def proveedor() -> str:
    if not config.proveedor_valido():
        raise ProveedorNoSoportado(
            f"LLM_PROVIDER={config.LLM_PROVIDER!r} no soportado. "
            "Valores validos: 'openai' o 'bedrock'."
        )
    return config.LLM_PROVIDER


def crear_cliente_chat(temperature: float = 0.0):
    """Cliente de chat para el agente conversacional.

    Devuelve `ChatOpenAI` o `ChatBedrockConverse` segun `LLM_PROVIDER`. Los imports
    son perezosos para no arrastrar los dos SDK cuando solo se usa uno.
    """
    nombre = proveedor()

    if nombre == "openai":
        from langchain_openai import ChatOpenAI

        if not config.OPENAI_API_KEY:
            raise RuntimeError(
                "LLM_PROVIDER=openai pero OPENAI_API_KEY esta vacia. "
                "Rellenala en mvp/.env."
            )
        return ChatOpenAI(
            model=config.OPENAI_MODEL,
            api_key=config.OPENAI_API_KEY,
            base_url=config.OPENAI_BASE_URL,
            temperature=temperature,
        )

    from langchain_aws import ChatBedrockConverse

    # Verificado contra langchain-aws 1.7.6: el campo es `model_id`, no `model`.
    # `credentials_profile_name` solo se pasa si hay AWS_PROFILE; si no, boto3
    # resuelve las credenciales por la cadena habitual.
    argumentos: dict[str, Any] = {
        "model_id": config.BEDROCK_MODEL_ID,
        "region_name": config.AWS_REGION,
        "temperature": temperature,
    }
    if config.AWS_PROFILE:
        argumentos["credentials_profile_name"] = config.AWS_PROFILE
    return ChatBedrockConverse(**argumentos)


def parametros_analizador() -> dict[str, Any]:
    """Argumentos para construir `LLMAnalyzer` con el mismo proveedor.

    `LLMAnalyzer` viene copiado del sistema serverless y ya soporta los dos; aqui
    solo le damos los parametros correctos.
    """
    nombre = proveedor()

    comunes: dict[str, Any] = {
        "provider": nombre,
        "region_name": config.AWS_REGION,
        "self_consistency_samples": config.LLM_SELF_CONSISTENCY_SAMPLES,
    }

    if nombre == "openai":
        return {
            **comunes,
            "openai_model": config.OPENAI_MODEL,
            "openai_base_url": config.OPENAI_BASE_URL,
        }

    return {**comunes, "bedrock_model_id": config.BEDROCK_MODEL_ID}


def descripcion_proveedor() -> str:
    """Una linea legible para el frontend y los logs. Nunca incluye credenciales."""
    if proveedor() == "openai":
        return f"OpenAI · {config.OPENAI_MODEL}"
    return f"Amazon Bedrock · {config.BEDROCK_MODEL_ID} · {config.AWS_REGION}"
