"""Configuracion del MVP, leida de entorno con python-dotenv.

Un unico sitio donde se resuelven rutas y variables. Ni el agente, ni la capa MCP,
ni el orquestador leen `os.getenv` por su cuenta.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

MVP_ROOT = Path(__file__).resolve().parent
CORE_DIR = MVP_ROOT / "core"
DATA_DIR = MVP_ROOT / "data"
SAMPLES_DIR = DATA_DIR / "samples"
STATIC_DIR = MVP_ROOT / "static"
INDEX_HTML = MVP_ROOT / "index.html"
DB_PATH = DATA_DIR / "mvp_triage.db"

# override=False: una variable ya exportada en el shell gana sobre el fichero,
# que es lo que espera quien depura desde la terminal.
load_dotenv(MVP_ROOT / ".env", override=False)


def _texto(nombre: str, defecto: str = "") -> str:
    return (os.getenv(nombre) or defecto).strip()


def _entero(nombre: str, defecto: int) -> int:
    try:
        return int(_texto(nombre) or defecto)
    except ValueError:
        return defecto


LLM_PROVIDER = _texto("LLM_PROVIDER", "openai").lower()

OPENAI_API_KEY = _texto("OPENAI_API_KEY")
OPENAI_MODEL = _texto("OPENAI_MODEL", "gpt-4.1-mini")
OPENAI_BASE_URL = _texto("OPENAI_BASE_URL", "https://api.openai.com/v1")

AWS_REGION = _texto("AWS_REGION", "ap-southeast-2")
AWS_PROFILE = _texto("AWS_PROFILE")
BEDROCK_MODEL_ID = _texto("BEDROCK_MODEL_ID", "au.anthropic.claude-sonnet-4-6")

LLM_SELF_CONSISTENCY_SAMPLES = _entero("LLM_SELF_CONSISTENCY_SAMPLES", 1)

SUPPRESSION_ALLOWLIST: set[str] = {
    entrada.strip()
    for entrada in _texto(
        "SUPPRESSION_ALLOWLIST",
        "Recon:EC2/PortProbeUnprotectedPort,"
        "Software and Configuration Checks/Package Vulnerability",
    ).split(",")
    if entrada.strip()
}

MCP_URL = _texto("MCP_URL", "http://127.0.0.1:8001/")
LOG_LEVEL = _texto("LOG_LEVEL", "INFO")

# Ventana por defecto de T3, en dias.
VENTANA_HISTORIAL_DIAS = _entero("VENTANA_HISTORIAL_DIAS", 30)

# Ocurrencias previas a partir de las cuales consideramos que hay un patron
# recurrente. Por debajo de este umbral no tiene sentido hablar de "variacion":
# no hay patron del que variar.
MINIMO_OCURRENCIAS_PATRON = _entero("MINIMO_OCURRENCIAS_PATRON", 3)

ADVERTENCIA_DATOS = (
    "Datos sinteticos de demostracion. Los findings estan anonimizados y el "
    "inventario, el historial y el catalogo KEV/EPSS son locales."
)


def proveedor_valido() -> bool:
    return LLM_PROVIDER in {"openai", "bedrock"}


def resumen_configuracion() -> dict[str, object]:
    """Resumen apto para logs: nunca incluye la clave de API."""
    return {
        "llm_provider": LLM_PROVIDER,
        "modelo": OPENAI_MODEL if LLM_PROVIDER == "openai" else BEDROCK_MODEL_ID,
        "openai_api_key_presente": bool(OPENAI_API_KEY),
        "aws_region": AWS_REGION if LLM_PROVIDER == "bedrock" else None,
        "self_consistency_samples": LLM_SELF_CONSISTENCY_SAMPLES,
        "mcp_url": MCP_URL,
        "db_path": str(DB_PATH),
    }
