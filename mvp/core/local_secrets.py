"""Secretos en local, reutilizando el modelo del sistema serverless.

En Lambda el bundle venia de Secrets Manager. Aqui se construye desde variables de
entorno, con el mismo `IntegrationSecretBundle` en lugar de duplicar el contrato.

Slack y Confluence quedan siempre vacios: el MVP no los usa.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_DIR = Path(__file__).resolve().parent
_MVP_ROOT = _CORE_DIR.parent
for _ruta in (str(_MVP_ROOT), str(_CORE_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

from config import LLM_PROVIDER, OPENAI_API_KEY  # noqa: E402
from models import IntegrationSecretBundle  # noqa: E402


def cargar_secretos_locales() -> IntegrationSecretBundle:
    """Con OpenAI lee OPENAI_API_KEY. Con Bedrock devuelve el bundle vacio.

    En Bedrock la autenticacion es por IAM (perfil o rol), asi que no hay ninguna
    clave que transportar: boto3 la resuelve por su cuenta.
    """
    if LLM_PROVIDER == "openai":
        return IntegrationSecretBundle(openai_api_key=OPENAI_API_KEY)

    return IntegrationSecretBundle(openai_api_key="")
