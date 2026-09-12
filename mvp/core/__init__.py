"""Copia deliberada de la logica de dominio del sistema serverless de la raiz.

Los modulos copiados usan imports planos (`from models import ...`), igual que en
el repositorio de origen. Importar este paquete inserta `mvp/core` y `mvp/` en
`sys.path` para que esos imports resuelvan sin tocar los ficheros copiados.

El hash del commit del que se copio esta en `mvp/README.md`.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_DIR = Path(__file__).resolve().parent
_MVP_ROOT = _CORE_DIR.parent

for _ruta in (str(_MVP_ROOT), str(_CORE_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)
