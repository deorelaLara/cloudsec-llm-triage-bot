"""Pone `mvp/core` y `mvp/` en `sys.path` antes de recoger los tests.

Los tests copiados de `tests/` hacen `sys.path.insert(0, parents[1] / "src")`.
En este arbol `mvp/src` es un symlink a `mvp/core`, asi que resuelven solos; este
conftest cubre ademas los tests nuevos y las ejecuciones desde otro directorio.
"""

from __future__ import annotations

import sys
from pathlib import Path

MVP_ROOT = Path(__file__).resolve().parent

for _ruta in (MVP_ROOT, MVP_ROOT / "core"):
    if str(_ruta) not in sys.path:
        sys.path.insert(0, str(_ruta))
