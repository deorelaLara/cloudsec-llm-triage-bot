"""Sirve el servidor MCP por HTTP.

    uvicorn api.mcp:app --reload --port 8001
"""

from __future__ import annotations

import sys
from pathlib import Path

_MVP_ROOT = Path(__file__).resolve().parents[1]
for _ruta in (str(_MVP_ROOT), str(_MVP_ROOT / "core")):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

from mcp_server import mcp  # noqa: E402

app = mcp.http_app(path="/", stateless_http=True)
