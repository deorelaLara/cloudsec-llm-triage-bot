from __future__ import annotations

import json
import logging
import os
from typing import Any


def get_logger(name: str = "cloudsec-llm-triage-bot") -> logging.Logger:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger


def log_event(logger: logging.Logger, level: str, message: str, **context: Any) -> None:
    payload = {"message": message, **context}
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(json.dumps(payload, default=str))
