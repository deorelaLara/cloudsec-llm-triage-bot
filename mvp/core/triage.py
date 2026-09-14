"""Orquestador del MVP.

Ejecuta el triage completo en un orden fijo. Es el unico sitio donde se coordinan
las seis piezas, y el unico que escribe en la base.

  1. normalize_finding_event(evento)          T1, del modulo copiado
  2. consultar_contexto_recurso(...)          T2
  3. consultar_historial_patron(...)          T3
  4. enriquecimiento local KEV/EPSS           T4
  5. LLMAnalyzer.analyze(...)                 UNICA llamada de clasificacion
  6. evaluate_policy(..., context=, history=) T5
  7. registrar en decision_triage             T6
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

_CORE_DIR = Path(__file__).resolve().parent
_MVP_ROOT = _CORE_DIR.parent
for _ruta in (str(_MVP_ROOT), str(_CORE_DIR)):
    if _ruta not in sys.path:
        sys.path.insert(0, _ruta)

import config  # noqa: E402
import llm_factory  # noqa: E402
from context import (  # noqa: E402
    consultar_contexto_recurso,
    consultar_historial_patron,
    extraer_puerto_y_origen,
)
from db import asegurar_base, registrar_decision  # noqa: E402
from enrichment_local import enrich_finding  # noqa: E402
from finding_normalizer import inspect_event_shape, normalize_finding_event  # noqa: E402
from llm_analyzer import LLMAnalyzer  # noqa: E402
from local_secrets import cargar_secretos_locales  # noqa: E402
from logger import get_logger, log_event  # noqa: E402
from models import (  # noqa: E402
    CasoTriage,
    EventIngestionMetadata,
    FueraDeAlcance,
    TriageResult,
)
from policy_engine import evaluate_policy  # noqa: E402

_logger = get_logger("mvp-cloudsec-triage")

_CLAVES_SOBRE_EVENTBRIDGE = {"id", "source", "detail-type", "account", "region", "time", "detail"}


def _metadata_segura(evento: Any) -> EventIngestionMetadata:
    """Metadata de ingesta que nunca lanza.

    `inspect_event_shape` viene copiado y asume la forma de GuardDuty o Inspector.
    Con otros eventos puede fallar: un AWS Health Event trae `detail.service` como
    cadena ("EC2") y el modulo hace `.get("action")` sobre ella. No se toca el
    modulo copiado; aqui degradamos a una metadata minima sacada del sobre de
    EventBridge, que es lo unico que hace falta para explicar por que el evento
    queda fuera de alcance.
    """
    base = evento if isinstance(evento, dict) else {}
    try:
        return inspect_event_shape(base)
    except (AttributeError, TypeError, ValueError):
        detalle = base.get("detail")
        detalle = detalle if isinstance(detalle, dict) else {}
        return EventIngestionMetadata(
            event_id=str(base.get("id") or detalle.get("id") or ""),
            source=str(base.get("source") or detalle.get("source") or "unknown"),
            detail_type=str(base.get("detail-type") or base.get("detail_type") or "unknown"),
            account=str(base.get("account") or "unknown"),
            region=str(base.get("region") or "unknown"),
            event_time=str(base.get("time") or ""),
            event_shape="unknown",
            has_eventbridge_envelope=(
                _CLAVES_SOBRE_EVENTBRIDGE.issubset(base.keys()) and isinstance(base.get("detail"), dict)
            ),
        )


def triagear(evento: dict[str, Any], db_path: Path | None = None) -> CasoTriage:
    """Triage completo de un evento.

    Si el evento no es un finding de GuardDuty ni de Inspector, devuelve un
    resultado de fuera de alcance sin llamar al modelo y sin escribir nada.
    """
    ruta_base = Path(db_path) if db_path else config.DB_PATH
    asegurar_base(ruta_base)

    # --- 1. Normalizacion (T1) ------------------------------------------------
    try:
        finding = normalize_finding_event(evento)
    except (ValueError, AttributeError, TypeError) as exc:
        metadata = _metadata_segura(evento)
        log_event(
            _logger,
            "info",
            "Evento fuera de alcance. No se llama al modelo ni se registra.",
            fuente=metadata.source,
            error=str(exc),
        )
        return CasoTriage(
            fuera_de_alcance=FueraDeAlcance(
                motivo=(
                    "El evento no es un finding de Amazon GuardDuty ni de Amazon "
                    f"Inspector (source={metadata.source!r}, "
                    f"detail-type={metadata.detail_type!r}). No se ejecuta triage."
                ),
                fuente_evento=metadata.source,
            ),
            llamadas_al_modelo=0,
        )

    metadata = _metadata_segura(evento)

    # --- 2 y 3. Contexto e historial (T2, T3) ---------------------------------
    contexto = consultar_contexto_recurso(finding.resource_id, db_path=ruta_base)
    puerto, origen = extraer_puerto_y_origen(finding.raw_event)
    historial = consultar_historial_patron(
        finding_type=finding.finding_type,
        resource_id=finding.resource_id,
        ventana_dias=config.VENTANA_HISTORIAL_DIAS,
        puerto=puerto,
        origen=origen,
        db_path=ruta_base,
    )

    # --- 4. Enriquecimiento local KEV/EPSS (T4) -------------------------------
    enriquecimiento = enrich_finding(finding, _logger, db_path=ruta_base)

    # --- 5. Unica llamada de clasificacion ------------------------------------
    analizador = LLMAnalyzer(logger=_logger, **llm_factory.parametros_analizador())
    analisis = analizador.analyze(finding, cargar_secretos_locales())
    llamadas = max(1, config.LLM_SELF_CONSISTENCY_SAMPLES)

    # --- 6. Motor determinista (T5) -------------------------------------------
    decision = evaluate_policy(
        finding,
        analisis,
        config.SUPPRESSION_ALLOWLIST,
        enrichment=enriquecimiento,
        context=contexto,
        history=historial,
    )

    resultado = TriageResult(
        finding=finding,
        llm_analysis=analisis,
        policy_decision=decision,
        ingestion_metadata=metadata,
        enrichment=enriquecimiento,
        execution_id=str(uuid4()),
        processed_at=datetime.now(timezone.utc).isoformat(),
    )

    caso = CasoTriage(
        resultado=resultado,
        resource_context=contexto,
        pattern_history=historial,
        llamadas_al_modelo=llamadas,
    )

    # --- 7. Registro (T6). Unico punto de escritura ---------------------------
    caso.registro_id = registrar_decision(
        finding_id=finding.finding_id,
        decision=decision.decision,
        final_risk_level=decision.final_risk_level,
        reason_codes=decision.reason_codes,
        caso_completo=caso.model_dump(mode="json"),
        db_path=ruta_base,
    )

    log_event(
        _logger,
        "info",
        "Triage completado.",
        finding_id=finding.finding_id,
        decision=decision.decision,
        final_risk_level=decision.final_risk_level,
        reason_codes=decision.reason_codes,
        registro_id=caso.registro_id,
    )
    return caso
