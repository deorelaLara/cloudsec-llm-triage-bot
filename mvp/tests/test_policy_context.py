"""Tests de las dos reglas que el MVP anade al motor de politica.

Cubren las dos reglas nuevas y, sobre todo, que con `context=None` y `history=None`
el comportamiento sea identico al original. Esa equivalencia es la razon por la que
los tests copiados de `tests/test_policy_engine.py` siguen pasando sin tocarlos.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))

from models import (  # noqa: E402
    FindingEnrichment,
    LLMAnalysis,
    NormalizedFinding,
    PatternHistory,
    ResourceContext,
)
from policy_engine import evaluate_policy  # noqa: E402


ALLOWLIST = {
    "Recon:EC2/PortProbeUnprotectedPort",
    "Software and Configuration Checks/Package Vulnerability",
}


def _finding(
    severity: str = "low",
    environment: str = "dev",
    finding_type: str = "Recon:EC2/PortProbeUnprotectedPort",
    resource_id: str = "i-0devportprobe12345",
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id="finding-mvp-1",
        source="guardduty",
        account_id="123456789012",
        region="us-east-1",
        severity=severity,
        title="Recon:EC2/PortProbeUnprotectedPort",
        description="Sondeo de puerto de baja severidad sobre un host de desarrollo.",
        finding_type=finding_type,
        resource_id=resource_id,
        resource_type="Instance",
        environment=environment,
        raw_event={},
    )


def _analysis(
    risk_level: str = "low",
    confidence: float = 0.95,
    suppression_candidate: bool = True,
) -> LLMAnalysis:
    return LLMAnalysis(
        summary="Sondeo rutinario.",
        risk_level=risk_level,
        confidence=confidence,
        rationale="Trafico esperado en un entorno de desarrollo efimero.",
        indicators=["port probe"],
        recommended_action="Sin accion inmediata.",
        suppression_candidate=suppression_candidate,
        finding_tags=["recon"],
    )


def _contexto(encontrado: bool = True) -> ResourceContext:
    if not encontrado:
        return ResourceContext(resource_id="i-0sandboxhoneypot999", encontrado=False)
    return ResourceContext(
        resource_id="i-0devportprobe12345",
        encontrado=True,
        environment="dev",
        tags={"Environment": "dev"},
        expuesto_internet=True,
        criticidad="low",
    )


def _historial(variacion: bool = False) -> PatternHistory:
    return PatternHistory(
        finding_type="Recon:EC2/PortProbeUnprotectedPort",
        resource_id="i-0devportprobe12345",
        ventana_dias=30,
        ocurrencias=5,
        puertos_observados=[22],
        origenes_observados=["203.0.113.45"],
        ultima_vez="2026-05-19T12:00:00+00:00",
        patron_recurrente=True,
        variacion_detectada=variacion,
        variaciones=["puerto 3389 nunca visto antes (historico: 22)"] if variacion else [],
    )


# --- Regla nueva 1: variacion del patron -------------------------------------


def test_variacion_de_patron_fuerza_revision_manual() -> None:
    decision = evaluate_policy(
        _finding(),
        _analysis(),
        ALLOWLIST,
        context=_contexto(),
        history=_historial(variacion=True),
    )

    assert decision.decision == "manual_review"
    assert "pattern_variation_detected" in decision.reason_codes
    assert decision.candidate_for_suppression is False
    # El motivo tiene que explicar QUE cambio, no solo que cambio algo.
    assert "3389" in decision.recommended_action


def test_sin_variacion_el_patron_recurrente_no_bloquea() -> None:
    decision = evaluate_policy(
        _finding(),
        _analysis(),
        ALLOWLIST,
        context=_contexto(),
        history=_historial(variacion=False),
    )

    assert decision.decision == "candidate_for_suppression"
    assert "pattern_variation_detected" not in decision.reason_codes


# --- Regla nueva 2: recurso no inventariado ----------------------------------


def test_recurso_no_inventariado_fuerza_revision_manual() -> None:
    decision = evaluate_policy(
        _finding(),
        _analysis(),
        ALLOWLIST,
        context=_contexto(encontrado=False),
        history=_historial(variacion=False),
    )

    assert decision.decision == "manual_review"
    assert "resource_context_not_found" in decision.reason_codes
    assert decision.candidate_for_suppression is False
    assert "i-0sandboxhoneypot999" in decision.recommended_action


def test_recurso_inventariado_no_dispara_la_regla() -> None:
    decision = evaluate_policy(
        _finding(),
        _analysis(),
        ALLOWLIST,
        context=_contexto(encontrado=True),
        history=_historial(variacion=False),
    )

    assert "resource_context_not_found" not in decision.reason_codes


# --- Orden entre las dos reglas nuevas ---------------------------------------


def test_la_variacion_tiene_prioridad_sobre_el_contexto_ausente() -> None:
    decision = evaluate_policy(
        _finding(),
        _analysis(),
        ALLOWLIST,
        context=_contexto(encontrado=False),
        history=_historial(variacion=True),
    )

    assert decision.decision == "manual_review"
    assert decision.reason_codes == ["pattern_variation_detected"]


# --- Las reglas nuevas van DESPUES de las existentes -------------------------


def test_kev_sigue_ganando_a_las_reglas_nuevas() -> None:
    """La puerta de CISA KEV es la primera y no la desplaza nada."""
    decision = evaluate_policy(
        _finding(severity="medium", finding_type="Software and Configuration Checks/Package Vulnerability"),
        _analysis(risk_level="low"),
        ALLOWLIST,
        enrichment=FindingEnrichment(cve_id="CVE-2026-12345", in_cisa_kev=True, source="kev_epss"),
        context=_contexto(encontrado=False),
        history=_historial(variacion=True),
    )

    assert decision.decision == "alert_and_document"
    assert decision.reason_codes == ["cve_in_cisa_kev_blocked"]


def test_riesgo_alto_sigue_ganando_a_las_reglas_nuevas() -> None:
    decision = evaluate_policy(
        _finding(severity="high"),
        _analysis(risk_level="high"),
        ALLOWLIST,
        context=_contexto(encontrado=False),
        history=_historial(variacion=True),
    )

    assert decision.decision == "alert_and_document"
    assert decision.reason_codes == ["risk_level_blocked"]


def test_produccion_sigue_ganando_a_las_reglas_nuevas() -> None:
    decision = evaluate_policy(
        _finding(environment="production"),
        _analysis(),
        ALLOWLIST,
        context=_contexto(encontrado=False),
        history=_historial(variacion=True),
    )

    assert decision.decision == "alert_and_document"
    assert decision.reason_codes == ["production_environment_blocked"]


# --- Equivalencia con None: el contrato que protege los tests copiados -------


def test_con_none_el_comportamiento_es_identico_al_original() -> None:
    """Mismo finding y mismo analisis, con y sin los parametros nuevos a None."""
    casos = [
        (_finding(), _analysis(), None),
        (_finding(severity="high"), _analysis(risk_level="high"), None),
        (_finding(environment="production"), _analysis(), None),
        (_finding(), _analysis(confidence=0.5), None),
        (_finding(severity="medium"), _analysis(risk_level="medium"), None),
        (_finding(environment="staging"), _analysis(), None),
        (_finding(finding_type="Trojan:EC2/DNSDataExfiltration"), _analysis(), None),
        (_finding(), _analysis(suppression_candidate=False), None),
    ]

    for finding, analysis, enrichment in casos:
        sin_parametros = evaluate_policy(finding, analysis, ALLOWLIST, enrichment)
        con_none = evaluate_policy(
            finding, analysis, ALLOWLIST, enrichment, context=None, history=None
        )
        assert sin_parametros == con_none, f"divergencia en {finding.finding_type}"


def test_con_none_no_aparecen_los_reason_codes_nuevos() -> None:
    decision = evaluate_policy(_finding(), _analysis(), ALLOWLIST, context=None, history=None)

    assert "pattern_variation_detected" not in decision.reason_codes
    assert "resource_context_not_found" not in decision.reason_codes
    assert decision.decision == "candidate_for_suppression"


def test_solo_uno_de_los_dos_parametros_informado() -> None:
    """Informar history sin context, y al reves, no debe romper nada."""
    solo_historial = evaluate_policy(
        _finding(), _analysis(), ALLOWLIST, history=_historial(variacion=True)
    )
    assert solo_historial.reason_codes == ["pattern_variation_detected"]

    solo_contexto = evaluate_policy(
        _finding(), _analysis(), ALLOWLIST, context=_contexto(encontrado=False)
    )
    assert solo_contexto.reason_codes == ["resource_context_not_found"]


def test_el_umbral_de_confianza_sigue_en_080() -> None:
    """No se toca: 0.80 y se queda."""
    justo_debajo = evaluate_policy(
        _finding(),
        _analysis(confidence=0.79),
        ALLOWLIST,
        context=_contexto(),
        history=_historial(),
    )
    assert justo_debajo.reason_codes == ["llm_confidence_below_threshold"]

    justo_encima = evaluate_policy(
        _finding(),
        _analysis(confidence=0.80),
        ALLOWLIST,
        context=_contexto(),
        history=_historial(),
    )
    assert "llm_confidence_below_threshold" not in justo_encima.reason_codes
