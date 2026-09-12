from __future__ import annotations

from models import (
    FindingEnrichment,
    LLMAnalysis,
    NormalizedFinding,
    PatternHistory,
    PolicyDecision,
    ResourceContext,
)


BLOCKED_KEYWORDS = {
    "credential compromise",
    "credentialaccess",
    "malware",
    "privilege escalation",
    "privilegeescalation",
    "public exposure",
    "publicly accessible",
    "active exploitation",
    "exploitation",
}


def evaluate_policy(
    finding: NormalizedFinding,
    analysis: LLMAnalysis,
    allowlist: set[str],
    enrichment: FindingEnrichment | None = None,
    context: ResourceContext | None = None,
    history: PatternHistory | None = None,
) -> PolicyDecision:
    reason_codes: list[str] = []
    final_risk_level = _max_risk(finding.severity, analysis.risk_level)
    normalized_environment = finding.environment.lower()

    # Deterministic threat-intel gate (REVIEW.md C1): a CVE on CISA's Known
    # Exploited Vulnerabilities catalog is actively exploited in the wild — it is
    # never a suppression candidate, regardless of what the LLM thinks. This rule
    # is fed by retrieval, not by the model, and runs first.
    if enrichment is not None and enrichment.in_cisa_kev:
        reason_codes.append("cve_in_cisa_kev_blocked")
        return PolicyDecision(
            decision="alert_and_document",
            candidate_for_suppression=False,
            final_risk_level=_max_risk(final_risk_level, "high"),
            reason_codes=reason_codes,
            recommended_action=(
                "CVE is on the CISA Known Exploited Vulnerabilities catalog "
                "(actively exploited). Patch/escalate immediately; suppression is forbidden."
            ),
        )
    # Match dangerous-category keywords against the finding's own fields (sourced
    # from GuardDuty/Inspector) plus the LLM's *structured* tags — a controlled
    # signal the model has to set on purpose. We deliberately exclude the LLM's
    # free-text `rationale` and `indicators`: prose that merely *mentions* a
    # dangerous term (often to negate it, e.g. "this is NOT a credential
    # compromise") was causing false blocks. See REVIEW.md section B2.
    searchable_text = " ".join(
        [
            finding.title,
            finding.description,
            finding.finding_type,
            " ".join(analysis.finding_tags),
        ]
    ).lower()

    if final_risk_level in {"high", "critical"}:
        reason_codes.append("risk_level_blocked")
        return PolicyDecision(
            decision="alert_and_document",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Escalate immediately. Suppression is forbidden for high or critical risk findings.",
        )

    if normalized_environment == "production":
        reason_codes.append("production_environment_blocked")
        return PolicyDecision(
            decision="alert_and_document",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Escalate and document. Production findings cannot be suppression candidates.",
        )

    if any(keyword in searchable_text for keyword in BLOCKED_KEYWORDS):
        reason_codes.append("dangerous_finding_type_blocked")
        return PolicyDecision(
            decision="alert_and_document",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Treat as actionable security signal and route to SecOps for remediation.",
        )

    # --- Reglas anadidas por el MVP (T2 y T3) --------------------------------
    # Cubren lo que la ficha de caso de uso promete y el sistema serverless aun no
    # implementa: detectar cuando el escaneo recurrente cambia de origen, de puerto
    # o de recurso, y no dar por buena una valoracion de explotabilidad sobre un
    # recurso del que no sabemos nada. Con context=None y history=None este bloque
    # entero se salta y el comportamiento es identico al original.

    if history is not None and history.variacion_detectada:
        reason_codes.append("pattern_variation_detected")
        cambios = "; ".join(history.variaciones) or "el patron observado cambio"
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action=(
                "El patron recurrente de este finding cambio respecto al historico "
                f"de los ultimos {history.ventana_dias} dias ({history.ocurrencias} "
                f"ocurrencias previas). Cambios detectados: {cambios}. "
                "Un escaneo recurrente que cambia de puerto o de origen deja de ser "
                "ruido conocido: revisar manualmente antes de tratarlo como tal."
            ),
        )

    if context is not None and not context.encontrado:
        reason_codes.append("resource_context_not_found")
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action=(
                f"El recurso {context.resource_id} no esta en el inventario, asi que "
                "no se puede valorar su explotabilidad: se desconoce su entorno, su "
                "criticidad y si esta expuesto a internet. Revisar manualmente e "
                "inventariar el recurso."
            ),
        )

    if analysis.confidence < 0.80:
        reason_codes.append("llm_confidence_below_threshold")
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Perform human review before any exception handling.",
        )

    if final_risk_level != "low":
        reason_codes.append("only_low_risk_can_be_suppressed")
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Document the finding and require analyst validation.",
        )

    if normalized_environment not in {"dev", "sandbox"}:
        reason_codes.append("environment_not_allowlisted")
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Only dev or sandbox findings can be suppression candidates in this MVP.",
        )

    if finding.finding_type not in allowlist:
        reason_codes.append("finding_type_not_in_allowlist")
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="Finding type is not allowlisted for candidate_for_suppression.",
        )

    if not analysis.suppression_candidate:
        reason_codes.append("llm_did_not_recommend_suppression")
        return PolicyDecision(
            decision="manual_review",
            candidate_for_suppression=False,
            final_risk_level=final_risk_level,
            reason_codes=reason_codes,
            recommended_action="The LLM did not recommend suppression. Keep manual review in place.",
        )

    reason_codes.append("allowlisted_low_risk_nonprod_candidate")
    return PolicyDecision(
        decision="candidate_for_suppression",
        candidate_for_suppression=True,
        final_risk_level=final_risk_level,
        reason_codes=reason_codes,
        recommended_action=(
            "Candidate for suppression after human approval. "
            "Do not automate suppression in this MVP."
        ),
    )


def _max_risk(*levels: str) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    valid_levels = [level for level in levels if level in rank]
    highest = max(valid_levels, key=rank.get, default="medium")
    return highest
