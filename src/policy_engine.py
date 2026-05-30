from __future__ import annotations

from models import LLMAnalysis, NormalizedFinding, PolicyDecision


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
) -> PolicyDecision:
    reason_codes: list[str] = []
    final_risk_level = _max_risk(finding.severity, analysis.risk_level)
    normalized_environment = finding.environment.lower()
    searchable_text = " ".join(
        [
            finding.title,
            finding.description,
            finding.finding_type,
            analysis.rationale,
            " ".join(analysis.indicators),
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
