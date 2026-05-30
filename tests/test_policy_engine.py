from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from models import LLMAnalysis, NormalizedFinding
from policy_engine import evaluate_policy


ALLOWLIST = {"Recon:EC2/PortProbeUnprotectedPort", "Software and Configuration Checks/Package Vulnerability"}


def _finding(
    severity: str,
    environment: str,
    finding_type: str,
    title: str = "Generic finding",
    description: str = "Generic description",
) -> NormalizedFinding:
    return NormalizedFinding(
        finding_id="finding-123",
        source="guardduty",
        account_id="123456789012",
        region="us-east-1",
        severity=severity,
        title=title,
        description=description,
        finding_type=finding_type,
        resource_id="i-1234567890",
        resource_type="Instance",
        environment=environment,
        raw_event={"detail": "sample"},
    )


def _analysis(
    risk_level: str,
    confidence: float,
    suppression_candidate: bool,
    rationale: str = "Initial assessment",
    tags: list[str] | None = None,
) -> LLMAnalysis:
    return LLMAnalysis(
        summary="Summary",
        risk_level=risk_level,
        confidence=confidence,
        rationale=rationale,
        indicators=["test-indicator"],
        recommended_action="Review",
        suppression_candidate=suppression_candidate,
        finding_tags=tags or [],
    )


def test_high_or_critical_findings_cannot_be_suppressed() -> None:
    finding = _finding("high", "dev", "Recon:EC2/PortProbeUnprotectedPort")
    analysis = _analysis("low", 0.95, True)

    decision = evaluate_policy(finding, analysis, ALLOWLIST)

    assert decision.decision == "alert_and_document"
    assert decision.candidate_for_suppression is False


def test_production_findings_cannot_be_suppressed() -> None:
    finding = _finding("low", "production", "Recon:EC2/PortProbeUnprotectedPort")
    analysis = _analysis("low", 0.98, True)

    decision = evaluate_policy(finding, analysis, ALLOWLIST)

    assert decision.decision == "alert_and_document"
    assert "production_environment_blocked" in decision.reason_codes


def test_credential_compromise_findings_are_blocked() -> None:
    finding = _finding(
        "low",
        "sandbox",
        "CredentialAccess:IAMUser/AnomalousBehavior",
        title="Potential credential compromise",
        description="Possible credential compromise observed.",
    )
    analysis = _analysis(
        "low",
        0.99,
        True,
        rationale="Credential compromise indicators present.",
        tags=["credential compromise"],
    )

    decision = evaluate_policy(finding, analysis, ALLOWLIST)

    assert decision.decision == "alert_and_document"
    assert "dangerous_finding_type_blocked" in decision.reason_codes


def test_low_risk_nonprod_allowlisted_findings_can_be_candidates() -> None:
    finding = _finding("low", "dev", "Recon:EC2/PortProbeUnprotectedPort")
    analysis = _analysis("low", 0.92, True)

    decision = evaluate_policy(finding, analysis, ALLOWLIST)

    assert decision.decision == "candidate_for_suppression"
    assert decision.candidate_for_suppression is True


def test_confidence_below_threshold_forces_manual_review() -> None:
    finding = _finding("low", "sandbox", "Recon:EC2/PortProbeUnprotectedPort")
    analysis = _analysis("low", 0.79, True)

    decision = evaluate_policy(finding, analysis, ALLOWLIST)

    assert decision.decision == "manual_review"
    assert "llm_confidence_below_threshold" in decision.reason_codes


def test_medium_risk_finding_stays_in_manual_review() -> None:
    finding = _finding("medium", "dev", "Software and Configuration Checks/Package Vulnerability")
    analysis = _analysis("medium", 0.95, True)

    decision = evaluate_policy(finding, analysis, ALLOWLIST)

    assert decision.decision == "manual_review"
    assert decision.candidate_for_suppression is False
