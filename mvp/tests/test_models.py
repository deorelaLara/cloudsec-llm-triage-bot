from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from models import EventIngestionMetadata, LLMAnalysis, NormalizedFinding, PolicyDecision, TriageResult


def test_llm_analysis_accepts_valid_payload() -> None:
    analysis = LLMAnalysis(
        summary="Low-risk development port probe.",
        risk_level="low",
        confidence=0.91,
        rationale="Behavior matches known sandbox activity.",
        indicators=["low severity", "sandbox environment"],
        recommended_action="Review and keep as manual candidate only.",
        suppression_candidate=True,
        finding_tags=["false positive"],
    )

    assert analysis.confidence == 0.91
    assert analysis.suppression_candidate is True


def test_llm_analysis_rejects_invalid_confidence() -> None:
    with pytest.raises(ValidationError):
        LLMAnalysis(
            summary="Invalid confidence",
            risk_level="low",
            confidence=1.5,
            rationale="Invalid example.",
            indicators=[],
            recommended_action="Review",
            suppression_candidate=False,
            finding_tags=[],
        )


def test_triage_result_serializes_expected_contract() -> None:
    finding = NormalizedFinding(
        finding_id="finding-001",
        source="guardduty",
        account_id="123456789012",
        region="us-east-1",
        severity="low",
        title="Recon:EC2/PortProbeUnprotectedPort",
        description="Low severity probe in sandbox.",
        finding_type="Recon:EC2/PortProbeUnprotectedPort",
        resource_id="i-001",
        resource_type="Instance",
        environment="sandbox",
        raw_event={"sample": True},
    )
    analysis = LLMAnalysis(
        summary="Likely low-risk sandbox traffic.",
        risk_level="low",
        confidence=0.93,
        rationale="Tags and severity are consistent with non-production testing.",
        indicators=["sandbox", "low severity"],
        recommended_action="Human approval before any suppression exception.",
        suppression_candidate=True,
        finding_tags=["false positive"],
    )
    decision = PolicyDecision(
        decision="candidate_for_suppression",
        candidate_for_suppression=True,
        final_risk_level="low",
        reason_codes=["allowlisted_low_risk_nonprod_candidate"],
        recommended_action="Human approval required before suppression.",
    )

    result = TriageResult(
        finding=finding,
        llm_analysis=analysis,
        policy_decision=decision,
        ingestion_metadata=EventIngestionMetadata(
            event_id="evt-123",
            source="aws.guardduty",
            detail_type="GuardDuty Finding",
            account="123456789012",
            region="us-east-1",
            event_time="2026-05-21T12:00:00Z",
            event_shape="eventbridge_guardduty_finding",
            has_eventbridge_envelope=True,
        ),
        execution_id="request-12345678",
        processed_at="2026-05-21T12:00:00Z",
        confluence_page_url="https://example.atlassian.net/wiki/x/abc123",
        slack_notification_sent=True,
        errors=[],
    )

    payload = result.model_dump(mode="json")
    assert payload["policy_decision"]["decision"] == "candidate_for_suppression"
    assert payload["slack_notification_sent"] is True
    assert payload["execution_id"] == "request-12345678"
    assert payload["ingestion_metadata"]["event_shape"] == "eventbridge_guardduty_finding"
