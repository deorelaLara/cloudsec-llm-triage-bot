from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from confluence_client import ConfluenceClient
from logger import get_logger
from models import EventIngestionMetadata, LLMAnalysis, NormalizedFinding, PolicyDecision, TriageResult


def _triage_result() -> TriageResult:
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
    return TriageResult(
        finding=finding,
        llm_analysis=analysis,
        policy_decision=decision,
        ingestion_metadata=EventIngestionMetadata(
            event_id="evt-001",
            source="aws.guardduty",
            detail_type="GuardDuty Finding",
            account="123456789012",
            region="us-east-1",
            event_time="2026-05-21T19:07:54Z",
            event_shape="eventbridge_guardduty_finding",
            has_eventbridge_envelope=True,
        ),
        execution_id="abcd1234-ef56-7890",
        processed_at="2026-05-21T19:07:54Z",
    )


def test_build_unique_title_adds_execution_context() -> None:
    client = ConfluenceClient(
        base_url="https://example.atlassian.net",
        email="user@example.com",
        api_token="token",
        space_key="AWSKB",
        parent_page_id="123456",
        logger=get_logger("test"),
    )

    title = client._build_unique_title(_triage_result())

    assert title.startswith("[LOW] AWS Security Finding - Recon:EC2/PortProbeUnprotectedPort - finding-001 - ")
    assert title.endswith("-abcd1234")
    assert "20260521-190754Z" in title
