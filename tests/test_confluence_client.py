from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

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


class _FakeResponse:
    def __init__(self, status_code: int, text: str = "", json_data: dict | None = None) -> None:
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self.text = text
        self._json = json_data or {}

    def json(self) -> dict:
        return self._json


def _client() -> ConfluenceClient:
    return ConfluenceClient(
        base_url="https://example.atlassian.net",
        email="user@example.com",
        api_token="token",
        space_key="AWSKB",
        parent_page_id="123456",
        logger=get_logger("test"),
    )


def test_build_unique_title_adds_execution_context() -> None:
    client = _client()

    title = client._build_unique_title(_triage_result())

    assert title.startswith("[LOW] AWS Security Finding - Recon:EC2/PortProbeUnprotectedPort - finding-001 - ")
    assert title.endswith("-abcd1234")
    assert "20260521-190754Z" in title


def test_duplicate_title_400_retries_with_unique_suffix() -> None:
    client = _client()
    duplicate = _FakeResponse(400, text="A page with this title already exists.")
    success = _FakeResponse(
        200,
        json_data={"_links": {"base": "https://example.atlassian.net/wiki", "webui": "/pages/1"}},
    )

    with patch.object(client, "_post_page", side_effect=[duplicate, success]) as post:
        url = client.create_page(_triage_result())

    assert url == "https://example.atlassian.net/wiki/pages/1"
    assert post.call_count == 2  # retried once with a unique title


def test_non_duplicate_400_raises_without_masking() -> None:
    client = _client()
    bad_request = _FakeResponse(400, text="The space key WRONG is invalid.")

    with patch.object(client, "_post_page", side_effect=[bad_request]) as post:
        with pytest.raises(RuntimeError):
            client.create_page(_triage_result())

    assert post.call_count == 1  # no masking retry — the real error surfaces


def test_body_includes_threat_intel_when_enriched() -> None:
    from models import FindingEnrichment

    client = _client()
    triage = _triage_result()
    triage.enrichment = FindingEnrichment(
        cve_id="CVE-2021-44228", in_cisa_kev=True, epss_score=0.99999, source="kev_epss"
    )

    body = client._build_storage_html(triage)

    assert "Threat Intelligence" in body
    assert "CVE-2021-44228" in body
    assert "YES" in body
