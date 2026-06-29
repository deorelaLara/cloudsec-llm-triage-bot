from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from logger import get_logger  # noqa: E402
from models import (  # noqa: E402
    FindingEnrichment,
    LLMAnalysis,
    NormalizedFinding,
    PolicyDecision,
    TriageResult,
)
from slack_notifier import SlackNotifier  # noqa: E402


def _triage_result(enrichment: FindingEnrichment | None = None) -> TriageResult:
    finding = NormalizedFinding(
        finding_id="f",
        source="inspector",
        account_id="123456789012",
        region="us-east-1",
        severity="critical",
        title="Critical vuln",
        description="d",
        finding_type="Software and Configuration Checks/Package Vulnerability",
        resource_id="i-1",
        resource_type="AWS_EC2_INSTANCE",
        environment="production",
        raw_event={},
    )
    analysis = LLMAnalysis(
        summary="s",
        risk_level="critical",
        confidence=0.9,
        rationale="r",
        indicators=[],
        recommended_action="a",
        suppression_candidate=False,
        finding_tags=[],
    )
    decision = PolicyDecision(
        decision="alert_and_document",
        candidate_for_suppression=False,
        final_risk_level="critical",
        reason_codes=["cve_in_cisa_kev_blocked"],
        recommended_action="Escalate immediately.",
    )
    return TriageResult(
        finding=finding, llm_analysis=analysis, policy_decision=decision, enrichment=enrichment
    )


def _summary_text(payload: dict) -> str:
    return payload["blocks"][0]["text"]["text"]


def test_payload_includes_cve_when_enriched() -> None:
    notifier = SlackNotifier("https://hooks.slack.example/x", get_logger("test"))
    triage = _triage_result(
        FindingEnrichment(cve_id="CVE-2021-44228", in_cisa_kev=True, epss_score=0.97, source="kev_epss")
    )

    text = _summary_text(notifier.build_payload(triage))

    assert "CVE-2021-44228" in text
    assert "CISA KEV" in text


def test_payload_omits_cve_when_not_enriched() -> None:
    notifier = SlackNotifier("https://hooks.slack.example/x", get_logger("test"))

    text = _summary_text(notifier.build_payload(_triage_result(None)))

    assert "CVE" not in text
