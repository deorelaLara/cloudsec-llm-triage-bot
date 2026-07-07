from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm_analyzer import TRIAGE_TOOL_NAME, LLMAnalyzer  # noqa: E402
from logger import get_logger  # noqa: E402
from models import IntegrationSecretBundle, LLMAnalysis, NormalizedFinding  # noqa: E402


def _sample(risk_level: str, suppression: bool) -> LLMAnalysis:
    return LLMAnalysis(
        summary="s",
        risk_level=risk_level,
        confidence=0.95,
        rationale="r",
        indicators=["i"],
        recommended_action="a",
        suppression_candidate=suppression,
        finding_tags=[],
    )


def _finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_id="finding-123",
        source="guardduty",
        account_id="123456789012",
        region="us-east-1",
        severity="high",
        title="Test finding",
        description="desc",
        finding_type="CredentialAccess:IAMUser/AnomalousBehavior",
        resource_id="AKIAEXAMPLE",
        resource_type="AccessKey",
        environment="dev",
        raw_event={"detail": "sample"},
    )


def _valid_tool_input() -> dict:
    return {
        "summary": "Potential credential compromise.",
        "risk_level": "high",
        "confidence": 0.9,
        "rationale": "Anomalous API calls from a suspicious IP.",
        "indicators": ["AnomalousBehavior"],
        "recommended_action": "Escalate to SecOps.",
        "suppression_candidate": False,
        "finding_tags": ["credential compromise"],
    }


def _bedrock_response(content: list[dict]) -> dict:
    return {"body": io.BytesIO(json.dumps({"content": content}).encode())}


def test_bedrock_tool_use_is_extracted_without_parsing_text() -> None:
    mock_client = MagicMock()
    mock_client.invoke_model.return_value = _bedrock_response(
        [{"type": "tool_use", "name": TRIAGE_TOOL_NAME, "input": _valid_tool_input()}]
    )
    with patch("llm_analyzer.boto3.client", return_value=mock_client):
        analyzer = LLMAnalyzer(provider="bedrock", region_name="us-east-2", logger=get_logger())
        result = analyzer.analyze(_finding(), IntegrationSecretBundle())

    assert result.risk_level == "high"
    assert result.confidence == 0.9
    # And the request actually forced the tool call.
    sent = json.loads(mock_client.invoke_model.call_args.kwargs["body"])
    assert sent["tool_choice"] == {"type": "tool", "name": TRIAGE_TOOL_NAME}


def test_self_consistency_low_agreement_lowers_confidence() -> None:
    analyzer = LLMAnalyzer(provider="bedrock", region_name="us-east-2", logger=get_logger())
    # The model flip-flops: 2 say low, 1 says high -> agreement 2/3 on 'low'.
    samples = [_sample("low", True), _sample("low", True), _sample("high", False)]

    result = analyzer._aggregate(samples)

    assert result.risk_level == "low"
    assert result.confidence == 0.67  # below the 0.80 gate -> manual review
    assert result.suppression_candidate is False  # not unanimous


def test_self_consistency_full_agreement_keeps_high_confidence() -> None:
    analyzer = LLMAnalyzer(provider="bedrock", region_name="us-east-2", logger=get_logger())
    samples = [_sample("low", True), _sample("low", True), _sample("low", True)]

    result = analyzer._aggregate(samples)

    assert result.risk_level == "low"
    assert result.confidence == 1.0
    assert result.suppression_candidate is True


def test_missing_tool_call_falls_back_to_safe_default() -> None:
    mock_client = MagicMock()
    mock_client.invoke_model.return_value = _bedrock_response(
        [{"type": "text", "text": "I cannot use tools right now."}]
    )
    with patch("llm_analyzer.boto3.client", return_value=mock_client):
        analyzer = LLMAnalyzer(provider="bedrock", region_name="us-east-2", logger=get_logger())
        result = analyzer.analyze(_finding(), IntegrationSecretBundle())

    # Safe fallback: never suppresses, confidence 0.0 -> policy sends to manual review.
    assert result.confidence == 0.0
    assert result.suppression_candidate is False
