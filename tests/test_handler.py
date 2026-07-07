from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import handler  # noqa: E402


def _guardduty_event() -> dict:
    return {
        "version": "0",
        "id": "evt-guardduty-test",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": "123456789012",
        "time": "2026-05-20T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "id": "finding-test",
            "accountId": "123456789012",
            "region": "us-east-1",
            "severity": 8.6,
            "title": "Test finding",
            "description": "desc",
            "type": "CredentialAccess:IAMUser/AnomalousBehavior",
            "resource": {
                "resourceType": "AccessKey",
                "accessKeyDetails": {"accessKeyId": "AKIAEXAMPLE1234"},
            },
            "service": {"action": {"actionType": "AWS_API_CALL"}},
        },
    }


def test_unsupported_event_is_dropped_not_retried() -> None:
    # A malformed / unsupported event is a poison message: acknowledge it instead
    # of raising, so EventBridge does not keep retrying it into the DLQ.
    result = handler.lambda_handler({"foo": "bar"}, None)

    assert result["status"] == "ignored"


def test_duplicate_finding_is_skipped(monkeypatch) -> None:
    # With dedup enabled, an already-processed finding is skipped before any LLM spend.
    monkeypatch.setenv("DEDUP_TABLE_NAME", "processed-findings")
    with patch.object(handler, "is_duplicate", return_value=True):
        result = handler.lambda_handler(_guardduty_event(), None)

    assert result["status"] == "skipped_duplicate"


def test_transient_downstream_error_propagates_for_retry() -> None:
    # A transient infra failure (e.g. Secrets Manager throttling) must propagate so
    # EventBridge retries and, on exhaustion, dead-letters the event — never a
    # silent drop of a real finding.
    with patch.object(
        handler,
        "load_integration_secrets",
        side_effect=RuntimeError("secrets manager throttled"),
    ):
        with pytest.raises(RuntimeError):
            handler.lambda_handler(_guardduty_event(), None)
