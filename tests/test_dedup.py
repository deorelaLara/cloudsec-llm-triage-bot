from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import dedup  # noqa: E402
from logger import get_logger  # noqa: E402


def test_is_duplicate_true_when_item_exists() -> None:
    table = MagicMock()
    table.get_item.return_value = {"Item": {"finding_id": "f1"}}
    with patch("dedup._table", return_value=table):
        assert dedup.is_duplicate("f1", "t", "us-east-1", get_logger("test")) is True


def test_is_duplicate_false_when_absent() -> None:
    table = MagicMock()
    table.get_item.return_value = {}
    with patch("dedup._table", return_value=table):
        assert dedup.is_duplicate("f1", "t", "us-east-1", get_logger("test")) is False


def test_is_duplicate_fail_open_on_error() -> None:
    err = ClientError({"Error": {"Code": "X", "Message": "y"}}, "GetItem")
    with patch("dedup._table", side_effect=err):
        # Fail-open: never block triage on a dedup outage.
        assert dedup.is_duplicate("f1", "t", "us-east-1", get_logger("test")) is False


def test_mark_processed_writes_item_with_ttl() -> None:
    table = MagicMock()
    with patch("dedup._table", return_value=table):
        dedup.mark_processed("f1", "t", "us-east-1", 3600, get_logger("test"))

    assert table.put_item.called
    item = table.put_item.call_args.kwargs["Item"]
    assert item["finding_id"] == "f1"
    assert "expires_at" in item
