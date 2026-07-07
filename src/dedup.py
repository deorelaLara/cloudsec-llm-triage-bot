from __future__ import annotations

import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from logger import log_event


# Idempotency / dedup (REVIEW.md B6). GuardDuty re-emits the same finding
# periodically; without dedup that means duplicate Confluence pages and Slack spam.
# We record processed finding IDs in DynamoDB (with a TTL) and skip re-processing.
#
# Design: CHECK at the start, MARK only after a successful run. This keeps it
# compatible with the B1 retry/DLQ behaviour — a finding that failed mid-run was
# never marked, so an EventBridge retry reprocesses it instead of being skipped.
# Dedup is fail-open: a DynamoDB outage logs a warning and lets triage proceed.


def _table(table_name: str, region: str):
    return boto3.resource("dynamodb", region_name=region).Table(table_name)


def is_duplicate(finding_id: str, table_name: str, region: str, logger) -> bool:
    try:
        response = _table(table_name, region).get_item(Key={"finding_id": finding_id})
        return "Item" in response
    except (BotoCoreError, ClientError) as exc:
        log_event(
            logger,
            "warning",
            "Dedup lookup failed; processing the finding anyway.",
            finding_id=finding_id,
            error=str(exc),
        )
        return False


def mark_processed(finding_id: str, table_name: str, region: str, ttl_seconds: int, logger) -> None:
    try:
        _table(table_name, region).put_item(
            Item={"finding_id": finding_id, "expires_at": int(time.time()) + ttl_seconds}
        )
    except (BotoCoreError, ClientError) as exc:
        log_event(
            logger,
            "warning",
            "Failed to record processed finding for dedup.",
            finding_id=finding_id,
            error=str(exc),
        )
