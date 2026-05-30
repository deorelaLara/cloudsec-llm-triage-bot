from __future__ import annotations

from typing import Any

from models import EventIngestionMetadata, NormalizedFinding


def normalize_finding_event(event: dict[str, Any]) -> NormalizedFinding:
    detail = event.get("detail", event)
    event_source = (event.get("source") or detail.get("source") or "").lower()

    if event_source == "aws.guardduty" or "guardduty" in event_source or "service.action" in detail:
        return _normalize_guardduty(event, detail)

    if event_source == "aws.inspector2" or "inspector" in event_source or detail.get("findingArn"):
        return _normalize_inspector(event, detail)

    raise ValueError("Unsupported event source. Expected GuardDuty or Inspector finding.")


def inspect_event_shape(event: dict[str, Any]) -> EventIngestionMetadata:
    detail = event.get("detail", {})
    detail = detail if isinstance(detail, dict) else {}
    source = str(event.get("source") or detail.get("source") or "unknown")
    detail_type = str(event.get("detail-type") or event.get("detail_type") or "unknown")
    account = str(event.get("account") or detail.get("accountId") or detail.get("awsAccountId") or "unknown")
    region = str(event.get("region") or detail.get("region") or "unknown")
    event_id = str(event.get("id") or detail.get("id") or detail.get("findingArn") or "")
    event_time = str(event.get("time") or "")
    has_eventbridge_envelope = _has_eventbridge_envelope(event)

    if has_eventbridge_envelope and source == "aws.guardduty" and detail_type == "GuardDuty Finding":
        event_shape = "eventbridge_guardduty_finding"
    elif has_eventbridge_envelope and source == "aws.inspector2" and detail_type == "Inspector2 Finding":
        event_shape = "eventbridge_inspector_finding"
    elif detail.get("service", {}).get("action") or detail.get("type"):
        event_shape = "direct_guardduty_payload"
    elif detail.get("findingArn") or detail.get("resources"):
        event_shape = "direct_inspector_payload"
    else:
        event_shape = "unknown"

    return EventIngestionMetadata(
        event_id=event_id,
        source=source,
        detail_type=detail_type,
        account=account,
        region=region,
        event_time=event_time,
        event_shape=event_shape,
        has_eventbridge_envelope=has_eventbridge_envelope,
    )


def _normalize_guardduty(event: dict[str, Any], detail: dict[str, Any]) -> NormalizedFinding:
    resource = detail.get("resource", {})
    instance_details = resource.get("instanceDetails", {})
    access_key_details = resource.get("accessKeyDetails", {})
    resource_type = resource.get("resourceType") or "Unknown"
    resource_id = (
        instance_details.get("instanceId")
        or access_key_details.get("accessKeyId")
        or resource.get("resourceId")
        or resource_type
    )

    tags = instance_details.get("tags", [])
    environment = _extract_environment(tags)

    return NormalizedFinding(
        finding_id=detail.get("id") or detail.get("findingId") or "unknown-finding-id",
        source="guardduty",
        account_id=detail.get("accountId") or event.get("account") or "unknown-account",
        region=detail.get("region") or event.get("region") or "unknown-region",
        severity=_normalize_guardduty_severity(detail.get("severity")),
        title=detail.get("title") or "GuardDuty finding",
        description=detail.get("description") or "No description provided.",
        finding_type=detail.get("type") or "unknown",
        resource_id=resource_id,
        resource_type=resource_type,
        environment=environment,
        raw_event=event,
    )


def _normalize_inspector(event: dict[str, Any], detail: dict[str, Any]) -> NormalizedFinding:
    resources = detail.get("resources") or []
    primary_resource = resources[0] if resources else {}
    tags = primary_resource.get("tags") or detail.get("tags") or {}

    return NormalizedFinding(
        finding_id=detail.get("findingArn") or detail.get("findingId") or "unknown-finding-id",
        source="inspector",
        account_id=detail.get("awsAccountId") or event.get("account") or "unknown-account",
        region=detail.get("region") or event.get("region") or "unknown-region",
        severity=_normalize_string_severity(detail.get("severity")),
        title=detail.get("title") or "Inspector finding",
        description=detail.get("description") or "No description provided.",
        finding_type=detail.get("type") or detail.get("packageVulnerabilityDetails", {}).get("vulnerabilityId") or "unknown",
        resource_id=primary_resource.get("id") or primary_resource.get("resourceId") or "unknown-resource-id",
        resource_type=primary_resource.get("type") or primary_resource.get("resourceType") or "Unknown",
        environment=_extract_environment(tags),
        raw_event=event,
    )


def _normalize_guardduty_severity(value: Any) -> str:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return "unknown"

    if numeric >= 9.0:
        return "critical"
    if numeric >= 7.0:
        return "high"
    if numeric >= 4.0:
        return "medium"
    return "low"


def _normalize_string_severity(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    return "unknown"


def _extract_environment(tags: Any) -> str:
    if isinstance(tags, dict):
        for key, value in tags.items():
            if str(key).lower() in {"environment", "env"}:
                return str(value).lower()
        return "unknown"

    if isinstance(tags, list):
        for item in tags:
            key = str(item.get("key") or item.get("Key") or "").lower()
            if key in {"environment", "env"}:
                return str(item.get("value") or item.get("Value") or "unknown").lower()

    return "unknown"


def _has_eventbridge_envelope(event: dict[str, Any]) -> bool:
    required_keys = {"id", "source", "detail-type", "account", "region", "time", "detail"}
    return required_keys.issubset(event.keys()) and isinstance(event.get("detail"), dict)
