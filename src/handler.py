from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from confluence_client import ConfluenceClient
from finding_normalizer import inspect_event_shape, normalize_finding_event
from llm_analyzer import LLMAnalyzer
from logger import get_logger, log_event
from models import TriageResult
from policy_engine import evaluate_policy
from secrets import load_integration_secrets
from slack_notifier import SlackNotifier


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    logger = get_logger()
    config = _load_runtime_config()
    execution_id = getattr(context, "aws_request_id", "") or event.get("id") or "local-run"
    processed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ingestion_metadata = inspect_event_shape(event)

    log_event(
        logger,
        "info",
        "Received security finding event.",
        llm_provider=config["llm_provider"],
        project_name=config["project_name"],
        event_id=ingestion_metadata.event_id,
        event_source=ingestion_metadata.source,
        detail_type=ingestion_metadata.detail_type,
        account=ingestion_metadata.account,
        region=ingestion_metadata.region,
        event_shape=ingestion_metadata.event_shape,
        has_eventbridge_envelope=ingestion_metadata.has_eventbridge_envelope,
    )

    try:
        finding = normalize_finding_event(event)
    except ValueError as exc:
        # Poison message: the event is not a supported GuardDuty/Inspector finding.
        # Retrying will never succeed, so we acknowledge it (return without raising)
        # to keep it out of the DLQ. Everything *after* normalization is allowed to
        # propagate so transient infra failures get retried and dead-lettered
        # instead of silently dropping a real security finding. See REVIEW.md B1.
        log_event(
            logger,
            "error",
            "Unsupported or malformed event; dropping without retry.",
            event_id=ingestion_metadata.event_id,
            event_shape=ingestion_metadata.event_shape,
            error=str(exc),
        )
        return {
            "status": "ignored",
            "message": str(exc),
            "project_name": config["project_name"],
        }

    log_event(
        logger,
        "info",
        "Normalized incoming security finding.",
        event_id=ingestion_metadata.event_id,
        event_shape=ingestion_metadata.event_shape,
        finding_id=finding.finding_id,
        finding_source=finding.source,
        severity=finding.severity,
        finding_type=finding.finding_type,
        environment=finding.environment,
        resource_id=finding.resource_id,
    )

    # No broad try/except below on purpose. If Secrets Manager, Bedrock/OpenAI, or
    # any other step raises, the Lambda fails so EventBridge retries and, on
    # exhaustion, routes the event to the DLQ. Swallowing here would lose the
    # finding silently — the worst outcome for a security pipeline. See REVIEW.md B1.
    secrets = load_integration_secrets(config["secret_name"], config["aws_region"], logger)

    analyzer = LLMAnalyzer(
        provider=config["llm_provider"],
        region_name=config["aws_region"],
        logger=logger,
        openai_model=config["openai_model"],
        openai_base_url=config["openai_base_url"],
        bedrock_model_id=config["bedrock_model_id"],
    )
    llm_analysis = analyzer.analyze(finding, secrets)
    decision = evaluate_policy(finding, llm_analysis, config["suppression_allowlist"])

    triage_result = TriageResult(
        finding=finding,
        llm_analysis=llm_analysis,
        policy_decision=decision,
        ingestion_metadata=ingestion_metadata,
        execution_id=execution_id,
        processed_at=processed_at,
    )

    confluence_client = ConfluenceClient(
        base_url=secrets.confluence_base_url,
        email=secrets.confluence_email,
        api_token=secrets.confluence_api_token,
        space_key=config["confluence_space_key"],
        parent_page_id=config["confluence_parent_page_id"],
        logger=logger,
    )
    slack_notifier = SlackNotifier(secrets.slack_webhook_url, logger)

    # Slack/Confluence are documentation/notification side-effects: a failure here
    # is recorded in `errors` but must NOT fail the invocation — the triage decision
    # already succeeded, and re-running would re-notify/re-document.
    errors: list[str] = []

    try:
        triage_result.confluence_page_url = confluence_client.create_page(triage_result)
    except Exception as exc:  # noqa: BLE001
        errors.append("confluence_documentation_failed")
        log_event(
            logger,
            "error",
            "Confluence page creation failed.",
            finding_id=finding.finding_id,
            error=str(exc),
        )

    triage_result.slack_notification_sent = slack_notifier.send(triage_result)
    if not triage_result.slack_notification_sent:
        errors.append("slack_notification_not_sent")

    triage_result.errors.extend(errors)
    log_event(
        logger,
        "info",
        "Security finding processed.",
        event_id=ingestion_metadata.event_id,
        finding_id=finding.finding_id,
        decision=decision.decision,
        risk_level=decision.final_risk_level,
    )
    return triage_result.model_dump(mode="json")


def _load_runtime_config() -> dict[str, Any]:
    allowlist_raw = os.getenv(
        "SUPPRESSION_ALLOWLIST",
        "Recon:EC2/PortProbeUnprotectedPort,Software and Configuration Checks/Package Vulnerability",
    )
    allowlist = {item.strip() for item in allowlist_raw.split(",") if item.strip()}

    return {
        "aws_region": os.getenv("AWS_REGION", "us-east-1"),
        "project_name": os.getenv("PROJECT_NAME", "cloudsec-llm-triage-bot"),
        "environment": os.getenv("ENVIRONMENT", "dev"),
        "llm_provider": os.getenv("LLM_PROVIDER", "openai").lower(),
        "secret_name": os.getenv("SECRET_NAME", "cloudsec-llm-triage-bot/dev/integrations"),
        "confluence_space_key": os.getenv("CONFLUENCE_SPACE_KEY", "SECOPS"),
        "confluence_parent_page_id": os.getenv("CONFLUENCE_PARENT_PAGE_ID", ""),
        "openai_model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
        "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        "bedrock_model_id": os.getenv("BEDROCK_MODEL_ID", "au.anthropic.claude-sonnet-4-6"),
        "suppression_allowlist": allowlist,
    }
