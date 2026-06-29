from __future__ import annotations

import requests

from logger import log_event
from models import TriageResult


class SlackNotifier:
    def __init__(self, webhook_url: str | None, logger) -> None:
        self.webhook_url = webhook_url or ""
        self.logger = logger

    def build_payload(self, triage_result: TriageResult) -> dict:
        finding = triage_result.finding
        decision = triage_result.policy_decision
        metadata = triage_result.ingestion_metadata
        confluence_link = (
            f"<{triage_result.confluence_page_url}|Open page>"
            if triage_result.confluence_page_url
            else "Not available"
        )

        summary_lines = [
            f"*Risk level:* `{decision.final_risk_level}`",
            f"*Finding source:* `{finding.source}`",
            f"*Finding title:* {finding.title}",
            f"*Affected resource:* `{finding.resource_type}:{finding.resource_id}`",
            f"*Decision:* `{decision.decision}`",
            f"*Recommended action:* {decision.recommended_action}",
            f"*Confluence page:* {confluence_link}",
        ]
        if metadata is not None:
            summary_lines.extend(
                [
                    f"*Event source:* `{metadata.source}`",
                    f"*Detail type:* `{metadata.detail_type}`",
                    f"*Event shape:* `{metadata.event_shape}`",
                    f"*Event id:* `{metadata.event_id}`",
                ]
            )

        enrichment = triage_result.enrichment
        if enrichment is not None and enrichment.cve_id:
            kev = "YES :warning:" if enrichment.in_cisa_kev else "no"
            epss = f"{enrichment.epss_score:.2f}" if enrichment.epss_score is not None else "n/a"
            summary_lines.append(
                f"*CVE:* `{enrichment.cve_id}` | *CISA KEV:* {kev} | *EPSS:* {epss}"
            )

        return {
            "text": f"[{decision.final_risk_level.upper()}] {finding.title} -> {decision.decision}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(summary_lines),
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*LLM summary:* {triage_result.llm_analysis.summary}\n"
                            f"*Reason codes:* {', '.join(decision.reason_codes) or 'none'}"
                        ),
                    },
                },
            ],
        }

    def send(self, triage_result: TriageResult) -> bool:
        if not self.webhook_url:
            log_event(
                self.logger,
                "warning",
                "Slack webhook URL not configured. Skipping notification.",
                finding_id=triage_result.finding.finding_id,
            )
            return False

        try:
            response = requests.post(self.webhook_url, json=self.build_payload(triage_result), timeout=10)
            response.raise_for_status()
            return True
        except requests.RequestException as exc:
            log_event(
                self.logger,
                "error",
                "Slack notification failed.",
                finding_id=triage_result.finding.finding_id,
                error=str(exc),
            )
            return False
