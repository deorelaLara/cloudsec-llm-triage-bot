from __future__ import annotations

import html
import json
from datetime import datetime

import requests

from logger import log_event
from models import TriageResult


class ConfluenceClient:
    def __init__(
        self,
        base_url: str | None,
        email: str | None,
        api_token: str | None,
        space_key: str,
        parent_page_id: str | None,
        logger,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.email = email or ""
        self.api_token = api_token or ""
        self.space_key = space_key
        self.parent_page_id = parent_page_id or ""
        self.logger = logger

    def create_page(self, triage_result: TriageResult) -> str | None:
        if not all([self.base_url, self.email, self.api_token, self.space_key]):
            log_event(
                self.logger,
                "warning",
                "Confluence configuration incomplete. Skipping page creation.",
                finding_id=triage_result.finding.finding_id,
            )
            return None

        title = self._build_title(triage_result)
        body = self._build_storage_html(triage_result)
        payload = self._build_payload(title, body)
        response = self._post_page(payload)

        if response.ok:
            return self._extract_page_url(response)

        if response.status_code == 400:
            unique_title = self._build_unique_title(triage_result)
            log_event(
                self.logger,
                "warning",
                "Confluence rejected the initial page title. Retrying with a unique suffix.",
                finding_id=triage_result.finding.finding_id,
                original_title=title,
                retry_title=unique_title,
                response_text=response.text[:500],
            )
            retry_payload = self._build_payload(unique_title, body)
            retry_response = self._post_page(retry_payload)
            if retry_response.ok:
                return self._extract_page_url(retry_response)

            raise RuntimeError(
                f"Confluence create failed after retry ({retry_response.status_code}): "
                f"{retry_response.text[:500]}"
            )

        raise RuntimeError(f"Confluence create failed ({response.status_code}): {response.text[:500]}")

    def _build_title(self, triage_result: TriageResult) -> str:
        risk = triage_result.policy_decision.final_risk_level.upper()
        finding = triage_result.finding
        return f"[{risk}] AWS Security Finding - {finding.finding_type} - {finding.finding_id}"

    def _build_unique_title(self, triage_result: TriageResult) -> str:
        base_title = self._build_title(triage_result)
        execution_part = (triage_result.execution_id or "run").split("-")[0]
        timestamp_raw = triage_result.processed_at or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        timestamp_part = timestamp_raw.replace("-", "").replace(":", "").replace("T", "-").replace("Z", "Z")
        return f"{base_title} - {timestamp_part}-{execution_part}"

    def _build_storage_html(self, triage_result: TriageResult) -> str:
        finding = triage_result.finding
        analysis = triage_result.llm_analysis
        decision = triage_result.policy_decision
        metadata = triage_result.ingestion_metadata
        raw_finding = html.escape(json.dumps(finding.raw_event, indent=2))

        sections = [
            "<h1>Executive Summary</h1>",
            f"<p>{html.escape(analysis.summary)}</p>",
            "<h1>Finding Details</h1>",
            (
                "<table>"
                f"<tr><td><strong>Source</strong></td><td>{html.escape(finding.source)}</td></tr>"
                f"<tr><td><strong>Severity</strong></td><td>{html.escape(decision.final_risk_level)}</td></tr>"
                f"<tr><td><strong>Title</strong></td><td>{html.escape(finding.title)}</td></tr>"
                f"<tr><td><strong>Finding Type</strong></td><td>{html.escape(finding.finding_type)}</td></tr>"
                f"<tr><td><strong>Resource</strong></td><td>{html.escape(finding.resource_type)}:{html.escape(finding.resource_id)}</td></tr>"
                f"<tr><td><strong>Environment</strong></td><td>{html.escape(finding.environment)}</td></tr>"
                "</table>"
            ),
            "<h1>Event Ingestion Metadata</h1>",
            (
                "<table>"
                f"<tr><td><strong>Event ID</strong></td><td>{html.escape(metadata.event_id if metadata else '')}</td></tr>"
                f"<tr><td><strong>Event Source</strong></td><td>{html.escape(metadata.source if metadata else 'unknown')}</td></tr>"
                f"<tr><td><strong>Detail Type</strong></td><td>{html.escape(metadata.detail_type if metadata else 'unknown')}</td></tr>"
                f"<tr><td><strong>Event Shape</strong></td><td>{html.escape(metadata.event_shape if metadata else 'unknown')}</td></tr>"
                f"<tr><td><strong>Account</strong></td><td>{html.escape(metadata.account if metadata else finding.account_id)}</td></tr>"
                f"<tr><td><strong>Region</strong></td><td>{html.escape(metadata.region if metadata else finding.region)}</td></tr>"
                f"<tr><td><strong>Event Time</strong></td><td>{html.escape(metadata.event_time if metadata else '')}</td></tr>"
                "</table>"
            ),
            "<h1>LLM Analysis</h1>",
            f"<p><strong>Confidence:</strong> {analysis.confidence:.2f}</p>",
            f"<p><strong>Rationale:</strong> {html.escape(analysis.rationale)}</p>",
            f"<p><strong>Indicators:</strong> {html.escape(', '.join(analysis.indicators) or 'none')}</p>",
            "<h1>Policy Decision</h1>",
            f"<p><strong>Decision:</strong> {html.escape(decision.decision)}</p>",
            f"<p><strong>Reason Codes:</strong> {html.escape(', '.join(decision.reason_codes) or 'none')}</p>",
            "<h1>Recommended Remediation</h1>",
            f"<p>{html.escape(decision.recommended_action)}</p>",
            "<h1>Raw Finding</h1>",
            f"<pre>{raw_finding}</pre>",
        ]
        return "".join(sections)

    def _build_payload(self, title: str, body: str) -> dict:
        payload = {
            "type": "page",
            "title": title,
            "space": {"key": self.space_key},
            "body": {
                "storage": {
                    "value": body,
                    "representation": "storage",
                }
            },
        }
        if self.parent_page_id:
            payload["ancestors"] = [{"id": str(self.parent_page_id)}]
        return payload

    def _post_page(self, payload: dict) -> requests.Response:
        return requests.post(
            self._build_api_url(),
            auth=(self.email, self.api_token),
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )

    def _extract_page_url(self, response: requests.Response) -> str:
        data = response.json()
        links = data.get("_links", {})
        base = links.get("base") or self.base_url
        webui = links.get("webui") or ""
        return f"{base}{webui}"

    def _build_api_url(self) -> str:
        if self.base_url.endswith("/wiki"):
            return f"{self.base_url}/rest/api/content"
        return f"{self.base_url}/wiki/rest/api/content"
