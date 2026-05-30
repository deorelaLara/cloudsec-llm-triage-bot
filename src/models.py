from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


RiskLevel = Literal["low", "medium", "high", "critical", "unknown"]
DecisionType = Literal["alert_and_document", "manual_review", "candidate_for_suppression"]
EventShape = Literal[
    "eventbridge_guardduty_finding",
    "eventbridge_inspector_finding",
    "direct_guardduty_payload",
    "direct_inspector_payload",
    "unknown",
]


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    source: Literal["guardduty", "inspector"]
    account_id: str
    region: str
    severity: RiskLevel
    title: str
    description: str
    finding_type: str
    resource_id: str
    resource_type: str
    environment: str = "unknown"
    raw_event: dict[str, Any]

    @field_validator("environment")
    @classmethod
    def normalize_environment(cls, value: str) -> str:
        normalized = (value or "unknown").strip().lower()
        aliases = {"prod": "production", "prd": "production", "sbx": "sandbox"}
        return aliases.get(normalized, normalized)


class LLMAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    indicators: list[str] = Field(default_factory=list)
    recommended_action: str
    suppression_candidate: bool = False
    finding_tags: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: DecisionType
    candidate_for_suppression: bool = False
    final_risk_level: Literal["low", "medium", "high", "critical"]
    reason_codes: list[str] = Field(default_factory=list)
    recommended_action: str


class EventIngestionMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = ""
    source: str = "unknown"
    detail_type: str = "unknown"
    account: str = "unknown"
    region: str = "unknown"
    event_time: str = ""
    event_shape: EventShape = "unknown"
    has_eventbridge_envelope: bool = False


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: NormalizedFinding
    llm_analysis: LLMAnalysis
    policy_decision: PolicyDecision
    ingestion_metadata: EventIngestionMetadata | None = None
    execution_id: str | None = None
    processed_at: str | None = None
    confluence_page_url: str | None = None
    slack_notification_sent: bool = False
    errors: list[str] = Field(default_factory=list)


class IntegrationSecretBundle(BaseModel):
    model_config = ConfigDict(extra="ignore")

    openai_api_key: str | None = ""
    slack_webhook_url: str | None = ""
    confluence_base_url: str | None = ""
    confluence_email: str | None = ""
    confluence_api_token: str | None = ""
