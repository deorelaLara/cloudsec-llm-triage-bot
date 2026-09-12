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


class FindingEnrichment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str | None = None
    in_cisa_kev: bool = False
    epss_score: float | None = None
    # "kev_epss" when threat intel was looked up, "none" when not applicable,
    # "unavailable" when the lookup failed and we degraded gracefully.
    source: str = "none"


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: NormalizedFinding
    llm_analysis: LLMAnalysis
    policy_decision: PolicyDecision
    ingestion_metadata: EventIngestionMetadata | None = None
    enrichment: FindingEnrichment | None = None
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


# --- Anadido por el MVP -------------------------------------------------------
# El sistema serverless promete detectar cuando el escaneo recurrente cambia de
# origen, de puerto o de recurso, pero no tiene ni inventario ni historico. Estos
# dos modelos son la salida de T2 y T3, y alimentan las dos reglas nuevas del motor
# de politica.


class ResourceContext(BaseModel):
    """Salida de T2: contexto de inventario de un recurso."""

    model_config = ConfigDict(extra="forbid")

    resource_id: str
    encontrado: bool = False
    environment: str = "unknown"
    tags: dict[str, str] = Field(default_factory=dict)
    expuesto_internet: bool = False
    criticidad: str = "unknown"


class PatternHistory(BaseModel):
    """Salida de T3: historial de un finding_type sobre un recurso."""

    model_config = ConfigDict(extra="forbid")

    finding_type: str
    resource_id: str
    ventana_dias: int
    ocurrencias: int = 0
    puertos_observados: list[int] = Field(default_factory=list)
    origenes_observados: list[str] = Field(default_factory=list)
    ultima_vez: str | None = None
    patron_recurrente: bool = False
    variacion_detectada: bool = False
    variaciones: list[str] = Field(default_factory=list)


class FueraDeAlcance(BaseModel):
    """Evento que no es un finding de GuardDuty ni de Inspector.

    No se llama al modelo y no se escribe en `decision_triage`.
    """

    model_config = ConfigDict(extra="forbid")

    decision: Literal["out_of_scope"] = "out_of_scope"
    motivo: str
    fuente_evento: str = "unknown"


class CasoTriage(BaseModel):
    """Contenedor de un triage completo.

    `TriageResult` viene del sistema serverless y declara `extra="forbid"`, asi que
    no puede transportar el contexto de recurso, el historial de patron, el numero
    de llamadas al modelo ni el id de registro. En lugar de deformar el contrato
    copiado, lo envolvemos.
    """

    model_config = ConfigDict(extra="forbid")

    resultado: TriageResult | None = None
    fuera_de_alcance: FueraDeAlcance | None = None
    resource_context: ResourceContext | None = None
    pattern_history: PatternHistory | None = None
    llamadas_al_modelo: int = 0
    registro_id: int | None = None
