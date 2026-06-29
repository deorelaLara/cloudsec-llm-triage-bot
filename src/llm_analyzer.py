from __future__ import annotations

import json
import os
from typing import Any

import boto3
from pydantic import ValidationError

from logger import log_event
from models import IntegrationSecretBundle, LLMAnalysis, NormalizedFinding


# The LLM must answer by *calling* this tool. Its input schema is the LLMAnalysis
# contract, so the provider validates the shape for us and we read structured data
# directly — no more parsing JSON out of free text. See REVIEW.md section C3.
TRIAGE_TOOL_NAME = "submit_triage"


class LLMAnalyzer:
    def __init__(
        self,
        provider: str,
        region_name: str,
        logger,
        openai_model: str | None = None,
        openai_base_url: str | None = None,
        bedrock_model_id: str | None = None,
    ) -> None:
        self.provider = (provider or "openai").lower()
        self.region_name = region_name
        self.logger = logger
        self.openai_model = openai_model or os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        self.openai_base_url = openai_base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.bedrock_model_id = bedrock_model_id or os.getenv(
            "BEDROCK_MODEL_ID",
            "au.anthropic.claude-sonnet-4-6",
        )

    def analyze(self, finding: NormalizedFinding, secrets: IntegrationSecretBundle) -> LLMAnalysis:
        prompt = self._build_prompt(finding)

        try:
            if self.provider == "bedrock":
                payload = self._invoke_bedrock(prompt)
            elif self.provider == "openai":
                payload = self._invoke_openai(prompt, secrets.openai_api_key or "")
            else:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")

            return LLMAnalysis.model_validate(payload)
        except (RuntimeError, ValueError, ValidationError, KeyError, json.JSONDecodeError) as exc:
            log_event(
                self.logger,
                "error",
                "LLM analysis failed. Falling back to safe defaults.",
                finding_id=finding.finding_id,
                provider=self.provider,
                error=str(exc),
            )
            return self._safe_default(finding, str(exc))

    def _tool_input_schema(self) -> dict[str, Any]:
        # Derived from the Pydantic model so the tool contract and the validation
        # contract can never drift apart.
        return LLMAnalysis.model_json_schema()

    def _invoke_openai(self, prompt: str, api_key: str) -> dict[str, Any]:
        if not api_key:
            raise RuntimeError("Missing OpenAI API key in secret payload.")

        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=self.openai_base_url)
        response = client.chat.completions.create(
            model=self.openai_model,
            temperature=0.1,
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": TRIAGE_TOOL_NAME,
                        "description": "Return the structured triage analysis for the security finding.",
                        "parameters": self._tool_input_schema(),
                    },
                }
            ],
            tool_choice={"type": "function", "function": {"name": TRIAGE_TOOL_NAME}},
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cloud security triage assistant. "
                        "Never recommend autonomous suppression of risky findings."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        )
        tool_calls = response.choices[0].message.tool_calls or []
        if not tool_calls:
            raise ValueError("OpenAI response did not include the submit_triage function call.")
        return json.loads(tool_calls[0].function.arguments)

    def _invoke_bedrock(self, prompt: str) -> dict[str, Any]:
        client = boto3.client("bedrock-runtime", region_name=self.region_name)
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 900,
            "temperature": 0.1,
            "tools": [
                {
                    "name": TRIAGE_TOOL_NAME,
                    "description": "Return the structured triage analysis for the security finding.",
                    "input_schema": self._tool_input_schema(),
                }
            ],
            "tool_choice": {"type": "tool", "name": TRIAGE_TOOL_NAME},
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": prompt}],
                }
            ],
        }
        response = client.invoke_model(
            modelId=self.bedrock_model_id,
            body=json.dumps(payload),
            contentType="application/json",
            accept="application/json",
        )
        body = json.loads(response["body"].read())
        for block in body.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == TRIAGE_TOOL_NAME:
                return block["input"]
        raise ValueError("Bedrock response did not include the submit_triage tool call.")

    def _build_prompt(self, finding: NormalizedFinding) -> str:
        finding_json = json.dumps(finding.model_dump(mode="json"), indent=2)
        return f"""
Analyze the following AWS security finding and produce a risk recommendation.

Hard constraints:
- The LLM is advisory only.
- Do not recommend autonomous suppression unless the evidence strongly suggests a low-risk false positive.
- Be conservative when uncertainty exists.
- Report your analysis by calling the {TRIAGE_TOOL_NAME} tool. Do not answer in free text.

Finding:
{finding_json}
""".strip()

    def _safe_default(self, finding: NormalizedFinding, error_message: str) -> LLMAnalysis:
        fallback_risk = finding.severity if finding.severity in {"low", "medium", "high", "critical"} else "medium"
        return LLMAnalysis(
            summary="LLM analysis unavailable. Falling back to conservative triage.",
            risk_level=fallback_risk,
            confidence=0.0,
            rationale=f"Safe fallback path activated because the LLM analysis failed: {error_message}",
            indicators=[finding.finding_type, finding.resource_type],
            recommended_action="Escalate for manual review and do not suppress automatically.",
            suppression_candidate=False,
            finding_tags=[],
        )
