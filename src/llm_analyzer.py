from __future__ import annotations

import json
import os
from typing import Any

import boto3
from pydantic import ValidationError

from logger import log_event
from models import IntegrationSecretBundle, LLMAnalysis, NormalizedFinding


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
                raw_content = self._invoke_bedrock(prompt)
            elif self.provider == "openai":
                raw_content = self._invoke_openai(prompt, secrets.openai_api_key or "")
            else:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")

            payload = self._extract_json_document(raw_content)
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

    def _invoke_openai(self, prompt: str, api_key: str) -> str:
        if not api_key:
            raise RuntimeError("Missing OpenAI API key in secret payload.")

        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=self.openai_base_url)
        response = client.chat.completions.create(
            model=self.openai_model,
            temperature=0.1,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cloud security triage assistant. "
                        "Return only valid JSON and never recommend autonomous suppression of risky findings."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content or "{}"

    def _invoke_bedrock(self, prompt: str) -> str:
        client = boto3.client("bedrock-runtime", region_name=self.region_name)
        payload = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 900,
            "temperature": 0.1,
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
        return body["content"][0]["text"]

    def _build_prompt(self, finding: NormalizedFinding) -> str:
        finding_json = json.dumps(finding.model_dump(mode="json"), indent=2)
        return f"""
Analyze the following AWS security finding and produce a risk recommendation as valid JSON.

Hard constraints:
- The LLM is advisory only.
- Do not recommend autonomous suppression unless the evidence strongly suggests a low-risk false positive.
- Be conservative when uncertainty exists.
- Return only JSON with the exact schema below.

JSON schema:
{{
  "summary": "short executive summary",
  "risk_level": "low|medium|high|critical",
  "confidence": 0.0,
  "rationale": "detailed reasoning",
  "indicators": ["indicator 1", "indicator 2"],
  "recommended_action": "actionable recommendation",
  "suppression_candidate": false,
  "finding_tags": ["credential compromise", "public exposure"]
}}

Finding:
{finding_json}
""".strip()

    def _extract_json_document(self, raw_content: str) -> dict[str, Any]:
        candidate = raw_content.strip()
        if candidate.startswith("```"):
            candidate = candidate.strip("`")
            candidate = candidate.replace("json\n", "", 1).strip()

        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("The LLM response does not contain a JSON object.")

        return json.loads(candidate[start : end + 1])

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
