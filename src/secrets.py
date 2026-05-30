from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from logger import log_event
from models import IntegrationSecretBundle


def load_integration_secrets(secret_name: str, region_name: str, logger) -> IntegrationSecretBundle:
    client = boto3.client("secretsmanager", region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as exc:
        log_event(
            logger,
            "error",
            "Unable to load integration secret from Secrets Manager.",
            secret_name=secret_name,
            error=str(exc),
        )
        raise RuntimeError(f"Unable to read secret {secret_name}") from exc

    secret_string = response.get("SecretString", "{}")
    try:
        payload = json.loads(secret_string)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Secret {secret_name} does not contain valid JSON.") from exc

    return IntegrationSecretBundle.model_validate(payload)
