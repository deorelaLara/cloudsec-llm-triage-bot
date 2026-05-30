from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from finding_normalizer import inspect_event_shape, normalize_finding_event


SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


def _load_sample(name: str) -> dict:
    return json.loads((SAMPLES_DIR / name).read_text())


def test_normalize_guardduty_finding() -> None:
    sample = _load_sample("guardduty_low_port_probe_dev.json")
    normalized = normalize_finding_event(sample)

    assert normalized.source == "guardduty"
    assert normalized.severity == "low"
    assert normalized.resource_id == "i-0devportprobe12345"
    assert normalized.environment == "dev"
    assert normalized.finding_type == "Recon:EC2/PortProbeUnprotectedPort"


def test_normalize_inspector_finding() -> None:
    sample = _load_sample("inspector_critical_cve.json")
    normalized = normalize_finding_event(sample)

    assert normalized.source == "inspector"
    assert normalized.severity == "critical"
    assert normalized.resource_type == "AWS_EC2_INSTANCE"
    assert normalized.environment == "production"
    assert normalized.finding_id.startswith("arn:aws:inspector2")


def test_classify_guardduty_eventbridge_envelope() -> None:
    sample = _load_sample("guardduty_low_port_probe_dev.json")
    metadata = inspect_event_shape(sample)

    assert metadata.event_shape == "eventbridge_guardduty_finding"
    assert metadata.has_eventbridge_envelope is True
    assert metadata.source == "aws.guardduty"
    assert metadata.detail_type == "GuardDuty Finding"


def test_classify_inspector_eventbridge_envelope() -> None:
    sample = _load_sample("inspector_medium_dev.json")
    metadata = inspect_event_shape(sample)

    assert metadata.event_shape == "eventbridge_inspector_finding"
    assert metadata.has_eventbridge_envelope is True
    assert metadata.source == "aws.inspector2"
    assert metadata.detail_type == "Inspector2 Finding"
