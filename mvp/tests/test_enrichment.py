from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import enrichment  # noqa: E402
from enrichment import enrich_finding, extract_cve_id  # noqa: E402
from logger import get_logger  # noqa: E402
from models import NormalizedFinding  # noqa: E402


def setup_function() -> None:
    # Reset the module-level KEV cache so tests don't leak state into each other.
    enrichment._kev_cache = None


def _inspector_finding(cve: str = "CVE-2021-44228") -> NormalizedFinding:
    return NormalizedFinding(
        finding_id="f1",
        source="inspector",
        account_id="123456789012",
        region="us-east-1",
        severity="critical",
        title=f"Critical vuln {cve}",
        description="desc",
        finding_type="Software and Configuration Checks/Package Vulnerability",
        resource_id="i-1",
        resource_type="AWS_EC2_INSTANCE",
        environment="production",
        raw_event={"detail": {"packageVulnerabilityDetails": {"vulnerabilityId": cve}}},
    )


def _guardduty_finding() -> NormalizedFinding:
    return NormalizedFinding(
        finding_id="f2",
        source="guardduty",
        account_id="123456789012",
        region="us-east-1",
        severity="low",
        title="probe",
        description="d",
        finding_type="Recon:EC2/PortProbeUnprotectedPort",
        resource_id="i-2",
        resource_type="Instance",
        environment="dev",
        raw_event={"detail": {}},
    )


def _fake_get(kev_payload: dict | None = None, epss_payload: dict | None = None):
    def _get(url, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if "known_exploited" in url:
            resp.json.return_value = kev_payload or {"vulnerabilities": []}
        else:
            resp.json.return_value = epss_payload or {"data": []}
        return resp

    return _get


def test_extract_cve_id_from_inspector_raw_event() -> None:
    assert extract_cve_id(_inspector_finding("CVE-2026-12345")) == "CVE-2026-12345"


def test_guardduty_finding_is_not_enriched() -> None:
    result = enrich_finding(_guardduty_finding(), get_logger("test"))

    assert result.source == "none"
    assert result.in_cisa_kev is False


def test_kev_hit_and_epss_parsed() -> None:
    kev = {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
    epss = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97"}]}
    with patch("enrichment.requests.get", side_effect=_fake_get(kev, epss)):
        result = enrich_finding(_inspector_finding("CVE-2021-44228"), get_logger("test"))

    assert result.in_cisa_kev is True
    assert result.epss_score == 0.97
    assert result.source == "kev_epss"


def test_enrichment_outage_degrades_gracefully() -> None:
    with patch("enrichment.requests.get", side_effect=requests.RequestException("feed down")):
        result = enrich_finding(_inspector_finding(), get_logger("test"))

    # Fail-open: never blocks triage; just marks the lookup unavailable.
    assert result.source == "unavailable"
    assert result.in_cisa_kev is False
