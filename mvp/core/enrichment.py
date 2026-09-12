from __future__ import annotations

import re

import requests

from logger import log_event
from models import FindingEnrichment, NormalizedFinding


# Deterministic threat-intel enrichment (REVIEW.md C1). This feeds *hard* signals
# into the policy engine — most importantly whether a CVE is actively exploited
# (CISA KEV) — rather than relying on the LLM's prose. Enrichment is additive and
# fail-open: if the feeds are unreachable we degrade to "unavailable" and let the
# LLM + policy engine run as before, never blocking triage on an enrichment outage.

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Module-level cache: the KEV catalog updates roughly daily, so caching it for the
# warm-container lifetime avoids re-downloading ~1MB on every invocation.
_kev_cache: set[str] | None = None


def extract_cve_id(finding: NormalizedFinding) -> str | None:
    detail = finding.raw_event.get("detail", finding.raw_event)
    pkg = detail.get("packageVulnerabilityDetails", {}) if isinstance(detail, dict) else {}
    candidate = pkg.get("vulnerabilityId") or finding.finding_type or ""

    match = _CVE_RE.search(str(candidate)) or _CVE_RE.search(f"{finding.title} {finding.description}")
    return match.group(0).upper() if match else None


def enrich_finding(finding: NormalizedFinding, logger, timeout: float = 5.0) -> FindingEnrichment:
    # Only Inspector findings carry a CVE; GuardDuty findings are behavioral.
    if finding.source != "inspector":
        return FindingEnrichment(source="none")

    cve = extract_cve_id(finding)
    if not cve:
        return FindingEnrichment(source="none")

    try:
        in_kev = _is_in_kev(cve, timeout)
        epss = _epss_score(cve, timeout)
        return FindingEnrichment(cve_id=cve, in_cisa_kev=in_kev, epss_score=epss, source="kev_epss")
    except requests.RequestException as exc:
        log_event(
            logger,
            "warning",
            "Threat-intel enrichment unavailable; continuing without it.",
            cve=cve,
            error=str(exc),
        )
        return FindingEnrichment(cve_id=cve, source="unavailable")


def _load_kev_set(timeout: float) -> set[str]:
    global _kev_cache
    if _kev_cache is None:
        response = requests.get(CISA_KEV_URL, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        _kev_cache = {
            str(v.get("cveID", "")).upper()
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
    return _kev_cache


def _is_in_kev(cve: str, timeout: float) -> bool:
    return cve.upper() in _load_kev_set(timeout)


def _epss_score(cve: str, timeout: float) -> float | None:
    response = requests.get(EPSS_API_URL, params={"cve": cve}, timeout=timeout)
    response.raise_for_status()
    data = response.json().get("data", [])
    if data and data[0].get("epss") is not None:
        return float(data[0]["epss"])
    return None
