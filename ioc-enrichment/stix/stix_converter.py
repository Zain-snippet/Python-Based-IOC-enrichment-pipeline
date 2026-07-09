"""
STIX 2.1 converter — maps IOCResult objects to STIX Indicator SDOs.

Each IOCResult is converted independently into a STIX 2.1 Indicator.
No cross-source merging — three results for the same IOC produce three
separate Indicator objects, each referencing a shared tool Identity.
"""

from datetime import datetime, timezone
from typing import Optional

import stix2

from aggregator.aggregator import AggregatedResult
from normalizers.schema import IOCResult

# Shared Identity SDO representing this enrichment tool.
TOOL_IDENTITY = stix2.Identity(
    name="IOC-Enrichment-Pipeline",
    identity_class="system",
    description="Automated multi-source IOC enrichment and STIX 2.1 export tool",
)


def _detect_ip_version(ioc: str) -> str:
    return "ipv6-addr" if ":" in ioc else "ipv4-addr"


def _detect_hash_type(ioc: str) -> Optional[str]:
    length = len(ioc)
    if length == 32:
        return "MD5"
    if length == 40:
        return "SHA-1"
    if length == 64:
        return "SHA-256"
    return None


def _build_pattern(ioc: str, ioc_type: str) -> str:
    if ioc_type == "ip":
        return f"[{_detect_ip_version(ioc)}:value = '{ioc}']"

    if ioc_type == "domain":
        return f"[domain-name:value = '{ioc}']"

    if ioc_type == "url":
        return f"[url:value = '{ioc}']"

    if ioc_type == "hash":
        algo = _detect_hash_type(ioc)
        if algo is None:
            raise ValueError(
                f"Cannot determine hash type for '{ioc}' "
                f"(length {len(ioc)}, expected 32/40/64 hex chars)"
            )
        return f"[file:hashes.'{algo}' = '{ioc}']"

    raise ValueError(f"Unsupported ioc_type '{ioc_type}'")


def _fmt_ts(iso_str: Optional[str]) -> Optional[str]:
    if not iso_str:
        return None
    s = iso_str.strip().replace("+00:00", "Z").replace("-00:00", "Z")
    if s.endswith("Z"):
        return s
    if "+" in s[10:] or "-" in s[10:]:
        return s
    return s + "Z"


def to_stix_indicator(
    result: IOCResult,
    identity: stix2.Identity = TOOL_IDENTITY,
) -> Optional[stix2.Indicator]:
    """Convert an IOCResult into a stix2 Indicator SDO, or None if no
    actionable verdict exists (query_success=False or malicious=None)."""
    if not result.query_success or result.malicious is None:
        return None

    try:
        pattern = _build_pattern(result.ioc, result.ioc_type)
    except ValueError:
        return None

    indicator_type = "malicious-activity" if result.malicious else "benign"
    display_ioc = (result.ioc[:48] + "...") if len(result.ioc) > 48 else result.ioc
    name = f"{display_ioc} ({result.ioc_type}) - {result.source}"

    description_parts = [f"Source: {result.source}"]
    if result.source_url:
        description_parts.append(f"Report: {result.source_url}")
    if result.raw_score is not None:
        description_parts.append(f"Raw score: {result.raw_score}")
    description = "; ".join(description_parts)

    valid_from = _fmt_ts(result.first_seen) or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    valid_until = _fmt_ts(result.last_seen)

    kwargs: dict = {
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "created_by_ref": str(identity.id),
        "valid_from": valid_from,
        "indicator_types": [indicator_type],
        "labels": list(result.tags),
    }

    if result.confidence is not None:
        kwargs["confidence"] = result.confidence
    if valid_until is not None and valid_until > valid_from:
        kwargs["valid_until"] = valid_until

    return stix2.Indicator(**kwargs)


def to_stix_indicator_aggregated(
    agg: AggregatedResult,
    identity: stix2.Identity = TOOL_IDENTITY,
) -> Optional[stix2.Indicator]:
    """Convert an AggregatedResult into a single stix2 Indicator SDO.

    Produces one merged Indicator per IOC (not one per source).
    Returns None if final_verdict is "unknown" (no actionable data).
    """
    if agg.final_verdict == "unknown":
        return None

    try:
        pattern = _build_pattern(agg.ioc, agg.ioc_type)
    except ValueError:
        return None

    verdict_to_stix_type = {
        "malicious": "malicious-activity",
        "suspicious": "anomalous-activity",
        "benign": "benign",
    }
    indicator_type = verdict_to_stix_type.get(agg.final_verdict, "unknown")

    display_ioc = (agg.ioc[:48] + "...") if len(agg.ioc) > 48 else agg.ioc
    name = f"{display_ioc} ({agg.ioc_type}) - aggregated"

    flagged = ", ".join(agg.sources_flagged_malicious) or "none"
    checked = ", ".join(agg.sources_checked)
    description = (
        f"Aggregated verdict: {agg.final_verdict} "
        f"(confidence: {agg.aggregate_confidence}/100). "
        f"Sources checked: {checked}. "
        f"Sources flagging malicious: {flagged}."
    )

    valid_from = None
    valid_until = None
    for r in agg.individual_results:
        fs = _fmt_ts(r.first_seen)
        lu = _fmt_ts(r.last_seen)
        if fs and (valid_from is None or fs < valid_from):
            valid_from = fs
        if lu and (valid_until is None or lu > valid_until):
            valid_until = lu

    if valid_from is None:
        valid_from = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    kwargs: dict = {
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "created_by_ref": str(identity.id),
        "valid_from": valid_from,
        "indicator_types": [indicator_type],
        "labels": list(agg.all_tags),
        "confidence": agg.aggregate_confidence,
    }

    if valid_until is not None and valid_until > valid_from:
        kwargs["valid_until"] = valid_until

    return stix2.Indicator(**kwargs)


def to_stix_bundle(
    results: list[IOCResult],
    identity: stix2.Identity = TOOL_IDENTITY,
) -> stix2.Bundle:
    """Convert a list of IOCResult objects into a single STIX 2.1 Bundle.

    The shared Identity is included first, followed by one Indicator per
    valid IOCResult. Results without a verdict are silently excluded.
    """
    objects: list = [identity]

    for result in results:
        indicator = to_stix_indicator(result, identity)
        if indicator is not None:
            objects.append(indicator)

    return stix2.Bundle(*objects)