"""
Test script for Phase 3 aggregator (cross-source scoring).

Uses synthetic IOCResult fixtures (no API calls, no normalizers).
Tests aggregation logic and the aggregated STIX indicator conversion.

Usage:
    python test_aggregator.py
"""

import json

from aggregator.aggregator import aggregate, AggregatedResult
from normalizers.schema import IOCResult
from stix.stix_converter import to_stix_indicator_aggregated

# ── Fixtures ──────────────────────────────────────────────────────────

# IP flagged by all three sources
IP_MALICIOUS_ALL = [
    IOCResult(source="otx", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=60, tags=["c2"]),
    IOCResult(source="virustotal", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=70, tags=["malware"]),
    IOCResult(source="abuseipdb", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=85, tags=["port_scan"]),
]

# Two flag malicious, one benign — should be "malicious"
IP_TWO_MALICIOUS_ONE_BENIGN = [
    IOCResult(source="otx", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=60, tags=["c2"]),
    IOCResult(source="virustotal", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=70, tags=["malware"]),
    IOCResult(source="abuseipdb", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=0, tags=["whitelisted"]),
]

# Exactly one source flags malicious — should be "suspicious"
IP_ONE_MALICIOUS_TWO_BENIGN = [
    IOCResult(source="otx", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=60, tags=["c2"]),
    IOCResult(source="virustotal", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=None, tags=["benign"]),
    IOCResult(source="abuseipdb", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=0, tags=["whitelisted"]),
]

# All sources benign — should be "benign"
IP_ALL_BENIGN = [
    IOCResult(source="otx", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=None, tags=["benign"]),
    IOCResult(source="virustotal", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=None, tags=["searchengine"]),
    IOCResult(source="abuseipdb", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=0, tags=["whitelisted"]),
]

# All sources failed — should be "unknown"
IP_ALL_FAILED = [
    IOCResult(source="otx", ioc="1.1.1.1", ioc_type="ip", malicious=None, confidence=None, query_success=False, error="API key missing"),
    IOCResult(source="virustotal", ioc="1.1.1.1", ioc_type="ip", malicious=None, confidence=None, query_success=False, error="Rate limited"),
    IOCResult(source="abuseipdb", ioc="1.1.1.1", ioc_type="ip", malicious=None, confidence=None, query_success=False, error="Not found"),
]

# Some sources failed, others disagree — mixed scenario
IP_MIXED_WITH_FAILURES = [
    IOCResult(source="otx", ioc="1.1.1.1", ioc_type="ip", malicious=True, confidence=60, tags=["c2"]),
    IOCResult(source="virustotal", ioc="1.1.1.1", ioc_type="ip", malicious=None, confidence=None, query_success=False, error="Timeout"),
    IOCResult(source="abuseipdb", ioc="1.1.1.1", ioc_type="ip", malicious=False, confidence=0, tags=["whitelisted"]),
]

# Empty list
EMPTY: list[IOCResult] = []


def assert_eq(label: str, actual, expected) -> None:
    status = "PASS" if actual == expected else "FAIL"
    if status == "FAIL":
        print(f"  [{status}] {label}: got {actual!r}, expected {expected!r}")
    else:
        print(f"  [{status}] {label}")


def test_aggregation() -> None:
    print(">>> AGGREGATION LOGIC <<<")

    # 1. All malicious → "malicious"
    agg = aggregate(IP_MALICIOUS_ALL)
    assert_eq("All malicious -> malicious", agg.final_verdict, "malicious")
    assert_eq("Sources flagged (3)", len(agg.sources_flagged_malicious), 3)
    assert_eq("Confidence avg ~71.67", round(agg.aggregate_confidence, 1), round((60 + 70 + 85) / 3))
    assert_eq("Tags deduped", sorted(agg.all_tags), ["c2", "malware", "port_scan"])
    assert_eq("IOC preserved", agg.ioc, "1.1.1.1")
    assert_eq("Type preserved", agg.ioc_type, "ip")

    # 2. Two malicious → "malicious"
    agg = aggregate(IP_TWO_MALICIOUS_ONE_BENIGN)
    assert_eq("2 malicious, 1 benign -> malicious", agg.final_verdict, "malicious")
    assert_eq("Sources flagged (2)", agg.sources_flagged_malicious, ["otx", "virustotal"])
    assert_eq("Confidence avg", agg.aggregate_confidence, round((60 + 70 + 0) / 3))

    # 3. One malicious → "suspicious"
    #    OTX conf=60, AbuseIPDB conf=0, VT conf=None → avg of [60, 0] = 30
    agg = aggregate(IP_ONE_MALICIOUS_TWO_BENIGN)
    assert_eq("1 malicious, 2 benign -> suspicious", agg.final_verdict, "suspicious")
    assert_eq("Sources flagged (1)", agg.sources_flagged_malicious, ["otx"])
    assert_eq("Confidence avg (60+0)/2", agg.aggregate_confidence, 30)

    # 4. All benign → "benign"
    agg = aggregate(IP_ALL_BENIGN)
    assert_eq("All benign -> benign", agg.final_verdict, "benign")
    assert_eq("Sources flagged (0)", len(agg.sources_flagged_malicious), 0)
    # Only abuseipdb has confidence=0, others have None
    assert_eq("Confidence (only abuseipdb has value)", agg.aggregate_confidence, 0)

    # 5. All failed → "unknown"
    agg = aggregate(IP_ALL_FAILED)
    assert_eq("All failed -> unknown", agg.final_verdict, "unknown")
    assert_eq("Sources flagged (0)", len(agg.sources_flagged_malicious), 0)
    assert_eq("Confidence 0", agg.aggregate_confidence, 0)
    # Failed sources are still listed in sources_checked
    assert_eq("All 3 sources checked", len(agg.sources_checked), 3)
    # Verify failed sources excluded from confidence (none had confidence)
    assert_eq("No confidence values", agg.aggregate_confidence, 0)

    # 6. Mixed with failures — OTX says malicious, AbuseIPDB says benign,
    #    VT failed → 1 malicious out of 2 voting → "suspicious"
    agg = aggregate(IP_MIXED_WITH_FAILURES)
    assert_eq("Mixed (1 mal+1 ben+1 fail) -> suspicious", agg.final_verdict, "suspicious")
    assert_eq("Sources flagged (1)", agg.sources_flagged_malicious, ["otx"])
    assert_eq("Sources checked (all 3)", len(agg.sources_checked), 3)

    # 7. Empty list
    agg = aggregate(EMPTY)
    assert_eq("Empty -> unknown", agg.final_verdict, "unknown")
    assert_eq("Empty -> confidence 0", agg.aggregate_confidence, 0)
    assert_eq("Empty -> no sources", len(agg.sources_checked), 0)

    print("\n>>> AGGREGATED STIX INDICATOR <<<")

    # Malicious → STIX indicator with malicious-activity
    agg = aggregate(IP_MALICIOUS_ALL)
    indicator = to_stix_indicator_aggregated(agg)
    assert_eq("All malicious -> indicator is not None", indicator is not None, True)
    if indicator:
        assert_eq("indicator_types[0]", indicator.indicator_types[0], "malicious-activity")
        assert_eq("confidence", indicator.confidence, round((60 + 70 + 85) / 3))
        assert_eq("pattern is ipv4-addr", "ipv4-addr" in indicator.pattern, True)
        assert_eq("pattern contains 1.1.1.1", "1.1.1.1" in indicator.pattern, True)

    # Suspicious → STIX indicator with anomalous-activity
    agg = aggregate(IP_ONE_MALICIOUS_TWO_BENIGN)
    indicator = to_stix_indicator_aggregated(agg)
    assert_eq("Suspicious -> indicator is not None", indicator is not None, True)
    if indicator:
        assert_eq("indicator_types[0]", indicator.indicator_types[0], "anomalous-activity")

    # Unknown → None (no indicator)
    agg = aggregate(IP_ALL_FAILED)
    indicator = to_stix_indicator_aggregated(agg)
    assert_eq("Unknown -> indicator is None", indicator is None, True)

    print("\nDone.")


if __name__ == "__main__":
    test_aggregation()
