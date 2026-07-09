"""
Test script for STIX 2.1 conversion.

Produces IOCResult fixtures directly (no raw API dicts anywhere in this
file), converts them via to_stix_bundle(), and writes the serialized
STIX 2.1 Bundle to output/sample_bundle.json.

Usage:
    python test_stix.py
"""

import json
import os

from normalizers.schema import IOCResult
from stix.stix_converter import to_stix_bundle


def main() -> None:
    results: list[IOCResult] = [
        # ── OTX ──
        IOCResult(
            source="otx",
            ioc="103.235.46.39",
            ioc_type="ip",
            malicious=True,
            confidence=None,
            raw_score=3.0,
            tags=["c2", "mirai", "malware", "scanner", "bruteforce"],
            first_seen="2025-01-15T10:30:00Z",
            last_seen="2025-06-22T16:30:00Z",
            source_url="https://otx.alienvault.com/indicator/ip/103.235.46.39",
            query_success=True,
            error=None,
        ),
        IOCResult(
            source="otx",
            ioc="1.1.1.1",
            ioc_type="ip",
            malicious=False,
            confidence=None,
            raw_score=0.0,
            tags=[],
            first_seen=None,
            last_seen=None,
            source_url="https://otx.alienvault.com/indicator/ip/1.1.1.1",
            query_success=True,
            error=None,
        ),
        # ── VirusTotal ──
        IOCResult(
            source="virustotal",
            ioc="44d88612fea8a8f36de82e1278abb02f",
            ioc_type="hash",
            malicious=True,
            confidence=None,
            raw_score=0.2143,
            tags=["peexe", "trojan", "executable"],
            first_seen="2023-11-14T22:13:20Z",
            last_seen="2024-05-06T12:53:20Z",
            source_url=(
                "https://www.virustotal.com/gui/file/"
                "44d88612fea8a8f36de82e1278abb02f/detection"
            ),
            query_success=True,
            error=None,
        ),
        IOCResult(
            source="virustotal",
            ioc="google.com",
            ioc_type="domain",
            malicious=False,
            confidence=None,
            raw_score=0.0,
            tags=["searchengine"],
            first_seen=None,
            last_seen="2024-05-06T12:53:20Z",
            source_url="https://www.virustotal.com/gui/domain/google.com/detection",
            query_success=True,
            error=None,
        ),
        # ── AbuseIPDB, malicious (confidence 85) ──
        IOCResult(
            source="abuseipdb",
            ioc="103.235.46.39",
            ioc_type="ip",
            malicious=True,
            confidence=85,
            raw_score=85.0,
            tags=[
                "port_scan",
                "brute_force",
                "ssh_bruteforce",
            ],
            first_seen=None,
            last_seen="2025-06-22T16:30:00Z",
            source_url="https://www.abuseipdb.com/check/103.235.46.39",
            query_success=True,
            error=None,
        ),
        # ── AbuseIPDB, benign (confidence 0) ──
        # Phase 2 marks this as malicious=False (0 < 50 threshold).
        # That is a valid verdict, so it IS included as an Indicator
        # with indicator_types=['benign'] and confidence=0.
        IOCResult(
            source="abuseipdb",
            ioc="1.1.1.1",
            ioc_type="ip",
            malicious=False,
            confidence=0,
            raw_score=0.0,
            tags=["whitelisted", "domain:cloudflare.com"],
            first_seen=None,
            last_seen="2025-06-20T10:00:00Z",
            source_url="https://www.abuseipdb.com/check/1.1.1.1",
            query_success=True,
            error=None,
        ),
        # ── Should be EXCLUDED (query_success=False) ──
        IOCResult(
            source="abuseipdb",
            ioc="10.0.0.1",
            ioc_type="ip",
            malicious=None,
            confidence=None,
            raw_score=None,
            tags=[],
            first_seen=None,
            last_seen=None,
            source_url=None,
            query_success=False,
            error="IOC not found in AbuseIPDB database.",
        ),
        # ── Should be EXCLUDED (malicious=None) ──
        IOCResult(
            source="otx",
            ioc="192.0.2.1",
            ioc_type="ip",
            malicious=None,
            confidence=None,
            raw_score=None,
            tags=[],
            first_seen=None,
            last_seen=None,
            source_url=None,
            query_success=True,
            error="No verdict from OTX.",
        ),
    ]

    bundle = to_stix_bundle(results)

    # Write to output file
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "sample_bundle.json")

    json_output = bundle.serialize(pretty=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_output)

    # Print summary to stdout
    parsed = json.loads(json_output)
    n_objects = len(parsed["objects"])
    n_indicators = sum(1 for o in parsed["objects"] if o["type"] == "indicator")
    n_skipped = len(results) - n_indicators
    print(f"Bundle written to: {output_path}")
    print(f"Bundle contains: {n_objects} objects ({n_indicators} indicators, 1 identity)")
    print(f"Skipped (no verdict): {n_skipped}")
    print()

    # Print the full bundle to stdout so the user can verify
    print(json_output)


if __name__ == "__main__":
    main()