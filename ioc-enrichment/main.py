#!/usr/bin/env python3
"""
Interactive IOC Enrichment Pipeline

Prompts the user for IOC values and routes them through connectors,
normalizers, and STIX converter into a single STIX 2.1 bundle.
"""

import ipaddress
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

_script_dir = os.path.dirname(os.path.abspath(__file__))
_ioc_enrichment_dir = os.path.join(_script_dir, "ioc-enrichment")
if _ioc_enrichment_dir not in sys.path:
    sys.path.insert(0, _ioc_enrichment_dir)

import stix2

from aggregator.aggregator import aggregate, AggregatedResult
from connectors import abuseipdb as abuseipdb_connector
from connectors import otx as otx_connector
from connectors import virustotal as vt_connector
from connectors.exceptions import ConnectorError, UnsupportedIOCTypeError
from config import MissingAPIKeyError
from normalizers.abuseipdb_normalizer import normalize as abuseipdb_normalize
from normalizers.otx_normalizer import normalize as otx_normalize
from normalizers.schema import IOCResult
from normalizers.vt_normalizer import normalize as vt_normalize
from stix.stix_converter import to_stix_indicator_aggregated, TOOL_IDENTITY

SOURCES = {
    "otx": (otx_connector, otx_normalize),
    "vt": (vt_connector, vt_normalize),
    "abuseipdb": (abuseipdb_connector, abuseipdb_normalize),
}

_SOURCE_IOC_SUPPORT = {
    "otx": {"ip", "domain", "hash", "url"},
    "vt": {"ip", "domain", "hash", "url"},
    "abuseipdb": {"ip"},
}


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _validate_hash(h: str) -> bool:
    if not re.fullmatch(r"[0-9a-fA-F]+", h):
        return False
    return len(h) in (32, 40, 64)


def _sources_for(ioc_type: str) -> list[str]:
    return [s for s in SOURCES if ioc_type in _SOURCE_IOC_SUPPORT[s]]


def _enrich_source(
    ioc: str, ioc_type: str, source: str,
) -> tuple[IOCResult, list[str]]:
    """Call connector.query + normalize for a single source and return the
    IOCResult along with any diagnostic messages to be printed later.

    Every code path produces an IOCResult (never raises), so the caller
    always gets a result even on total failure.
    """
    messages: list[str] = []
    connector_module, normalize_fn = SOURCES[source]
    try:
        raw = connector_module.query(ioc, ioc_type)
        result = normalize_fn(raw, ioc, ioc_type)
    except (UnsupportedIOCTypeError, MissingAPIKeyError, ConnectorError) as e:
        messages.append(f"  [error] {source}: {e}")
        result = IOCResult(
            source=source,
            ioc=ioc,
            ioc_type=ioc_type,
            query_success=False,
            error=str(e),
        )
    except Exception as e:
        messages.append(f"  [error] {source}: unexpected failure: {e}")
        result = IOCResult(
            source=source,
            ioc=ioc,
            ioc_type=ioc_type,
            query_success=False,
            error=f"Unexpected error: {e}",
        )
    return result, messages


def enrich(ioc: str, ioc_type: str, sources: list[str]) -> list[IOCResult]:
    """Query each requested source in parallel (up to 3 workers) and
    normalize the result.

    Per-source error handling matches the original sequential logic exactly;
    messages are buffered per-thread and printed in source order after all
    threads finish so the terminal output remains readable.
    """
    # Pre-filter: skip unsupported sources before submitting any thread work.
    tasks: list[tuple[int, str]] = []
    for i, source in enumerate(sources):
        if ioc_type not in _SOURCE_IOC_SUPPORT[source]:
            print(
                f"  [skip] {source}: does not support ioc_type '{ioc_type}'",
                file=sys.stderr,
            )
            continue
        tasks.append((i, source))

    # Submit remaining sources to the thread pool.
    result_map: dict[int, tuple[IOCResult, list[str]]] = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_map: dict = {
            executor.submit(_enrich_source, ioc, ioc_type, s): idx
            for idx, s in tasks
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            result_map[idx] = future.result()

    # Reconstruct in original source order.
    results: list[IOCResult] = []
    for idx, _ in tasks:
        result, messages = result_map[idx]
        for m in messages:
            print(m, file=sys.stderr)
        results.append(result)
    return results


def _summary(result: IOCResult) -> str:
    if not result.query_success:
        return f"[!] {result.source}: {result.error}"
    if result.source == "otx":
        count = int(result.raw_score) if result.raw_score is not None else 0
        verdict = "malicious" if result.malicious else "benign"
        return f"OTX: {count} pulse(s) ({verdict})"
    if result.source == "virustotal":
        verdict = "malicious" if result.malicious else "benign"
        pct = f"{result.raw_score:.1%}" if result.raw_score is not None else "N/A"
        return f"VT: {verdict} ({pct} detection ratio)"
    if result.source == "abuseipdb":
        conf = result.confidence if result.confidence is not None else 0
        return f"AbuseIPDB: {conf}% confidence"
    return f"{result.source}: {result.malicious}"


def main() -> None:
    print("=" * 60)
    print("            IOC Enrichment Pipeline")
    print("=" * 60)

    ip = ""
    while True:
        ip = input(
            "\nEnter target IP address (IPv4 e.g. 1.1.1.1, "
            "IPv6 e.g. 2606:4700:4700::1111): "
        ).strip()
        if not ip:
            print("  IP address is required.")
            continue
        if not _validate_ip(ip):
            print("  Invalid IP address. Enter a valid IPv4 or IPv6 address.")
            continue
        break

    additional = input(
        "\nDo you also want to check a domain, file hash, or URL? (y/n): "
    ).strip().lower()

    domain = None
    file_hash = None
    url = None

    if additional in ("y", "yes"):
        d = input("\nEnter domain (or press Enter to skip): ").strip()
        if d:
            if " " in d or "." not in d:
                print("  Warning: domain looks unusual (contains spaces or missing dot).")
            domain = d

        while True:
            h = input(
                "Enter file hash (MD5/SHA1/SHA256) (or press Enter to skip): "
            ).strip()
            if not h:
                break
            if not _validate_hash(h):
                print(
                    f"  Invalid hash: expected 32, 40, or 64 hex characters, "
                    f"got {len(h)}."
                )
                continue
            file_hash = h
            break

        u = input(
            "Enter URL starting with http:// or https:// (or press Enter to skip): "
        ).strip()
        if u:
            if not (u.startswith("http://") or u.startswith("https://")):
                print("  Warning: URL should start with http:// or https://.")
            url = u

    iocs_to_process = [(ip, "ip", _sources_for("ip"))]
    if domain:
        iocs_to_process.append((domain, "domain", _sources_for("domain")))
    if file_hash:
        iocs_to_process.append((file_hash, "hash", _sources_for("hash")))
    if url:
        iocs_to_process.append((url, "url", _sources_for("url")))

    aggregated_results: list[AggregatedResult] = []

    print("\n" + "-" * 60)
    print("  Enriching IOCs...")
    print("-" * 60)

    for ioc_val, ioc_type_val, sources in iocs_to_process:
        label = f"[{ioc_type_val}] {ioc_val}"
        if len(label) > 70:
            label = label[:67] + "..."
        print(f"\n  {label}")
        results = enrich(ioc_val, ioc_type_val, sources)
        agg = aggregate(results)
        aggregated_results.append(agg)
        print(f"    Verdict: {agg.final_verdict} (confidence: {agg.aggregate_confidence}/100)")
        for r in results:
            print(f"      {_summary(r)}")

    bundle_objects: list = [TOOL_IDENTITY]
    for agg in aggregated_results:
        indicator = to_stix_indicator_aggregated(agg)
        if indicator is not None:
            bundle_objects.append(indicator)
    bundle = stix2.Bundle(*bundle_objects)
    stix_json = bundle.serialize(pretty=True)

    output_dir = os.path.join(_script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"session_{timestamp}.json")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(stix_json)

    parsed = json.loads(stix_json)
    n_indicators = sum(1 for o in parsed["objects"] if o["type"] == "indicator")
    total_sources = sum(len(agg.sources_checked) for agg in aggregated_results)

    print("\n" + "=" * 60)
    print(f"  Processed {len(iocs_to_process)} IOC(s) across "
          f"{total_sources} source result(s).")
    print(f"  Produced {n_indicators} aggregated STIX indicator(s).")
    print(f"  Bundle saved to: {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
