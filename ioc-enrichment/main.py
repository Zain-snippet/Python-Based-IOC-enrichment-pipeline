"""
IOC Enrichment Pipeline — main entry point.

Wires the three previously-disconnected stages together for real IOCs:

    connectors.query()  ->  normalizers.normalize()  ->  stix.to_stix_bundle()

Without this script, there is no path from a live IOC lookup to STIX
output: test_connectors.py prints raw API JSON, test_normalizers.py prints
normalized IOCResult JSON, and test_stix.py only exercises the converter
against hardcoded fixtures. This script is what actually produces a STIX
2.1 bundle for a real indicator.

Usage:
    python main.py 103.235.46.39 --type ip
    python main.py evil.example.com --type domain --out output/bundle.json
    python main.py 44d88612fea8a8f36de82e1278abb02f --type hash --sources vt,abuseipdb
"""

import argparse
import json
import sys

from connectors import abuseipdb as abuseipdb_connector
from connectors import otx as otx_connector
from connectors import virustotal as vt_connector
from connectors.exceptions import ConnectorError
from config import MissingAPIKeyError
from normalizers.abuseipdb_normalizer import normalize as abuseipdb_normalize
from normalizers.otx_normalizer import normalize as otx_normalize
from normalizers.schema import IOCResult
from normalizers.vt_normalizer import normalize as vt_normalize
from stix.stix_converter import to_stix_bundle

# Registry of available sources: name -> (connector module, normalizer.normalize)
# Storing the module (not module.query directly) so callers can monkeypatch
# e.g. otx_connector.query for testing and enrich() will pick it up, since
# it's resolved at call time rather than bound at import time.
SOURCES = {
    "otx": (otx_connector, otx_normalize),
    "vt": (vt_connector, vt_normalize),
    "abuseipdb": (abuseipdb_connector, abuseipdb_normalize),
}

# AbuseIPDB only supports IPs; skip it automatically for other ioc_types
# instead of letting it raise UnsupportedIOCTypeError.
_SOURCE_IOC_SUPPORT = {
    "otx": {"ip", "domain", "hash", "url"},
    "vt": {"ip", "domain", "hash", "url"},
    "abuseipdb": {"ip"},
}


def enrich(ioc: str, ioc_type: str, sources: list[str]) -> list[IOCResult]:
    """Query each requested source and normalize the result.

    A connector failure (bad key, rate limit, not found, network error)
    produces a query_success=False IOCResult instead of raising, so one
    failing source doesn't abort enrichment of the others.
    """
    results: list[IOCResult] = []

    for source in sources:
        if ioc_type not in _SOURCE_IOC_SUPPORT[source]:
            print(
                f"[skip] {source}: does not support ioc_type '{ioc_type}'",
                file=sys.stderr,
            )
            continue

        connector_module, normalize_fn = SOURCES[source]

        try:
            raw = connector_module.query(ioc, ioc_type)
            result = normalize_fn(raw, ioc, ioc_type)
        except MissingAPIKeyError as e:
            print(f"[error] {source}: {e}", file=sys.stderr)
            result = IOCResult(
                source=source,
                ioc=ioc,
                ioc_type=ioc_type,
                query_success=False,
                error=str(e),
            )
        except ConnectorError as e:
            print(f"[error] {source}: {e}", file=sys.stderr)
            result = IOCResult(
                source=source,
                ioc=ioc,
                ioc_type=ioc_type,
                query_success=False,
                error=str(e),
            )
        except Exception as e:  # noqa: BLE001 - surface unexpected errors per-source
            print(f"[error] {source}: unexpected failure: {e}", file=sys.stderr)
            result = IOCResult(
                source=source,
                ioc=ioc,
                ioc_type=ioc_type,
                query_success=False,
                error=f"Unexpected error: {e}",
            )

        results.append(result)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enrich an IOC across sources and export it as a STIX 2.1 bundle."
    )
    parser.add_argument("ioc", help="The indicator value (IP, domain, hash, or URL)")
    parser.add_argument(
        "--type",
        dest="ioc_type",
        required=True,
        choices=["ip", "domain", "hash", "url"],
        help="Type of the IOC",
    )
    parser.add_argument(
        "--sources",
        default="otx,vt,abuseipdb",
        help="Comma-separated list of sources to query (default: all)",
    )
    parser.add_argument(
        "--out",
        default="output/bundle.json",
        help="Path to write the STIX bundle JSON (default: output/bundle.json)",
    )
    args = parser.parse_args()

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = set(sources) - set(SOURCES)
    if unknown:
        parser.error(f"Unknown source(s): {', '.join(sorted(unknown))}. "
                      f"Valid sources: {', '.join(SOURCES)}")

    results = enrich(args.ioc, args.ioc_type, sources)
    bundle = to_stix_bundle(results)
    stix_json = bundle.serialize(pretty=True)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(stix_json)

    parsed = json.loads(stix_json)
    n_indicators = sum(1 for o in parsed["objects"] if o["type"] == "indicator")
    print(f"\nQueried {len(results)} source(s), produced {n_indicators} STIX indicator(s).")
    print(f"Bundle written to: {args.out}\n")
    print(stix_json)


if __name__ == "__main__":
    main()
