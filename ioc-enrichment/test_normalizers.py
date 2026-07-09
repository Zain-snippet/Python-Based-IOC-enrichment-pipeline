"""
Manual test script for Phase 2 normalizers.

Uses hardcoded fixture dicts that mimic real API responses (not live calls),
so it runs offline with no API keys needed.

Usage:
    python test_normalizers.py
"""

import json

from normalizers.schema import IOCResult
from normalizers.otx_normalizer import normalize as otx_normalize
from normalizers.vt_normalizer import normalize as vt_normalize
from normalizers.abuseipdb_normalizer import normalize as abuseipdb_normalize


# ── Fixtures ──────────────────────────────────────────────────────────

# OTX fixture — an IP with multiple pulse references (malicious)
OTX_MALICIOUS_FIXTURE = {
    "general": {
        "indicator": "103.235.46.39",
        "type": "IPv4",
        "pulse_info": {
            "count": 3,
            "pulses": [
                {
                    "name": "Recent C2 Activity",
                    "tags": ["c2", "mirai", "malware"],
                    "created": "2025-01-15T10:30:00",
                    "modified": "2025-06-20T14:00:00",
                    "description": "Observed C2 communication",
                    "adversary": "Unknown",
                    "malware_families": [{"display_name": "Mirai"}],
                },
                {
                    "name": "Scanning Campaign",
                    "tags": ["scanner", "bruteforce"],
                    "created": "2025-03-01T08:00:00",
                    "modified": "2025-06-18T09:00:00",
                    "description": "Port scanning activity",
                },
                {
                    "name": "Botnet Node",
                    "tags": ["botnet", "c2"],
                    "created": "2025-04-10T12:00:00",
                    "modified": "2025-06-22T16:30:00",
                },
            ],
        }
    }
}

# OTX — an IP with zero pulses (benign / unknown)
OTX_NOT_FOUND_FIXTURE = {
    "general": {
        "indicator": "1.1.1.1",
        "type": "IPv4",
        "pulse_info": {
            "count": 0,
            "pulses": [],
        },
    }
}

# VirusTotal — a file hash with 15 malicious detections (malicious)
VT_MALICIOUS_FIXTURE = {
    "data": {
        "type": "file",
        "id": "44d88612fea8a8f36de82e1278abb02f",
        "attributes": {
            "sha256": "44d88612fea8a8f36de82e1278abb02f",
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "last_analysis_stats": {
                "malicious": 15,
                "suspicious": 3,
                "harmless": 40,
                "undetected": 12,
                "timeout": 0,
            },
            "tags": ["peexe", "trojan", "executable"],
            "type_description": "Win32 EXE",
            "meaningful_name": "malware_sample.exe",
            "first_submission_date": 1700000000,
            "last_submission_date": 1715000000,
            "last_analysis_date": 1715000000,
            "last_modification_date": 1715000000,
            "reputation": -50,
            "total_votes": {"harmless": 2, "malicious": 10},
            "times_submitted": 25,
            "size": 65536,
        }
    }
}

# VirusTotal — a domain with zero malicious detections (benign)
VT_BENIGN_FIXTURE = {
    "data": {
        "type": "domain",
        "id": "google.com",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 68,
                "undetected": 2,
                "timeout": 0,
            },
            "tags": ["searchengine"],
            "reputation": 100,
            "total_votes": {"harmless": 500, "malicious": 1},
            "last_analysis_date": 1715000000,
            "last_modification_date": 1715000000,
        }
    }
}

# VirusTotal — a non-existent IOC (404-equivalent)
VT_NOT_FOUND_FIXTURE = {
    "error": {
        "code": "NotFoundError",
        "message": "Resource not found",
    }
}

# AbuseIPDB — an IP with high confidence score (malicious)
ABUSEIPDB_MALICIOUS_FIXTURE = {
    "data": {
        "ipAddress": "103.235.46.39",
        "abuseConfidenceScore": 85,
        "totalReports": 12,
        "numDistinctUsers": 5,
        "lastReportedAt": "2025-06-22T16:30:00",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "AS-Choopa",
        "domain": "choopa.com",
        "hostnames": ["host.choopa.com"],
        "isTor": False,
        "isWhitelisted": False,
        "countryCode": "US",
        "reports": [
            {
                "reportedAt": "2025-06-22T16:30:00",
                "categories": [14, 18],
                "comment": "SSH brute force attempt",
            },
            {
                "reportedAt": "2025-06-20T10:00:00",
                "categories": [14, 22],
                "comment": "Port scan and SSH brute force",
            },
        ],
    }
}

# AbuseIPDB — a clean IP with low confidence score (benign)
ABUSEIPDB_BENIGN_FIXTURE = {
    "data": {
        "ipAddress": "1.1.1.1",
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "numDistinctReports": 0,
        "lastReportedAt": None,
        "isWhitelisted": True,
        "isTor": False,
        "countryCode": "US",
        "isp": "Cloudflare Inc.",
        "domain": "cloudflare.com",
        "hostnames": ["one.one.one.one", "1.1.1.1"],
    }
}

# AbuseIPDB — empty data (not found)
ABUSEIPDB_NOT_FOUND_FIXTURE = {
    "data": {}
}


def print_result(label: str, result: IOCResult) -> None:
    print(f"\n{'='*60}")
    print(f"{label}")
    print(f"{'='*60}")
    print(json.dumps({
        "source": result.source,
        "ioc": result.ioc,
        "ioc_type": result.ioc_type,
        "malicious": result.malicious,
        "confidence": result.confidence,
        "raw_score": result.raw_score,
        "tags": result.tags,
        "first_seen": result.first_seen,
        "last_seen": result.last_seen,
        "source_url": result.source_url,
        "query_success": result.query_success,
        "error": result.error,
    }, indent=2, default=str))


def main() -> None:
    print(">>> OTX NORMALIZER <<<")
    r = otx_normalize(OTX_MALICIOUS_FIXTURE, "103.235.46.39", "ip")
    print_result("OTX — malicious IP (pulse_count=3)", r)

    r = otx_normalize(OTX_NOT_FOUND_FIXTURE, "1.1.1.1", "ip")
    print_result("OTX — benign IP (pulse_count=0)", r)

    r = otx_normalize({}, "1.2.3.4", "ip")
    print_result("OTX — empty response (error path)", r)

    print("\n>>> VT NORMALIZER <<<")
    r = vt_normalize(VT_MALICIOUS_FIXTURE, "44d8...b02f", "hash")
    print_result("VT — malicious hash (15 engines)", r)

    r = vt_normalize(VT_BENIGN_FIXTURE, "google.com", "domain")
    print_result("VT — benign domain (0 engines)", r)

    r = vt_normalize(VT_NOT_FOUND_FIXTURE, "nonexistent.com", "domain")
    print_result("VT — not found (error response)", r)

    print("\n>>> ABUSEIPDB NORMALIZER <<<")
    r = abuseipdb_normalize(ABUSEIPDB_MALICIOUS_FIXTURE, "103.235.46.39", "ip")
    print_result("AbuseIPDB — malicious IP (confidence=85)", r)

    r = abuseipdb_normalize(ABUSEIPDB_BENIGN_FIXTURE, "1.1.1.1", "ip")
    print_result("AbuseIPDB — benign IP (confidence=0)", r)

    r = abuseipdb_normalize(ABUSEIPDB_NOT_FOUND_FIXTURE, "10.0.0.1", "ip")
    print_result("AbuseIPDB — empty data (not found)", r)

    print("\nDone.")


if __name__ == "__main__":
    main()