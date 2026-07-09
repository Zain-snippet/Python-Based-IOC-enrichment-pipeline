"""
Manual test script for Phase 1 connectors.

Usage:
    python test_connectors.py

Before running, make sure your .env file has valid API keys for at least
the sources you want to test. Each connector is tested independently.

Known-bad IOCs:
  - You should replace KNOWN_MALICIOUS_IP with a confirmed malicious IP.
    Sources to find one:
      • AbuseIPDB blacklist (requires account): https://www.abuseipdb.com/blacklist
      • AlienVault OTX pulse list: https://otx.alienvault.com/browse/pulses
      • VirusTotal: search for a known malware hash
  - Default hash is set to a known test sample from the EICAR test file
    (MD5: 44d88612fea8a8f36de82e1278abb02f) — widely used for AV testing.
"""

KNOWN_BENIGN_IP = "1.1.1.1"
KNOWN_BENIGN_DOMAIN = "google.com"
KNOWN_BENIGN_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of empty string

# Replace these with real malicious samples before running tests
KNOWN_MALICIOUS_IP = "103.235.46.39"
KNOWN_MALICIOUS_HASH = "44d88612fea8a8f36de82e1278abb02f"
KNOWN_MALICIOUS_URL = "http://malware.testing.google.test/testing/malware/"
KNOWN_MALICIOUS_DOMAIN = "malware.testing.google.test"


def _print_result(source: str, label: str, data: dict) -> None:
    import json
    print(f"\n{'='*60}")
    print(f"{source} — {label}")
    print(f"{'='*60}")
    print(json.dumps(data, indent=2, default=str))


def test_otx() -> None:
    from connectors import otx
    print("\n>>> OTX CONNECTOR <<<")
    try:
        data = otx.query(KNOWN_BENIGN_IP, "ip")
        _print_result("OTX", f"IP (benign) {KNOWN_BENIGN_IP}", data)
    except Exception as e:
        print(f"OTX benign IP FAILED: {e}")
    try:
        data = otx.query(KNOWN_MALICIOUS_IP, "ip")
        _print_result("OTX", f"IP (malicious) {KNOWN_MALICIOUS_IP}", data)
    except Exception as e:
        print(f"OTX malicious IP FAILED: {e}")


def test_virustotal() -> None:
    from connectors import virustotal
    print("\n>>> VIRUSTOTAL CONNECTOR <<<")
    try:
        data = virustotal.query(KNOWN_BENIGN_HASH, "hash")
        _print_result("VT", f"Hash (benign) {KNOWN_BENIGN_HASH}", data)
    except Exception as e:
        print(f"VT benign hash FAILED: {e}")
    try:
        data = virustotal.query(KNOWN_MALICIOUS_HASH, "hash")
        _print_result("VT", f"Hash (malicious) {KNOWN_MALICIOUS_HASH}", data)
    except Exception as e:
        print(f"VT malicious hash FAILED: {e}")
    try:
        data = virustotal.query(KNOWN_BENIGN_DOMAIN, "domain")
        _print_result("VT", f"Domain (benign) {KNOWN_BENIGN_DOMAIN}", data)
    except Exception as e:
        print(f"VT benign domain FAILED: {e}")
    try:
        data = virustotal.query(KNOWN_MALICIOUS_URL, "url")
        _print_result("VT", f"URL (malicious) {KNOWN_MALICIOUS_URL}", data)
    except Exception as e:
        print(f"VT malicious URL FAILED: {e}")


def test_abuseipdb() -> None:
    from connectors import abuseipdb
    print("\n>>> ABUSEIPDB CONNECTOR <<<")
    try:
        data = abuseipdb.query(KNOWN_BENIGN_IP, "ip")
        _print_result("AbuseIPDB", f"IP (benign) {KNOWN_BENIGN_IP}", data)
    except Exception as e:
        print(f"AbuseIPDB benign IP FAILED: {e}")
    try:
        data = abuseipdb.query(KNOWN_MALICIOUS_IP, "ip")
        _print_result("AbuseIPDB", f"IP (malicious) {KNOWN_MALICIOUS_IP}", data)
    except Exception as e:
        print(f"AbuseIPDB malicious IP FAILED: {e}")

    print("\n>>> ABUSEIPDB — UNSUPPORTED IOC TYPE TEST <<<")
    try:
        abuseipdb.query(KNOWN_BENIGN_DOMAIN, "domain")
    except Exception as e:
        print(f"Expected error for non-IP type: {type(e).__name__}: {e}")


if __name__ == "__main__":
    test_otx()
    test_virustotal()
    test_abuseipdb()
    print("\nDone.")