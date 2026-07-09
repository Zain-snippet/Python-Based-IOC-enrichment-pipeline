# IOC Enrichment Pipeline — Phase 1

Phase 1 provides three independent source connectors that query threat-intel APIs and return raw, unmodified JSON responses. No normalization, aggregation, or scoring is performed yet.

## Supported Sources

| Source | IOC Types | API Auth |
|---|---|---|
| AlienVault OTX | ip, domain, hash, url | API key (OTXv2 SDK) |
| VirusTotal | ip, domain, hash, url | API key (REST v3) |
| AbuseIPDB | ip only | API key (REST v2) |

## Getting API Keys

- **AlienVault OTX**: https://otx.alienvault.com → sign up, API key in user settings
- **VirusTotal**: https://www.virustotal.com → sign up, API key in account settings (free tier: 4 req/min)
- **AbuseIPDB**: https://www.abuseipdb.com → sign up, API key in account settings

## Setup

```bash
cd ioc-enrichment
python -m venv .venv
.venv\Scripts\activate    # Windows
pip install -r requirements.txt
cp .env.example .env      # then fill in your real API keys
```

## Running the Tests

```bash
python test_connectors.py
```

The script tests each connector with a benign IOC (`1.1.1.1`, `google.com`, a SHA256 of empty string) and with a malicious sample. **Before running, replace `KNOWN_MALICIOUS_*` values in `test_connectors.py` with real malicious IOCs** sourced from:
- AbuseIPDB blacklist: https://www.abuseipdb.com/blacklist
- AlienVault OTX pulses: https://otx.alienvault.com/browse/pulses
- VirusTotal search for malware hashes

## Design Decisions

- **Raw JSON returned, not normalized**: Each API has a unique response schema. Normalising in Phase 1 would couple the connector logic to a data model that hasn't been designed yet. Phase 2 will create a common `EnrichmentResult` schema and map each source's fields into it. For now, returning `dict` keeps connectors simple, testable, and easy to debug.
- **API key validation deferred to call time**: `config.py` does not validate keys at import so that unit tests can import modules without live keys. Errors surface only when `query()` is called.
- **Rate limiting per connector**: VT's free tier is 4 req/min; AbuseIPDB allows ~10 req/min; OTX's SDK has internal retry logic but a 1-second guard is added. Each connector tracks its own call timing to avoid excessive backoff.
- **Custom exceptions**: Distinct exception types (`InvalidAPIKeyError`, `RateLimitExceededError`, `IOCNotFoundError`, `NetworkError`, `UnsupportedIOCTypeError`) let callers handle each failure mode specifically rather than parsing error strings.

## Project Structure

```
ioc-enrichment/
├── connectors/
│   ├── __init__.py
│   ├── exceptions.py      # Shared custom exceptions
│   ├── otx.py              # AlienVault OTX connector
│   ├── virustotal.py       # VirusTotal v3 connector
│   └── abuseipdb.py        # AbuseIPDB connector
├── config.py               # Environment variable loading
├── test_connectors.py      # Manual test script
├── requirements.txt
├── .env.example
└── README.md
```

## Assumptions to Verify Against Live Calls

1. **OTXv2 `get_indicator_details_full`**: Assumes the OTX SDK's `section` parameter maps as `IPv4`, `Domain`, `SHA256`, `URL` for the respective IOC types. The SDK may expect lowercase forms or alternative names for certain types (e.g., `ipv4` vs `IPv4`).
2. **VirusTotal URL ID encoding**: Assumes VT v3 uses base64url-encoded (no padding) URL strings as resource IDs for the `/urls/` endpoint. This is documented but should be verified.
3. **AbuseIPDB `verbose` parameter**: Assumes passing an empty string enables verbose output. The API docs show this as a boolean flag; an empty string may be treated as falsy.
4. **All APIs return HTTP 404 for missing IOCs**: OTX may return an empty results list instead of a non-200 HTTP status. The connector checks `result.get("results") == []` as a proxy.
5. **Rate limit headers**: VT and AbuseIPDB return 429 on rate limits, but the response body format may differ. The connectors only check the status code.
