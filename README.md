IOC Enrichment Pipeline

A Python tool that takes an indicator of compromise (IP, domain, file hash, or URL) and checks it against multiple threat intelligence sources — AlienVault OTX, VirusTotal, and AbuseIPDB — then combines their results into a single verdict and exports it as a standards-compliant STIX 2.1 bundle.

Instead of manually checking three different dashboards and mentally reconciling three different scoring systems, this tool automates that enrichment step and produces one clear answer: is this indicator malicious, suspicious, benign, or unknown — backed by which sources agreed and which didn't.

Why this exists

Manual IOC lookups don't scale, and single-source verdicts are noisy — one flagged detection out of dozens of engines is often a false positive, not a real threat. This tool applies a simple cross-source voting rule to cut down on that noise, and outputs everything in STIX 2.1 so the results can actually be shared with or ingested by other CTI tooling (MISP, TAXII feeds, SIEMs) instead of living only as a one-off script output.

How it works

1. Input
You provide an IP address (required) and, optionally, a domain, file hash, and/or URL. Each is validated for basic format correctness before anything is sent out (valid IP structure, correct hash length for MD5/SHA1/SHA256, proper URL scheme).

2. Source querying
Each IOC is checked against every source that supports its type:

SourceSupportsAlienVault OTXIP, domain, hash, URLVirusTotalIP, domain, hash, URLAbuseIPDBIP only

Sources that don't support a given IOC type are skipped automatically rather than erroring out. Every API call is rate-limited to respect each provider's free-tier limits (enforced client-side, not dynamically read from response headers):


OTX: 1 request/second
VirusTotal: 15 seconds between requests (4 req/min free tier)
AbuseIPDB: 6 seconds between requests


All calls run sequentially — one source at a time, one IOC at a time — so a full IP lookup across all three sources takes roughly 20–25 seconds, and a session covering all four IOC types can take 1–2 minutes. This is a known limitation of building against free-tier APIs without concurrency; see Known Limitations below.

3. Normalization
Each source has a completely different response schema and scoring model — OTX has no native "malicious" flag and requires inferring one from pulse counts, VirusTotal reports a detection ratio across dozens of AV engines, and AbuseIPDB gives a direct 0–100 confidence score. Every raw response is translated into one common internal structure so the rest of the pipeline doesn't need to know which source it came from.

4. Aggregation
Once all sources have reported in for a given IOC, results are combined using an explicit voting rule:


2 or more sources flag it malicious → malicious
exactly 1 source flags it → suspicious (a single flag is treated as a possible false positive, not a confirmed verdict)
no source has usable data → unknown (absence of data is never treated as evidence of safety)
otherwise → benign


5. STIX 2.1 export
The aggregated verdict is converted into a STIX Indicator object with a proper pattern (e.g. [ipv4-addr:value = '1.2.3.4']), confidence score, labels, and a description noting which sources were checked and which flagged it. All indicators from a session are bundled together and written to output/session_<timestamp>.json.

Getting started

Requirements


Python 3.11+
Free API keys for OTX, VirusTotal, and AbuseIPDB


Setup

bashgit clone <this-repo>
cd ioc-enrichment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

Fill in .env with your API keys:


OTX: https://otx.alienvault.com → account settings
VirusTotal: https://www.virustotal.com → API key in profile
AbuseIPDB: https://www.abuseipdb.com → account API section


Running it

bashpython main.py

You'll be prompted for a target IP, then asked whether you want to also check a domain, hash, or URL. Each additional field is individually skippable — press Enter to skip. Once processing finishes, a summary is printed per IOC and the full STIX bundle is saved under output/.

Project structure

ioc-enrichment/
├── connectors/       # Raw API calls to each source
├── normalizers/       # Per-source response → common schema
├── aggregator/         # Cross-source voting logic
├── stix/                 # STIX 2.1 conversion
├── main.py             # Interactive entry point
├── test_*.py            # Manual test scripts per layer
└── output/             # Generated STIX bundles

Known limitations & ideas for improvement


No concurrency. Sources are queried sequentially even though each has an independent rate limit, so total runtime is additive rather than parallelized. Moving to asyncio or threads for the three source calls would meaningfully cut this down.
No caching. Re-checking the same IOC re-queries every source from scratch, burning API quota unnecessarily.
Simple confidence averaging. Aggregate confidence is an unweighted mean across sources that reported one — a more refined approach might weight by source reliability or IOC freshness.
No batch mode. Currently one interactive session at a time; reading a list of IOCs from a file would make this more practical for real triage workflows.


This project is very much a learning/portfolio piece and I'm actively looking to improve it — if you have suggestions on the aggregation logic, STIX mapping choices, architecture, or anything else, I'd genuinely welcome the feedback. Feel free to open an issue or PR.
