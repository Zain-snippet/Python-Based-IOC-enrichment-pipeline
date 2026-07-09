"""
VirusTotal normalizer — maps VirusTotal v3 raw JSON to IOCResult.

Key judgment calls are documented as module-level constants.

VirusTotal aggregates detections from ~70+ AV engines. Using a threshold
of >= 3 malicious detections reduces the impact of single-engine false
positives (which are common — one engine flagging a benign file as
malware does not make it malicious). The 3-engine threshold is a common
industry heuristic; many TIP platforms default to this or similar values.
"""

import datetime
from typing import Optional

from normalizers.schema import IOCResult, NormalizationError

# Minimum number of AV engines flagging the IOC as malicious before we
# consider it malicious. Single-engine hits are often false positives
# (e.g., generic/heuristic detections on clean files). 3 engines provides
# reasonable confidence that multiple independent vendors agree.
VT_MALICIOUS_ENGINE_THRESHOLD = 3

# URL path segment mapping for VT web UI links
VT_UI_PATH: dict[str, str] = {
    "ip": "ip-address",
    "domain": "domain",
    "hash": "file",
    "url": "url",
}


def _ts_to_iso(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def normalize(raw: dict, ioc: str, ioc_type: str) -> IOCResult:
    try:
        data = raw.get("data", {})
        attrs = data.get("attributes", {})
        resource_id: str = data.get("id", ioc)

        stats = attrs.get("last_analysis_stats", {})
        malicious_count: int = stats.get("malicious", 0)
        suspicious_count: int = stats.get("suspicious", 0)
        harmless_count: int = stats.get("harmless", 0)
        undetected_count: int = stats.get("undetected", 0)

        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        malicious = malicious_count >= VT_MALICIOUS_ENGINE_THRESHOLD

        # raw_score: ratio of malicious detections to total engines.
        # This is informative even if under the threshold — a 2/70 ratio
        # is different from 0/70 even if both are "not malicious" per our
        # judgment call.
        if total_engines > 0:
            raw_score = round(malicious_count / total_engines, 4)
        else:
            raw_score = None

        # Confidence is not directly available from VT's public API.
        # VT uses reputation(-100 to 100) and total_votes internally,
        # but neither maps cleanly to a 0–100 confidence scale. We leave
        # it as None rather than improvising.
        confidence = None

        tags: list[str] = attrs.get("tags", []) or []

        first_ts = (
            attrs.get("first_submission_date")
            or attrs.get("first_seen_itw_date")
            or attrs.get("creation_date")
        )
        last_ts = (
            attrs.get("last_analysis_date")
            or attrs.get("last_modification_date")
        )

        first_seen = _ts_to_iso(first_ts)
        last_seen = _ts_to_iso(last_ts)

        ui_path = VT_UI_PATH.get(ioc_type, ioc_type)
        source_url = f"https://www.virustotal.com/gui/{ui_path}/{ioc}/detection"

        return IOCResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            malicious=malicious,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            first_seen=first_seen,
            last_seen=last_seen,
            source_url=source_url,
            query_success=True,
            error=None,
        )

    except (KeyError, TypeError, IndexError, ValueError) as e:
        try:
            return IOCResult(
                source="virustotal",
                ioc=ioc,
                ioc_type=ioc_type,
                malicious=None,
                confidence=None,
                raw_score=None,
                tags=[],
                first_seen=None,
                last_seen=None,
                source_url=None,
                query_success=False,
                error=f"Normalization failed: {e}",
            )
        except Exception:
            raise NormalizationError(
                f"Unexpected failure normalizing VirusTotal result for {ioc}"
            ) from e