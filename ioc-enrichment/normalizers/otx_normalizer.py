"""
OTX normalizer — maps AlienVault OTX raw JSON to IOCResult.

Key judgment calls are documented as module-level constants.

OTX does not have a single "malicious: true/false" field. The verdict is
derived from pulse_info.count: if threat-research pulses reference this
indicator, we treat it as malicious. This is a judgment call — a pulse
reference means the IOC appeared in *someone's* collection, not that it
was independently verified as malicious. False-positive pulses (e.g.
honeypot noise, over-enthusiastic automation) exist. The threshold is
set to > 0 because OTX already curates pulses; raising it higher would
increase the false-negative rate without a clear baseline for what
constitutes a "credible" pulse count.
"""

from typing import Optional

from normalizers.schema import IOCResult, NormalizationError

# An IOC appearing in any OTX pulse is treated as potentially malicious.
# OTX pulses are curated by threat researchers and community analysts.
# A pulse_count > 0 means at least one human or automated system decided
# this indicator was worth reporting as a threat.
OTX_MALICIOUS_PULSE_THRESHOLD = 1

# Maximum number of pulse tags to collect to avoid unbounded arrays.
OTX_MAX_TAGS = 100


def normalize(raw: dict, ioc: str, ioc_type: str) -> IOCResult:
    try:
        if not raw or "general" not in raw:
            return IOCResult(
                source="otx",
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
                error="Response missing 'general' section.",
            )

        general = raw.get("general", {})
        pulse_info = general.get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)

        malicious = pulse_count > OTX_MALICIOUS_PULSE_THRESHOLD

        pulses = pulse_info.get("pulses", []) or []
        tags: list[str] = []
        first_seen: Optional[str] = None
        last_seen: Optional[str] = None

        for pulse in pulses:
            for tag in pulse.get("tags", []) or []:
                if isinstance(tag, str) and tag not in tags:
                    tags.append(tag)
                    if len(tags) >= OTX_MAX_TAGS:
                        break
            created = pulse.get("created")
            modified = pulse.get("modified")
            if created and (first_seen is None or created < first_seen):
                first_seen = created
            if modified and (last_seen is None or modified > last_seen):
                last_seen = modified

        confidence = None
        # OTX has no native confidence score — pulse_count is the closest
        # proxy, but converting it directly would be misleading since pulse
        # counts are unbounded and not normalized. We leave confidence as
        # None to avoid fabricating a score OTX doesn't provide.

        raw_score = float(pulse_count)

        source_url = (
            f"https://otx.alienvault.com/indicator/{ioc_type}/{ioc}"
        )

        return IOCResult(
            source="otx",
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
                source="otx",
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
                f"Unexpected failure normalizing OTX result for {ioc}"
            ) from e