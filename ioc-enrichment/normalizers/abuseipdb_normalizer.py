"""
AbuseIPDB normalizer — maps AbuseIPDB v2 raw JSON to IOCResult.

Key judgment calls are documented as module-level constants.

AbuseIPDB provides a native abuseConfidenceScore (0–100) that represents
the community-based confidence that this IP is abusive. We use it both as
confidence and to derive the malicious boolean. A threshold of >= 50 was
chosen because AbuseIPDB's own documentation suggests scores >= 50
represent "high confidence" abuse reports. Scores below 50 may reflect
limited reporting or contested reports.
"""

from typing import Optional

from normalizers.schema import IOCResult, NormalizationError

# Minimum AbuseIPDB confidence score to consider an IP malicious.
# Scores 0–49 = low confidence (few reports, possibly contested).
# Scores 50–100 = moderate to high confidence (multiple reporters
# agreeing on abuse). This is consistent with AbuseIPDB's own
# categorization where scores >= 50 are highlighted as "abusive".
ABUSEIPDB_MALICIOUS_THRESHOLD = 50

# URL for the AbuseIPDB web report page per IP
ABUSEIPDB_BASE_URL = "https://www.abuseipdb.com/check"


def normalize(raw: dict, ioc: str, ioc_type: str) -> IOCResult:
    try:
        data = raw.get("data", {})
        if not data:
            return IOCResult(
                source="abuseipdb",
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
                error="Response contained no 'data' field.",
            )

        abuse_confidence_score: int = data.get("abuseConfidenceScore", 0)
        total_reports: int = data.get("totalReports", 0)

        malicious = abuse_confidence_score >= ABUSEIPDB_MALICIOUS_THRESHOLD
        confidence = abuse_confidence_score
        raw_score = float(abuse_confidence_score)

        tags: list[str] = []
        usage_type = data.get("usageType")
        if usage_type and isinstance(usage_type, str):
            tags.append(f"usage:{usage_type}")
        is_tor = data.get("isTor", False)
        if is_tor:
            tags.append("tor_exit_node")
        is_whitelisted = data.get("isWhitelisted")
        if is_whitelisted is True:
            tags.append("whitelisted")
        domain = data.get("domain")
        if domain and isinstance(domain, str):
            tags.append(f"domain:{domain}")
        hostnames = data.get("hostnames", []) or []
        for hn in hostnames[:5]:
            if isinstance(hn, str):
                tags.append(f"hostname:{hn}")

        # Collect category labels from verbose reports
        reports = data.get("reports", []) or []
        seen_cats: set[int] = set()
        CATEGORY_MAP = {
            1: "dns_compromise",
            2: "dns_poisoning",
            3: "fraud_orders",
            4: "ddos",
            5: "ftp_bruteforce",
            6: "ping_of_death",
            7: "phishing",
            8: "fraud_voip",
            9: "open_proxy",
            10: "web_spam",
            11: "email_spam",
            12: "blog_spam",
            13: "vpn_ip",
            14: "port_scan",
            15: "hacking",
            16: "sql_injection",
            17: "spoofing",
            18: "brute_force",
            19: "bad_web_bot",
            20: "exploited_host",
            21: "web_app_attack",
            22: "ssh_bruteforce",
            23: "iot_targeted",
        }
        for report in reports:
            for cat_id in report.get("categories", []) or []:
                if cat_id not in seen_cats:
                    seen_cats.add(cat_id)
                    label = CATEGORY_MAP.get(cat_id, f"category_{cat_id}")
                    tags.append(label)

        last_reported_at = data.get("lastReportedAt")
        if last_reported_at and isinstance(last_reported_at, str):
            last_seen: Optional[str] = last_reported_at
        else:
            last_seen = None

        source_url = f"{ABUSEIPDB_BASE_URL}/{ioc}"

        return IOCResult(
            source="abuseipdb",
            ioc=ioc,
            ioc_type=ioc_type,
            malicious=malicious,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            first_seen=None,
            last_seen=last_seen,
            source_url=source_url,
            query_success=True,
            error=None,
        )

    except (KeyError, TypeError, IndexError, ValueError) as e:
        try:
            return IOCResult(
                source="abuseipdb",
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
                f"Unexpected failure normalizing AbuseIPDB result for {ioc}"
            ) from e