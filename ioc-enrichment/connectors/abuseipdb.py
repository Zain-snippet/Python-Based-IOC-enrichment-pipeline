import time

import requests

from config import require_abuseipdb_key
from connectors.exceptions import (
    InvalidAPIKeyError,
    IOCNotFoundError,
    NetworkError,
    RateLimitExceededError,
    UnsupportedIOCTypeError,
    ConnectorError,
)

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_MIN_INTERVAL = 6.0
_last_call: float = 0.0


def _rate_limit() -> None:
    global _last_call
    now = time.time()
    elapsed = now - _last_call
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call = time.time()


def query(ioc: str, ioc_type: str) -> dict:
    if ioc_type != "ip":
        raise UnsupportedIOCTypeError(
            f"AbuseIPDB only supports 'ip' ioc_type, got '{ioc_type}'."
        )

    api_key = require_abuseipdb_key()
    _rate_limit()

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params: dict = {"ipAddress": ioc, "maxAgeInDays": "365", "verbose": ""}

    try:
        resp = requests.get(
            _BASE_URL, headers=headers, params=params, timeout=30
        )
    except requests.exceptions.Timeout:
        raise NetworkError("AbuseIPDB request timed out.")
    except requests.exceptions.ConnectionError as e:
        raise NetworkError(f"AbuseIPDB connection failed: {e}")
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"AbuseIPDB request error: {e}")

    if resp.status_code == 401:
        raise InvalidAPIKeyError("AbuseIPDB rejected the API key.")
    if resp.status_code == 429:
        raise RateLimitExceededError("AbuseIPDB rate limit exceeded.")
    if resp.status_code == 404:
        raise IOCNotFoundError(f"IP '{ioc}' not found in AbuseIPDB.")
    if resp.status_code != 200:
        raise ConnectorError(
            f"AbuseIPDB returned HTTP {resp.status_code}: {resp.text[:200]}"
        )

    return resp.json()