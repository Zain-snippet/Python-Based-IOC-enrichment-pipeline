import base64
from typing import Dict

import requests

from config import require_vt_key
from connectors._rate_limit import RateLimiter
from connectors.exceptions import (
    InvalidAPIKeyError,
    IOCNotFoundError,
    NetworkError,
    RateLimitExceededError,
    ConnectorError,
)

_BASE_URL = "https://www.virustotal.com/api/v3"

_IOC_ENDPOINTS: Dict[str, str] = {
    "ip": f"{_BASE_URL}/ip_addresses/",
    "domain": f"{_BASE_URL}/domains/",
    "hash": f"{_BASE_URL}/files/",
    "url": f"{_BASE_URL}/urls/",
}

_MIN_INTERVAL = 15.0
_rate_limiter = RateLimiter(_MIN_INTERVAL)


def _url_id(raw_url: str) -> str:
    return base64.urlsafe_b64encode(raw_url.encode()).decode().rstrip("=")


def query(ioc: str, ioc_type: str) -> dict:
    if ioc_type not in _IOC_ENDPOINTS:
        raise ValueError(
            f"Unsupported ioc_type '{ioc_type}'. Must be one of: {list(_IOC_ENDPOINTS)}"
        )

    api_key = require_vt_key()
    _rate_limiter.wait()

    endpoint = _IOC_ENDPOINTS[ioc_type]
    if ioc_type == "url":
        resource = _url_id(ioc)
    else:
        resource = ioc
    url = f"{endpoint}{resource}"

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.exceptions.Timeout:
        raise NetworkError("VirusTotal request timed out.")
    except requests.exceptions.ConnectionError as e:
        raise NetworkError(f"VirusTotal connection failed: {e}")
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"VirusTotal request error: {e}")

    if resp.status_code == 401:
        raise InvalidAPIKeyError("VirusTotal rejected the API key.")
    if resp.status_code == 429:
        raise RateLimitExceededError("VirusTotal rate limit exceeded (4 req/min free tier).")
    if resp.status_code == 404:
        raise IOCNotFoundError(f"IOC '{ioc}' not found in VirusTotal.")
    if resp.status_code != 200:
        raise ConnectorError(
            f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}"
        )

    return resp.json()