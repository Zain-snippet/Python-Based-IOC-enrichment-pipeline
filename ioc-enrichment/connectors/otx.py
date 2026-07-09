import time
from typing import Dict
from OTXv2 import OTXv2, InvalidAPIKey as OTXInvalidAPIKey, BadRequest, RetryError

from config import require_otx_key
from connectors.exceptions import (
    InvalidAPIKeyError,
    IOCNotFoundError,
    NetworkError,
    RateLimitExceededError,
    ConnectorError,
)

_IOC_TYPE_MAP: Dict[str, str] = {
    "ip": "IPv4",
    "domain": "Domain",
    "hash": "SHA256",
    "url": "URL",
}

_RATE_LIMIT_SLEEP = 1.0
_last_call: float = 0.0


def query(ioc: str, ioc_type: str) -> dict:
    if ioc_type not in _IOC_TYPE_MAP:
        raise ValueError(
            f"Unsupported ioc_type '{ioc_type}'. Must be one of: {list(_IOC_TYPE_MAP)}"
        )

    api_key = require_otx_key()
    otx_section = _IOC_TYPE_MAP[ioc_type]

    global _last_call
    now = time.time()
    elapsed = now - _last_call
    if elapsed < _RATE_LIMIT_SLEEP:
        time.sleep(_RATE_LIMIT_SLEEP - elapsed)
    _last_call = time.time()

    client = OTXv2(api_key)

    try:
        result = client.get_indicator_details_full(otx_section, ioc)
    except OTXInvalidAPIKey:
        raise InvalidAPIKeyError("AlienVault OTX rejected the API key.")
    except BadRequest as e:
        if "rate" in str(e).lower() or "limit" in str(e).lower() or "429" in str(e):
            raise RateLimitExceededError("OTX rate limit hit.")
        raise ConnectorError(f"OTX bad request: {e}")
    except RetryError as e:
        raise NetworkError(f"OTX request failed after retries: {e}")
    except Exception as e:
        raise ConnectorError(f"Unexpected OTX error: {e}")

    if result is None or result.get("results") == []:
        raise IOCNotFoundError(f"IOC '{ioc}' not found in AlienVault OTX.")

    return result