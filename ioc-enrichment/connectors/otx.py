from typing import Dict
from OTXv2 import OTXv2, IndicatorTypes, InvalidAPIKey as OTXInvalidAPIKey, BadRequest, RetryError

from config import require_otx_key
from connectors._rate_limit import RateLimiter
from connectors.exceptions import (
    InvalidAPIKeyError,
    IOCNotFoundError,
    NetworkError,
    RateLimitExceededError,
    ConnectorError,
)

_IOC_TYPE_MAP: Dict[str, IndicatorTypes] = {
    "ip": IndicatorTypes.IPv4,
    "domain": IndicatorTypes.DOMAIN,
    "url": IndicatorTypes.URL,
}

_RATE_LIMIT_SLEEP = 1.0
_rate_limiter = RateLimiter(_RATE_LIMIT_SLEEP)


def query(ioc: str, ioc_type: str) -> dict:
    if ioc_type == "hash":
        length = len(ioc)
        if length == 32:
            otx_section = IndicatorTypes.FILE_HASH_MD5
        elif length == 40:
            otx_section = IndicatorTypes.FILE_HASH_SHA1
        elif length == 64:
            otx_section = IndicatorTypes.FILE_HASH_SHA256
        else:
            raise ValueError(
                f"Cannot detect hash algorithm for '{ioc}': "
                f"expected 32, 40, or 64 hex characters, got {length}"
            )
    elif ioc_type in _IOC_TYPE_MAP:
        otx_section = _IOC_TYPE_MAP[ioc_type]
    else:
        raise ValueError(
            f"Unsupported ioc_type '{ioc_type}'. "
            f"Must be one of: ip, domain, hash, url"
        )

    api_key = require_otx_key()
    _rate_limiter.wait()
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