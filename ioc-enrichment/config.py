import os
from dotenv import load_dotenv

load_dotenv()


class MissingAPIKeyError(Exception):
    pass


def _get_key(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise MissingAPIKeyError(
            f"{name} is not set. Set it in your environment or .env file."
        )
    return value


def require_otx_key() -> str:
    return _get_key("OTX_API_KEY")


def require_vt_key() -> str:
    return _get_key("VT_API_KEY")


def require_abuseipdb_key() -> str:
    return _get_key("ABUSEIPDB_API_KEY")