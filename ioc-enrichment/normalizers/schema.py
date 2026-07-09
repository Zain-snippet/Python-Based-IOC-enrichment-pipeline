from dataclasses import dataclass, field
from typing import Optional


class NormalizationError(Exception):
    pass


@dataclass
class IOCResult:
    source: str
    ioc: str
    ioc_type: str
    malicious: Optional[bool] = None
    confidence: Optional[int] = None
    raw_score: Optional[float] = None
    tags: list[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_url: Optional[str] = None
    query_success: bool = True
    error: Optional[str] = None