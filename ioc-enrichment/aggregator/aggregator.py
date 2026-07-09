"""
Aggregator — combines multiple IOCResult objects for the same IOC into a
single cross-source verdict.

Scoring rules are documented inline and chosen to be simple, auditable,
and resistant to single-source false positives.
"""

from dataclasses import dataclass, field
from statistics import mean
from typing import Optional

from normalizers.schema import IOCResult


@dataclass
class AggregatedResult:
    ioc: str
    ioc_type: str
    sources_checked: list[str]             # all sources that were attempted (incl. failures)
    sources_flagged_malicious: list[str]   # subset that returned malicious=True
    final_verdict: str                     # "malicious", "suspicious", "benign", "unknown"
    aggregate_confidence: int              # 0-100, average of available source confidences
    all_tags: list[str]                    # deduped union of tags across sources
    individual_results: list[IOCResult]    # keep originals for traceability


def aggregate(results: list[IOCResult]) -> AggregatedResult:
    """Combine IOCResults for one IOC into a single aggregated verdict.

    Rules:
      1. Exclude query_success=False results from voting (still tracked
         in sources_checked as 'no data').
      2. If zero sources returned usable data → final_verdict = "unknown".
      3. If 2+ sources flag malicious → final_verdict = "malicious".
      4. If exactly 1 source flags malicious → final_verdict = "suspicious"
         (single-source flags are common false positives; this maps to
         alert fatigue — one source saying malicious is not enough to
         be confident).
      5. Otherwise → final_verdict = "benign".
      6. aggregate_confidence: simple average of confidence values from
         sources that provided one (weighted equally). This is a deliberate
         simplification — a production system might weight by source
         reliability, freshness, or IOC type.
    """

    if not results:
        return AggregatedResult(
            ioc="",
            ioc_type="",
            sources_checked=[],
            sources_flagged_malicious=[],
            final_verdict="unknown",
            aggregate_confidence=0,
            all_tags=[],
            individual_results=[],
        )

    first = results[0]
    ioc = first.ioc
    ioc_type = first.ioc_type

    sources_checked: list[str] = []
    sources_flagged_malicious: list[str] = []
    confidence_values: list[int] = []
    all_tags: set[str] = set()

    for r in results:
        sources_checked.append(r.source)
        if r.query_success and r.malicious is True:
            sources_flagged_malicious.append(r.source)
        if r.query_success and r.malicious is not None:
            if r.confidence is not None:
                confidence_values.append(r.confidence)
        if r.query_success:
            for tag in r.tags:
                all_tags.add(tag)

    n_flagged = len(sources_flagged_malicious)
    n_voting = sum(1 for r in results if r.query_success and r.malicious is not None)

    if n_voting == 0:
        final_verdict = "unknown"
    elif n_flagged >= 2:
        final_verdict = "malicious"
    elif n_flagged == 1:
        final_verdict = "suspicious"
    else:
        final_verdict = "benign"

    if confidence_values:
        aggregate_confidence = round(mean(confidence_values))
    else:
        aggregate_confidence = 0

    return AggregatedResult(
        ioc=ioc,
        ioc_type=ioc_type,
        sources_checked=sources_checked,
        sources_flagged_malicious=sources_flagged_malicious,
        final_verdict=final_verdict,
        aggregate_confidence=aggregate_confidence,
        all_tags=sorted(all_tags),
        individual_results=results,
    )
