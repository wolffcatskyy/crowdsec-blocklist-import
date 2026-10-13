"""Report-only planning primitives. No network calls or enforcement changes.

Hit observations must come from an explicit per-feed telemetry source. Feed
entry counts are not hit telemetry. These helpers do not collect that source.
"""
from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class FeedObservation:
    feed: str
    hits: Optional[int] = None
    window_seconds: Optional[int] = None
    complete: bool = False
    stale: bool = False


def hit_status(observation: FeedObservation, minimum_window_seconds: int) -> str:
    """Distinguish a measured zero from missing, partial or stale telemetry."""
    if minimum_window_seconds <= 0:
        raise ValueError("minimum window must be positive")
    if observation.hits is not None and observation.hits < 0:
        raise ValueError("hits cannot be negative")
    if observation.window_seconds is not None and observation.window_seconds < 0:
        raise ValueError("window cannot be negative")
    if (observation.hits is None or observation.window_seconds is None
            or not observation.complete or observation.stale
            or observation.window_seconds < minimum_window_seconds):
        return "unknown"
    return "zero_observed_hits" if observation.hits == 0 else "observed_hits"


@dataclass(frozen=True)
class FeedEstimate:
    feed: str
    estimated_decisions: Optional[int]
    priority: int = 0


def capacity_preview(feeds: Sequence[FeedEstimate], capacity: int) -> dict:
    """Return a deterministic greedy estimate, not an optimal or applied plan.

Counts are conservative additive estimates: overlapping feed entries may
count twice. Unknown estimates are excluded, never assumed to cost zero.
"""
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
        raise ValueError("a positive integer capacity must be configured")
    if len({f.feed for f in feeds}) != len(feeds):
        raise ValueError("feed names must be unique")
    selected, excluded, projected = [], [], 0
    for feed in sorted(feeds, key=lambda f: (-f.priority, f.feed)):
        count = feed.estimated_decisions
        if count is not None and (isinstance(count, bool)
                                  or not isinstance(count, int) or count < 0):
            raise ValueError("decision estimates must be nonnegative integers")
        if count is None:
            excluded.append({"feed": feed.feed, "reason": "unknown_estimate"})
        elif projected + count > capacity:
            excluded.append({"feed": feed.feed, "reason": "capacity"})
        else:
            selected.append(feed.feed)
            projected += count
    return {"report_only": True, "capacity": capacity,
            "estimated_decisions": projected, "selected": selected,
            "excluded": excluded, "estimate_method": "additive_greedy"}
