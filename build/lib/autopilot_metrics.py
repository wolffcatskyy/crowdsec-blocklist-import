"""Report-only AUTOPILOT telemetry extensions. No network calls, no feed changes.

Builds on autopilot_report.py primitives. The hit-rate collector turns raw
hit counts into FeedObservation values. The dead-feed detector flags feeds
with zero observed hits over consecutive complete windows. Quarantine review
marks suspect feeds for human review only; nothing is quarantined, disabled
or removed. The capacity packer partitions feeds into capacity-constrained
groups with the same additive-greedy method as capacity_preview(). None of
this applies changes, contacts CrowdSec, or alters any feed configuration.
"""
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence

from autopilot_report import FeedEstimate, FeedObservation, hit_status


def _check_feed(feed: object) -> str:
    if not isinstance(feed, str) or not feed:
        raise ValueError("feed must be a non-empty string")
    return feed


def _check_hits(hits: object) -> int:
    if isinstance(hits, bool) or not isinstance(hits, int) or hits < 0:
        raise ValueError("hits must be a nonnegative integer")
    return hits


def _check_window(window_seconds: object) -> None:
    if (isinstance(window_seconds, bool) or not isinstance(window_seconds, int)
            or window_seconds <= 0):
        raise ValueError("window must be a positive integer")


class HitRateCollector:
    """Accumulate per-feed hit counts over one window, then emit observations.

    Call record() as hit events arrive. Call close_window() once the window
    ends to get one FeedObservation per monitored feed. A feed monitored for
    the whole window with no recorded events yields hits=0, which hit_status()
    reports as "zero_observed_hits". Call mark_partial() if collection did
    not cover the full window; observations then come out incomplete and
    hit_status() reports "unknown" instead of a measured zero.

    Feeds never under monitoring are not invented here: build a bare
    FeedObservation(feed) for those and hit_status() reports "unknown".
    """

    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}
        self._complete = True

    def record(self, feed: str, hits: int = 1) -> None:
        """Add hit events for a feed in the current window."""
        feed = _check_feed(feed)
        hits = _check_hits(hits)
        self._counts[feed] = self._counts.get(feed, 0) + hits

    def mark_partial(self) -> None:
        """Flag that collection missed part of the window."""
        self._complete = False

    def close_window(self, window_seconds: int,
                     monitored_feeds: Sequence[str] = ()) -> List[FeedObservation]:
        """Emit observations and reset for the next window.

        Every feed in monitored_feeds gets an observation; feeds with no
        recorded events get hits=0. Feeds recorded but missing from
        monitored_feeds are included as well, but remain incomplete because
        full-window monitoring was not declared for them.
        """
        _check_window(window_seconds)
        monitored = {_check_feed(f) for f in monitored_feeds}
        feeds = monitored | set(self._counts)
        observations = [
            FeedObservation(feed=feed,
                            hits=self._counts.get(feed, 0),
                            window_seconds=window_seconds,
                            complete=self._complete and feed in monitored)
            for feed in sorted(feeds)
        ]
        self._counts = {}
        self._complete = True
        return observations


@dataclass(frozen=True)
class DeadFeedFinding:
    feed: str
    consecutive_zero_windows: int
    last_window_seconds: int


def detect_dead_feeds(histories: Mapping[str, Sequence[FeedObservation]],
                      minimum_window_seconds: int,
                      consecutive_windows: int) -> List[DeadFeedFinding]:
    """Flag feeds with zero observed hits over consecutive complete windows.

    histories maps each feed to its observations, oldest first. Only trailing
    windows where hit_status() reports "zero_observed_hits" count toward the
    streak; "unknown", "observed_hits" or stale windows break it. A feed is
    flagged only when the streak reaches consecutive_windows.
    """
    _check_window(minimum_window_seconds)
    if (isinstance(consecutive_windows, bool)
            or not isinstance(consecutive_windows, int)
            or consecutive_windows <= 0):
        raise ValueError("consecutive windows must be a positive integer")
    findings = []
    for feed in sorted(histories):
        _check_feed(feed)
        streak = 0
        last_window: Optional[int] = None
        for observation in histories[feed]:
            if observation.feed != feed:
                raise ValueError("observation feed does not match history key")
            status = hit_status(observation, minimum_window_seconds)
            if status == "zero_observed_hits":
                streak += 1
                last_window = observation.window_seconds
            else:
                streak = 0
                last_window = None
        if streak >= consecutive_windows:
            findings.append(DeadFeedFinding(
                feed=feed,
                consecutive_zero_windows=streak,
                last_window_seconds=last_window if last_window is not None else 0,
            ))
    return findings


@dataclass(frozen=True)
class QuarantineCandidate:
    feed: str
    reason: str
    detail: str
    consecutive_windows: Optional[int] = None


_DEAD_FEED = "dead_feed"
_STALE_TELEMETRY = "stale_telemetry"
_UNKNOWN_TELEMETRY = "unknown_telemetry"


def quarantine_review(dead_feeds: Sequence[DeadFeedFinding] = (),
                      stale_feeds: Sequence[str] = (),
                      unknown_feeds: Sequence[str] = ()) -> dict:
    """Build a quarantine review list. Report-only: nothing is quarantined.

    Candidates come from dead-feed findings, feeds with stale telemetry, and
    feeds with persistently unknown telemetry. Each candidate carries a reason
    code and a human-readable detail for review. The result always reports
    applied=False; acting on it is a separate, manual step.
    """
    candidates: List[QuarantineCandidate] = []
    seen = set()
    for finding in dead_feeds:
        _check_feed(finding.feed)
        if finding.feed in seen:
            raise ValueError("duplicate feed in quarantine input")
        seen.add(finding.feed)
        candidates.append(QuarantineCandidate(
            feed=finding.feed,
            reason=_DEAD_FEED,
            detail=("zero observed hits in %d consecutive windows "
                    "(last window %ds)"
                    % (finding.consecutive_zero_windows,
                       finding.last_window_seconds)),
            consecutive_windows=finding.consecutive_zero_windows,
        ))
    for reason, feeds in ((_STALE_TELEMETRY, stale_feeds),
                          (_UNKNOWN_TELEMETRY, unknown_feeds)):
        for feed in feeds:
            _check_feed(feed)
            if feed in seen:
                raise ValueError("duplicate feed in quarantine input")
            seen.add(feed)
            detail = ("telemetry marked stale; hits cannot be trusted"
                      if reason == _STALE_TELEMETRY else
                      "no complete telemetry window observed")
            candidates.append(QuarantineCandidate(
                feed=feed, reason=reason, detail=detail))
    candidates.sort(key=lambda c: (c.reason, c.feed))
    return {
        "report_only": True,
        "applied": False,
        "action": "review",
        "candidates": [
            {"feed": c.feed, "reason": c.reason, "detail": c.detail,
             "consecutive_windows": c.consecutive_windows}
            for c in candidates
        ],
    }


def _check_capacity(capacity: object) -> int:
    if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
        raise ValueError("a positive integer capacity must be configured")
    return capacity


def _check_estimate(count: Optional[int]) -> Optional[int]:
    if count is not None and (isinstance(count, bool)
                              or not isinstance(count, int) or count < 0):
        raise ValueError("decision estimates must be nonnegative integers")
    return count


def pack_feeds(feeds: Sequence[FeedEstimate], capacity: int) -> dict:
    """Partition feeds into capacity-constrained groups. Report-only.

    Uses the same deterministic ordering as capacity_preview() (priority
    descending, feed name ascending) and the same additive-greedy counting:
    each feed goes into the first group with room for its estimate. Unknown
    estimates are excluded, never packed. A feed whose estimate alone exceeds
    capacity is excluded with reason "exceeds_group_capacity". Returns groups
    plus an exclusion list; no plan is applied.
    """
    capacity = _check_capacity(capacity)
    if len({f.feed for f in feeds}) != len(feeds):
        raise ValueError("feed names must be unique")
    ordered = sorted(feeds, key=lambda f: (-f.priority, f.feed))
    groups: List[dict] = []
    excluded = []
    for feed in ordered:
        _check_feed(feed.feed)
        count = _check_estimate(feed.estimated_decisions)
        if count is None:
            excluded.append({"feed": feed.feed, "reason": "unknown_estimate"})
            continue
        if count > capacity:
            excluded.append({"feed": feed.feed,
                             "reason": "exceeds_group_capacity"})
            continue
        placed = False
        for group in groups:
            if group["estimated_decisions"] + count <= capacity:
                group["selected"].append(feed.feed)
                group["estimated_decisions"] += count
                placed = True
                break
        if not placed:
            groups.append({"group": len(groups) + 1,
                           "selected": [feed.feed],
                           "estimated_decisions": count})
    return {"report_only": True, "capacity": capacity,
            "groups": groups, "excluded": excluded,
            "estimate_method": "additive_greedy_first_fit"}
