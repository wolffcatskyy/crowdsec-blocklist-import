import pytest
from autopilot_metrics import (
    DeadFeedFinding,
    HitRateCollector,
    detect_dead_feeds,
    pack_feeds,
    quarantine_review,
)
from autopilot_report import FeedEstimate, FeedObservation, hit_status


def test_collector_zero_vs_observed():
    collector = HitRateCollector()
    collector.record("hits", 3)
    collector.record("hits", 2)
    observations = {o.feed: o for o in collector.close_window(3600, ["hits", "quiet"])}
    assert hit_status(observations["hits"], 3600) == "observed_hits"
    assert observations["hits"].hits == 5
    assert hit_status(observations["quiet"], 3600) == "zero_observed_hits"
    assert observations["quiet"].hits == 0


def test_collector_partial_window_is_unknown():
    collector = HitRateCollector()
    collector.record("a", 4)
    collector.mark_partial()
    observations = collector.close_window(3600, ["a"])
    assert len(observations) == 1
    assert hit_status(observations[0], 3600) == "unknown"


def test_collector_resets_between_windows():
    collector = HitRateCollector()
    collector.record("a", 2)
    collector.close_window(3600, ["a"])
    observations = collector.close_window(3600, ["a"])
    assert observations[0].hits == 0
    assert hit_status(observations[0], 3600) == "zero_observed_hits"


def test_collector_recorded_but_unmonitored_feed_kept():
    collector = HitRateCollector()
    collector.record("surprise", 1)
    observations = collector.close_window(3600, ["expected"])
    assert {o.feed for o in observations} == {"surprise", "expected"}


def test_collector_sorted_and_validated():
    collector = HitRateCollector()
    with pytest.raises(ValueError):
        collector.record("", 1)
    with pytest.raises(ValueError):
        collector.record("a", -1)
    with pytest.raises(ValueError):
        collector.record("a", True)
    with pytest.raises(ValueError):
        collector.close_window(0, ["a"])
    with pytest.raises(ValueError):
        collector.close_window(True, ["a"])


def window(feed, hits, seconds=3600, complete=True, stale=False):
    return FeedObservation(feed, hits, seconds, complete, stale)


def test_dead_feed_after_consecutive_zeros():
    histories = {"a": [window("a", 0), window("a", 0), window("a", 0)]}
    findings = detect_dead_feeds(histories, 3600, 3)
    assert findings == [DeadFeedFinding("a", 3, 3600)]


def test_dead_feed_streak_broken_by_hits():
    histories = {"a": [window("a", 0), window("a", 5), window("a", 0), window("a", 0)]}
    assert detect_dead_feeds(histories, 3600, 3) == []
    assert detect_dead_feeds(histories, 3600, 2)[0].consecutive_zero_windows == 2


def test_dead_feed_streak_broken_by_unknown():
    histories = {"a": [window("a", 0), window("a", None), window("a", 0), window("a", 0)]}
    assert detect_dead_feeds(histories, 3600, 3) == []


def test_dead_feed_ignores_short_or_stale_windows():
    histories = {
        "short": [window("short", 0, 100), window("short", 0, 100)],
        "stale": [window("stale", 0, 3600, True, True)],
    }
    assert detect_dead_feeds(histories, 3600, 1) == []


def test_dead_feed_sorted_and_validated():
    histories = {
        "b": [window("b", 0), window("b", 0)],
        "a": [window("a", 0), window("a", 0)],
    }
    findings = detect_dead_feeds(histories, 3600, 2)
    assert [f.feed for f in findings] == ["a", "b"]
    with pytest.raises(ValueError):
        detect_dead_feeds(histories, 3600, 0)
    with pytest.raises(ValueError):
        detect_dead_feeds({"a": [window("b", 0)]}, 3600, 1)


def test_quarantine_review_marks_without_applying():
    dead = [DeadFeedFinding("a", 4, 3600)]
    result = quarantine_review(dead, stale_feeds=["s"], unknown_feeds=["u"])
    assert result["report_only"] is True
    assert result["applied"] is False
    assert result["action"] == "review"
    reasons = {c["feed"]: c["reason"] for c in result["candidates"]}
    assert reasons == {"a": "dead_feed", "s": "stale_telemetry", "u": "unknown_telemetry"}
    assert result["candidates"][0]["consecutive_windows"] == 4
    assert result["candidates"][1]["consecutive_windows"] is None


def test_quarantine_review_empty_and_duplicates():
    assert quarantine_review()["candidates"] == []
    with pytest.raises(ValueError):
        quarantine_review([DeadFeedFinding("a", 2, 3600)], stale_feeds=["a"])


def test_pack_feeds_groups_and_exclusions():
    feeds = [FeedEstimate("a", 6), FeedEstimate("b", 8, 10),
             FeedEstimate("c", 2), FeedEstimate("big", 99),
             FeedEstimate("mystery", None)]
    result = pack_feeds(feeds, 10)
    assert result["report_only"] is True
    assert result["groups"][0]["selected"] == ["b", "c"]
    assert result["groups"][0]["estimated_decisions"] == 10
    assert result["groups"][1]["selected"] == ["a"]
    for group in result["groups"]:
        assert group["estimated_decisions"] <= 10
    assert result["excluded"] == [
        {"feed": "big", "reason": "exceeds_group_capacity"},
        {"feed": "mystery", "reason": "unknown_estimate"},
    ]


def test_pack_feeds_deterministic():
    feeds = [FeedEstimate("a", 3), FeedEstimate("b", 3), FeedEstimate("c", 3)]
    assert pack_feeds(feeds, 5) == pack_feeds(list(reversed(feeds)), 5)
    assert [g["selected"] for g in pack_feeds(feeds, 5)["groups"]] == [["a"], ["b"], ["c"]]


def test_pack_feeds_validation():
    with pytest.raises(ValueError):
        pack_feeds([FeedEstimate("a", 1)], 0)
    with pytest.raises(ValueError):
        pack_feeds([FeedEstimate("a", 1), FeedEstimate("a", 2)], 10)
    with pytest.raises(ValueError):
        pack_feeds([FeedEstimate("a", -1)], 10)


def test_recorded_without_declared_monitoring_is_unknown():
    collector = HitRateCollector()
    collector.record('unmonitored', 0)
    observation = collector.close_window(3600)[0]
    assert observation.hits == 0
    assert hit_status(observation, 3600) == 'unknown'
    assert detect_dead_feeds({'unmonitored': [observation]}, 3600, 1) == []


@pytest.mark.parametrize('minimum', [0, -1, True, 1.5])
def test_dead_feed_validates_minimum_even_without_histories(minimum):
    with pytest.raises(ValueError):
        detect_dead_feeds({}, minimum, 1)


def test_invalid_close_window_does_not_discard_events():
    collector = HitRateCollector()
    collector.record('a', 2)
    with pytest.raises(ValueError):
        collector.close_window(0, ['a'])
    assert collector.close_window(3600, ['a'])[0].hits == 2
