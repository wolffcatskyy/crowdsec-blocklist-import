import pytest
from autopilot_report import FeedObservation, FeedEstimate, hit_status, capacity_preview


@pytest.mark.parametrize("observation", [
    FeedObservation("a"), FeedObservation("a", 0, 3600, False),
    FeedObservation("a", 0, 3600, True, True),
    FeedObservation("a", 0, 3599, True), FeedObservation("a", 0, None, True),
])
def test_incomplete_telemetry_is_unknown(observation):
    assert hit_status(observation, 3600) == "unknown"


@pytest.mark.parametrize("hits,status", [(0, "zero_observed_hits"), (1, "observed_hits")])
def test_complete_window(hits, status):
    assert hit_status(FeedObservation("a", hits, 3600, True), 3600) == status


def test_bad_window_and_hits():
    for obs, window in [(FeedObservation("a"), 0),
                        (FeedObservation("a", -1), 1),
                        (FeedObservation("a", 0, -1), 1)]:
        with pytest.raises(ValueError):
            hit_status(obs, window)


def test_capacity_boundary_and_unknown():
    result = capacity_preview([FeedEstimate("b", 5), FeedEstimate("a", 5),
                               FeedEstimate("c", 1), FeedEstimate("d", None)], 10)
    assert result["selected"] == ["a", "b"]
    assert result["estimated_decisions"] == 10
    assert result["excluded"] == [{"feed": "c", "reason": "capacity"},
                                  {"feed": "d", "reason": "unknown_estimate"}]
    assert result["report_only"] is True


def test_priority_and_determinism():
    feeds = [FeedEstimate("a", 6), FeedEstimate("b", 8, 10), FeedEstimate("c", 2)]
    assert capacity_preview(feeds, 10) == capacity_preview(list(reversed(feeds)), 10)
    assert capacity_preview(feeds, 10)["selected"] == ["b", "c"]


@pytest.mark.parametrize("capacity", [None, 0, -1, True, 1.5])
def test_capacity_must_be_configured(capacity):
    with pytest.raises(ValueError):
        capacity_preview([], capacity)


def test_duplicate_and_invalid_estimates():
    for feeds in [[FeedEstimate("a", 1), FeedEstimate("a", 2)],
                  [FeedEstimate("a", -1)], [FeedEstimate("a", True)]]:
        with pytest.raises(ValueError):
            capacity_preview(feeds, 10)
