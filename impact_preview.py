"""Report-only impact preview: what would these feeds have caught?

Compares blocklist feed contents against IP addresses observed in your own
log files and reports, per feed and per preset, how many of those addresses
each feed would have covered - before anything is enabled or imported.

This module is strictly report-only:
  * it never contacts CrowdSec LAPI, adds decisions, or changes any feed
    configuration;
  * it never writes anywhere except the optional HTML report path the
    caller explicitly passes;
  * log contents stay local. Only aggregate counts leave this module.

The HTML report is self-contained (inline CSS/SVG, no external assets) so it
works offline and inside minimal containers.
"""
import bisect
import html
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Candidate tokens that might be IP addresses in arbitrary log text. Kept
# deliberately loose; every candidate is validated with ipaddress below.
_IP_CANDIDATE_RE = re.compile(
    r"(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)"
    r"|(?:\b[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b)"
)

MAX_SAMPLE_IPS = 50


def extract_log_ips(text: str) -> Set[str]:
    """Extract unique, syntactically valid IP addresses from log text.

    Private/reserved addresses are kept: they are real observations in the
    user's logs. They simply will not match public threat feeds.
    """
    found: Set[str] = set()
    for candidate in _IP_CANDIDATE_RE.findall(text):
        try:
            found.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return found


def _entry_intervals(entries: Iterable[str]) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Build merged (start, end) integer intervals for v4 and v6 entries.

    Single addresses become 1-wide intervals. Merging makes the containment
    bisect in covers() exact even when feed ranges overlap.
    """
    v4: List[Tuple[int, int]] = []
    v6: List[Tuple[int, int]] = []
    for entry in entries:
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                interval = (int(net.network_address), int(net.broadcast_address))
            else:
                addr = int(ipaddress.ip_address(entry))
                interval = (addr, addr)
        except ValueError:
            continue
        (v4 if ":" not in entry else v6).append(interval)
    return _merge(v4), _merge(v6)


def _merge(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


class NetworkSet:
    """Fast membership test over a feed's addresses and CIDR ranges."""

    def __init__(self, entries: Iterable[str]) -> None:
        self.v4, self.v6 = _entry_intervals(entries)
        self._v4_starts = [s for s, _ in self.v4]
        self._v6_starts = [s for s, _ in self.v6]

    def covers(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        value = int(addr)
        if isinstance(addr, ipaddress.IPv4Address):
            intervals, starts = self.v4, self._v4_starts
        else:
            intervals, starts = self.v6, self._v6_starts
        idx = bisect.bisect_right(starts, value) - 1
        return idx >= 0 and intervals[idx][1] >= value


@dataclass(frozen=True)
class FeedImpact:
    """Impact of one feed against the observed log addresses."""

    feed: str
    enabled_key: str = ""
    presets: Tuple[str, ...] = ()
    entries: int = 0
    hits: int = 0          # observed log IPs this feed covers
    unique_hits: int = 0   # hits no other analyzed feed covers
    shared_hits: int = 0   # hits at least one other feed also covers
    error: str = ""        # fetch/parse failure; counts then stay zero


@dataclass(frozen=True)
class PresetImpact:
    """Aggregate impact of one preset's default feed set."""

    preset: str
    feeds: int
    entries: int
    hits: int
    marginal_hits: int  # hits not covered by the smaller presets before it


@dataclass(frozen=True)
class ImpactReport:
    """Complete, report-only preview result."""

    log_ips_total: int
    matched_ips: int
    union_entries: int
    feeds: Tuple[FeedImpact, ...]
    presets: Tuple[PresetImpact, ...]
    matched_samples: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    generated_at: str = ""
    log_label: str = ""
    demonstration: bool = False
    feed_scope: str = ""

    @property
    def coverage_pct(self) -> float:
        if not self.log_ips_total:
            return 0.0
        return 100.0 * self.matched_ips / self.log_ips_total


def compute_impact(
    feeds: Sequence[Tuple[str, ...]],
    log_ips: Set[str],
    preset_membership: Optional[Dict[str, Tuple[str, ...]]] = None,
    preset_order: Sequence[str] = ("embedded", "server", "max"),
    samples: bool = True,
    generated_at: Optional[str] = None,
    log_label: str = "",
    demonstration: bool = False,
    feed_scope: str = "",
) -> ImpactReport:
    """Score feeds against observed log IPs. Pure function, no I/O.

    feeds: (feed name, enabled_key, entries) or
    (feed name, enabled_key, entries, error note) tuples; an error note
    marks the feed as failed while keeping the preview going. Duplicate
    names are rejected. preset_membership maps enabled_key -> presets including it by
    default; presets are reported smallest-first per preset_order.
    """
    normalized = []
    for item in feeds:
        if len(item) == 3:
            normalized.append((item[0], item[1], item[2], ""))
        elif len(item) == 4:
            normalized.append((item[0], item[1], item[2], item[3]))
        else:
            raise ValueError("feeds entries must be 3- or 4-tuples")
    feeds = normalized
    names = [name for name, _, _, _ in feeds]
    if len(set(names)) != len(names):
        raise ValueError("feed names must be unique")

    network_sets: Dict[str, NetworkSet] = {}
    per_feed_hits: Dict[str, Set[str]] = {}
    coverage_count: Dict[str, int] = {ip: 0 for ip in log_ips}

    for name, _key, entries, _err in feeds:
        nets = NetworkSet(entries)
        network_sets[name] = nets
        hits = {ip for ip in log_ips if nets.covers(ip)}
        per_feed_hits[name] = hits
        for ip in hits:
            coverage_count[ip] += 1

    membership = preset_membership or {}
    feed_impacts: List[FeedImpact] = []
    for name, key, entries, error in feeds:
        hits = per_feed_hits[name]
        unique = {ip for ip in hits if coverage_count[ip] == 1}
        feed_impacts.append(FeedImpact(
            feed=name,
            enabled_key=key,
            presets=tuple(membership.get(key, ())),
            entries=len(entries),
            hits=len(hits),
            unique_hits=len(unique),
            shared_hits=len(hits) - len(unique),
            error=error,
        ))

    matched = {ip for ip, count in coverage_count.items() if count > 0}
    union_entries = len(set().union(*(e for _, _, e, _ in feeds)) if feeds else set())

    preset_impacts: List[PresetImpact] = []
    covered_so_far: Set[str] = set()
    for preset in preset_order:
        preset_feeds = [
            (name, entries) for name, key, entries, _err in feeds
            if preset in membership.get(key, ())
        ]
        if not preset_feeds:
            continue
        preset_hits: Set[str] = set()
        preset_entries: Set[str] = set()
        for name, entries in preset_feeds:
            preset_hits |= per_feed_hits[name]
            preset_entries |= entries
        preset_impacts.append(PresetImpact(
            preset=preset,
            feeds=len(preset_feeds),
            entries=len(preset_entries),
            hits=len(preset_hits),
            marginal_hits=len(preset_hits - covered_so_far),
        ))
        covered_so_far |= preset_hits

    matched_samples: Dict[str, Tuple[str, ...]] = {}
    if samples:
        for name, _, _, _err in feeds:
            matched_samples[name] = tuple(sorted(per_feed_hits[name])[:MAX_SAMPLE_IPS])

    return ImpactReport(
        log_ips_total=len(log_ips),
        matched_ips=len(matched),
        union_entries=union_entries,
        feeds=tuple(feed_impacts),
        presets=tuple(preset_impacts),
        matched_samples=matched_samples,
        generated_at=generated_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"),
        log_label=log_label,
        demonstration=demonstration,
        feed_scope=feed_scope,
    )


def render_text(report: ImpactReport) -> str:
    """Plain-text summary for the CLI."""
    lines = [
        "IMPACT PREVIEW (report only - nothing enabled, nothing imported)",
        f"Log source: {report.log_label or '(unspecified)'}"
        + (" [SYNTHETIC DEMONSTRATION DATA]" if report.demonstration else ""),
        f"Observed IPs: {report.log_ips_total} | "
        f"Would-have-hit: {report.matched_ips} ({report.coverage_pct:.1f}%) | "
        f"Feed entries analyzed: {report.union_entries}",
        "",
        f"{'Feed':<32} {'Entries':>9} {'Hits':>7} {'Unique':>7} {'Shared':>7}",
    ]
    for feed in sorted(report.feeds, key=lambda f: (-f.hits, f.feed)):
        note = f"  [error: {feed.error}]" if feed.error else ""
        lines.append(
            f"{feed.feed:<32} {feed.entries:>9} {feed.hits:>7} "
            f"{feed.unique_hits:>7} {feed.shared_hits:>7}{note}")
    if report.presets:
        if report.feed_scope:
            lines += ["",
                      f"Preset rows cover only the analyzed feeds "
                      f"(scope: {report.feed_scope})."]
        lines += ["", f"{'Preset':<12} {'Feeds':>6} {'Entries':>9} "
                  f"{'Hits':>7} {'Marginal':>9}"]
        for preset in report.presets:
            lines.append(
                f"{preset.preset:<12} {preset.feeds:>6} {preset.entries:>9} "
                f"{preset.hits:>7} {preset.marginal_hits:>9}")
    lines.append("")
    lines.append("Preview only: no feeds were enabled and no decisions were "
                 "added. Allowlists are not applied in this preview.")
    lines.append("The HTML report may contain matched addresses from the "
                 "input logs; treat it as sensitive and do not publish it.")
    return "\n".join(lines)


_SVG_BAR_HEIGHT = 22
_SVG_ROW_GAP = 8
_SVG_LABEL_W = 210
_SVG_VALUE_W = 70
_SVG_BAR_MAX_W = 460


def _svg_bars(rows: Sequence[Tuple[str, int, int, str]],
              unique_color: str = "#2f9e6e",
              shared_color: str = "#7fb8dd") -> str:
    """Stacked horizontal bars: (label, unique, shared, tooltip) rows."""
    if not rows:
        return ""
    max_total = max((u + s) for _, u, s, _ in rows) or 1
    height = len(rows) * (_SVG_BAR_HEIGHT + _SVG_ROW_GAP) + _SVG_ROW_GAP
    width = _SVG_LABEL_W + _SVG_BAR_MAX_W + _SVG_VALUE_W + 12
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" role="img" font-family="monospace" font-size="12">'
    ]
    y = _SVG_ROW_GAP
    for label, unique, shared, _tip in rows:
        total = unique + shared
        unique_w = round(_SVG_BAR_MAX_W * unique / max_total)
        shared_w = round(_SVG_BAR_MAX_W * shared / max_total)
        esc_label = html.escape(label)
        parts.append(
            f'<text x="0" y="{y + 15}" fill="#333">{esc_label}</text>')
        if unique_w:
            parts.append(
                f'<rect x="{_SVG_LABEL_W}" y="{y}" width="{unique_w}" '
                f'height="{_SVG_BAR_HEIGHT}" fill="{unique_color}">'
                f"<title>{esc_label}: {unique} unique hits</title></rect>")
        if shared_w:
            parts.append(
                f'<rect x="{_SVG_LABEL_W + unique_w}" y="{y}" '
                f'width="{shared_w}" height="{_SVG_BAR_HEIGHT}" '
                f'fill="{shared_color}">'
                f"<title>{esc_label}: {shared} shared hits</title></rect>")
        parts.append(
            f'<text x="{_SVG_LABEL_W + unique_w + shared_w + 8}" '
            f'y="{y + 15}" fill="#333">{total}</text>')
        y += _SVG_BAR_HEIGHT + _SVG_ROW_GAP
    parts.append("</svg>")
    return "".join(parts)


_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
margin:2rem auto;max-width:960px;color:#1a1a1a;padding:0 1rem}
h1{font-size:1.4rem;margin-bottom:.2rem}
h2{font-size:1.05rem;margin-top:2rem}
.banner{background:#fff3cd;border:1px solid #e0c56e;border-radius:6px;
padding:.6rem .9rem;margin:.8rem 0;font-weight:600}
.demo{background:#f8d7da;border-color:#d98c94}
.cards{display:flex;flex-wrap:wrap;gap:.8rem;margin:1rem 0}
.card{border:1px solid #ddd;border-radius:8px;padding:.7rem 1rem;
min-width:150px}
.card .num{font-size:1.5rem;font-weight:700}
.card .lbl{font-size:.8rem;color:#555}
table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{border-bottom:1px solid #e3e3e3;text-align:right;padding:.3rem .5rem}
th:first-child,td:first-child{text-align:left}
.legend span{display:inline-block;margin-right:1rem;font-size:.8rem}
.swatch{display:inline-block;width:.8rem;height:.8rem;border-radius:2px;
margin-right:.3rem;vertical-align:middle}
details{margin:.3rem 0;font-size:.85rem}
.meta{color:#666;font-size:.78rem;margin-top:2rem}
code{background:#f4f4f4;padding:0 .3rem;border-radius:3px}
"""


def render_html(report: ImpactReport) -> str:
    """Self-contained graphical HTML report (inline CSS/SVG, no JS)."""
    esc = html.escape
    banner_class = "banner demo" if report.demonstration else "banner"
    banner_text = (
        "SYNTHETIC DEMONSTRATION DATA - not an analysis of real logs. "
        if report.demonstration else "") + (
        "Report only: previewing impact. No feeds were enabled, no decisions "
        "were added, and no live blocking rules were changed.")

    cards = "".join(
        f'<div class="card"><div class="num">{num}</div>'
        f'<div class="lbl">{lbl}</div></div>'
        for num, lbl in [
            (report.log_ips_total, "observed IPs in log input"),
            (f"{report.matched_ips} ({report.coverage_pct:.1f}%)",
             "would have hit a feed"),
            (report.union_entries, "feed entries analyzed"),
            (len(report.feeds), "feeds analyzed"),
        ])

    sorted_feeds = sorted(report.feeds, key=lambda f: (-f.hits, f.feed))
    hit_rows = [
        (f.feed if len(f.feed) <= 28 else f.feed[:25] + "...",
         f.unique_hits, f.shared_hits, f.feed)
        for f in sorted_feeds if f.hits > 0]
    hits_svg = _svg_bars(hit_rows) or "<p>No feed would have matched any " \
        "observed address in this input.</p>"

    entry_rows = [
        (f.feed if len(f.feed) <= 28 else f.feed[:25] + "...",
         f.entries, 0, f.feed)
        for f in sorted(report.feeds, key=lambda f: (-f.entries, f.feed))]
    entries_svg = _svg_bars(entry_rows, unique_color="#8884d8")

    feed_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
        "<td>{}</td></tr>".format(
            esc(f.feed) + (' <span title="fetch/parse problem">'
                           "&#9888;</span>" if f.error else ""),
            f.entries, f.hits, f.unique_hits, f.shared_hits,
            esc(", ".join(f.presets) if f.presets else "-"))
        for f in sorted_feeds)

    preset_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
        .format(esc(p.preset), p.feeds, p.entries, p.hits, p.marginal_hits)
        for p in report.presets)
    preset_section = ""
    if report.presets:
        scope_note = (
            f"<p><strong>Preset rows cover only the {len(report.feeds)} "
            f"analyzed feeds (scope: {esc(report.feed_scope)}).</strong> "
            "Run with --impact-preview-all-feeds to compare full presets.</p>"
            if report.feed_scope else "")
        preset_section = (
            "<h2>Preset ladder</h2><p>Marginal hits are observed addresses a "
            "preset would cover that every smaller preset above it missed."
            f"</p>{scope_note}"
            "<table><tr><th>Preset</th><th>Feeds</th><th>Entries</th>"
            "<th>Hits</th><th>Marginal hits</th></tr>"
            f"{preset_rows}</table>")

    drilldowns = "".join(
        "<details><summary>{} - {} matched (showing up to {})</summary>"
        "<p><code>{}</code></p></details>".format(
            esc(f.feed), f.hits, MAX_SAMPLE_IPS,
            esc(", ".join(report.matched_samples.get(f.feed, ())) or "none"))
        for f in sorted_feeds if f.hits > 0)
    drilldown_section = (
        f"<h2>Matched addresses per feed (sample)</h2>{drilldowns}"
        if drilldowns else "")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocklist impact preview (report only)</title>
<style>{_CSS}</style></head><body>
<h1>Blocklist impact preview</h1>
<div class="{banner_class}">{esc(banner_text)}</div>
<div class="cards">{cards}</div>
<h2>Would-have-hit per feed</h2>
<div class="legend">
<span><span class="swatch" style="background:#2f9e6e"></span>unique hits
(only this feed covers the address)</span>
<span><span class="swatch" style="background:#7fb8dd"></span>shared hits
(other analyzed feeds cover it too)</span>
</div>
{hits_svg}
<h2>Feed size (entries)</h2>
{entries_svg}
{preset_section}
<h2>Per-feed detail</h2>
<table><tr><th>Feed</th><th>Entries</th><th>Hits</th><th>Unique</th>
<th>Shared</th><th>In presets</th></tr>{feed_rows}</table>
{drilldown_section}
<p class="meta">Generated {esc(report.generated_at)} by
crowdsec-blocklist-import --impact-preview. Log input:
{esc(report.log_label or "(unspecified)")}. Feed contents are the snapshots
fetched at generation time. Allowlists are not applied in this preview;
import-time allowlists can only reduce the counts shown here. This report
may contain matched addresses from the input logs: it was generated locally
and is not uploaded anywhere - treat it as sensitive and do not publish
reports built from real logs.</p>
</body></html>"""
