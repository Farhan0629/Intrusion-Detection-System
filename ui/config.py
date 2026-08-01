"""Configuration for the terminal dashboard."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DashboardConfig:
    # Rule-alert deque is kept deep (200) so it always has more rows than
    # the terminal can render. Visible-on-screen count is still capped by
    # terminal height — this just prevents the deque from evicting entries
    # before they ever get drawn (the old maxlen=12 cut the visible table
    # to roughly half the panel and made older alerts disappear as soon as
    # new ones arrived).
    max_alerts: int = 200
    # Anomalies: bumped to 20 so multi-stage attacks (e.g. tcp-scan
    # followed by brute-force, syn-flood, udp-flood in quick succession) are
    # all visible at once. The visible-on-screen count is still capped by
    # terminal height; this just keeps the deque deep enough that the
    # displayed rows are the most recent ones when the panel is tall.
    max_anomalies: int = 200
    refresh_per_second: float = 4.0