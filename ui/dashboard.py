"""
Terminal Dashboard.

A live, colorized, in-place-updating console view built with `rich`, as an
alternative to the plain scrolling console output from main.py. Shows two
panels — Rule Alerts and Flow Anomalies — laid out side-by-side at a 50/50
split and colored properly instead of scrolling past.

The payload-signature alerts (HTTP SQLi / XSS / traversal / Shellshock /
scanner-UA matches) detected in Stage 5 still fire from the Rule Engine,
but no longer have their own dashboard panel — they appear in the console
output (main.py) only, so this view stays focused on the two highest-
signal panels.

Thread-safety note: alert/anomaly data arrives on the capture thread
(via the Dashboard*Handler adapters in handlers.py) while rich.Live renders
on its own background thread roughly `refresh_per_second` times a second.
A lock guards the shared deques; render() takes a quick snapshot under the
lock and does all formatting outside it, so rendering never blocks capture.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Optional

from rich.align import Align
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from flow_analyzer.models import FlowAnomaly
from rule_engine.models import Alert

from .config import DashboardConfig

_SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "warning": "bold yellow",
    "low": "cyan",
    "info": "dim white",
}


def _fmt_time(dt) -> str:
    return dt.strftime("%H:%M:%S")


class TerminalDashboard:
    def __init__(self, config: Optional[DashboardConfig] = None) -> None:
        self.config = config or DashboardConfig()
        self._lock = threading.Lock()

        self._alerts: deque[Alert] = deque(maxlen=self.config.max_alerts)
        self._anomalies: deque[FlowAnomaly] = deque(maxlen=self.config.max_anomalies)

        self._alerts_seen = 0
        self._anomalies_seen = 0

    # -- data intake (called from Dashboard*Handler adapters) ---------------

    def add_alert(self, alert: Alert) -> None:
        with self._lock:
            self._alerts.append(alert)
            self._alerts_seen += 1

    def add_anomaly(self, anomaly: FlowAnomaly) -> None:
        with self._lock:
            self._anomalies.append(anomaly)
            self._anomalies_seen += 1

    def _snapshot(self) -> tuple[list, list, int, int]:
        with self._lock:
            return (
                list(self._alerts),
                list(self._anomalies),
                self._alerts_seen,
                self._anomalies_seen,
            )

    # -- rendering ------------------------------------------------------------

    def _render_header(self, alerts_seen: int, anomalies_seen: int) -> Panel:
        banner = Text()
        banner.append("FARHAN\n", style="bold yellow")
        banner.append("IDS", style="bold red")
        counts = Text(
            f"alerts: {alerts_seen}   anomalies: {anomalies_seen}",
            style="dim white",
        )
        body = Text.assemble(banner, "\n", counts)
        return Panel(Align.center(body), border_style="grey50")

    def _render_alerts(self, alerts: list[Alert]) -> Panel:
        table = Table(expand=True, show_edge=False, pad_edge=False)
        table.add_column("Time", width=8)
        table.add_column("Severity", width=9)
        table.add_column("Rule", no_wrap=True, overflow="ellipsis", max_width=18)
        table.add_column("Message")

        for a in reversed(alerts):
            style = _SEVERITY_STYLE.get(a.severity.value, "white")
            table.add_row(
                _fmt_time(a.timestamp),
                Text(a.severity.value.upper(), style=style),
                a.rule_name,
                a.message,
            )

        return Panel(table, title="Rule Alerts", border_style="red")

    def _render_anomalies(self, anomalies: list[FlowAnomaly]) -> Panel:
        table = Table(expand=True, show_edge=False, pad_edge=False)
        table.add_column("Time", width=8)
        table.add_column("Severity", width=9)
        table.add_column("Type", no_wrap=True, overflow="ellipsis", max_width=14)
        table.add_column("Message")

        for a in reversed(anomalies):
            style = _SEVERITY_STYLE.get(a.severity, "white")
            table.add_row(
                _fmt_time(a.timestamp),
                Text(a.severity.upper(), style=style),
                a.anomaly_type.value,
                a.message,
            )

        return Panel(table, title="Flow Anomalies", border_style="magenta")

    def render(self) -> Layout:
        (
            alerts,
            anomalies,
            alerts_seen,
            anomalies_seen,
        ) = self._snapshot()

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="body"),
        )
        # Two panels share the body 50/50, side-by-side.
        # ratio=1 each gives an even horizontal split.
        layout["body"].split_row(
            Layout(name="alerts", ratio=1, minimum_size=10),
            Layout(name="anomalies", ratio=1, minimum_size=10),
        )

        layout["header"].update(
            self._render_header(alerts_seen, anomalies_seen)
        )
        layout["alerts"].update(self._render_alerts(alerts))
        layout["anomalies"].update(self._render_anomalies(anomalies))

        return layout

    def run_live(self, blocking_fn) -> None:
        """
        Enter the live full-screen dashboard and call blocking_fn() (e.g.
        CaptureEngine.start) while a background thread refreshes the display
        ~refresh_per_second times a second. Returns when blocking_fn()
        returns (e.g. after Ctrl+C stops the capture loop inside it).
        """
        stop_event = threading.Event()

        def _refresh_loop(live: Live) -> None:
            interval = 1.0 / self.config.refresh_per_second
            while not stop_event.wait(timeout=interval):
                live.update(self.render())

        with Live(self.render(), refresh_per_second=self.config.refresh_per_second, screen=True) as live:
            refresher = threading.Thread(target=_refresh_loop, args=(live,), daemon=True)
            refresher.start()
            try:
                blocking_fn()
            finally:
                stop_event.set()
                refresher.join(timeout=2)
                live.update(self.render())