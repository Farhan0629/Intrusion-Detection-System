"""
Adapters that let the same TerminalDashboard receive data from both
engines, each through the correct interface (AlertHandler, FlowEventHandler)
— mirrors the ConsoleAlertHandler / ConsoleFlowEventHandler pattern in
main.py, just writing into the dashboard instead of printing directly.
"""

from __future__ import annotations

from flow_analyzer.interfaces import FlowEventHandler
from flow_analyzer.models import FlowAnomaly
from rule_engine.interfaces import AlertHandler
from rule_engine.models import Alert

from .dashboard import TerminalDashboard


class DashboardAlertHandler(AlertHandler):
    def __init__(self, dashboard: TerminalDashboard) -> None:
        self._dashboard = dashboard

    def handle(self, alert: Alert) -> None:
        self._dashboard.add_alert(alert)


class DashboardFlowEventHandler(FlowEventHandler):
    def __init__(self, dashboard: TerminalDashboard) -> None:
        self._dashboard = dashboard

    def handle(self, anomaly: FlowAnomaly) -> None:
        self._dashboard.add_anomaly(anomaly)