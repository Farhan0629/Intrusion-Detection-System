"""
Stage 4 entrypoint: live terminal dashboard.

Same three engines as main.py (CaptureEngine, RuleEngine, FlowAnalyzer) —
only the presentation differs. Instead of ConsoleAlertHandler /
ConsoleFlowEventHandler scrolling text past, this wires
DashboardAlertHandler / DashboardFlowEventHandler into a single
TerminalDashboard, which rich.Live renders in-place.

The dashboard shows two panels (Rule Alerts, Flow Anomalies) side-by-side
at a 50/50 split. Payload-signature alerts from the rule engine still fire
and are still printed by main.py's console handler, but are not surfaced
on the dashboard itself — they would otherwise crowd the Rule Alerts panel
during sustained HTTP-attack-signature traffic.

Run (Windows, as Administrator, with Npcap installed):
    python main_dashboard.py
"""

from __future__ import annotations

from pathlib import Path

from packet_capture import CaptureConfig, CaptureEngine
from packet_capture.logger import get_logger
from rule_engine import RuleEngine
from flow_analyzer import FlowAnalyzer
from ui import (
    DashboardAlertHandler,
    DashboardFlowEventHandler,
    TerminalDashboard,
)

logger = get_logger("ids.main_dashboard")

RULES_FILE = Path(__file__).parent / "rules" / "default_rules.rules"


def main() -> None:
    dashboard = TerminalDashboard()

    config = CaptureConfig(
        interface=None,
        bpf_filter="tcp or udp or icmp or arp",
        packet_count=0,
    )

    capture_engine = CaptureEngine(config)

    rule_engine = RuleEngine(rules_file=RULES_FILE)
    rule_engine.register_alert_handler(DashboardAlertHandler(dashboard))
    capture_engine.register_handler(rule_engine)

    flow_analyzer = FlowAnalyzer()
    flow_analyzer.register_event_handler(DashboardFlowEventHandler(dashboard))
    capture_engine.register_handler(flow_analyzer)

    def start_capture() -> None:
        try:
            capture_engine.start(blocking=True)
        except KeyboardInterrupt:
            capture_engine.stop()

    try:
        dashboard.run_live(start_capture)
        print("Stopped.", capture_engine.stats)
    except PermissionError:
        logger.error(
            "Permission denied. On Windows, run this terminal as Administrator "
            "(with Npcap installed). On Linux, run with sudo."
        )


if __name__ == "__main__":
    main()