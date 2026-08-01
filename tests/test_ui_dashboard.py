import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.layout import Layout

from packet_capture.models import PacketData, Protocol
from rule_engine.models import Alert, Severity
from flow_analyzer.models import AnomalyType, FlowAnomaly
from ui import DashboardConfig, TerminalDashboard
from ui.handlers import (
    DashboardAlertHandler,
    DashboardFlowEventHandler,
)


def _packet(dst_port=443, flags="SYN"):
    return PacketData(
        timestamp=datetime.now(timezone.utc),
        protocol=Protocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=51000,
        dst_port=dst_port,
        tcp_flags=flags,
        ttl=64,
        packet_size=60,
    )


def _alert():
    return Alert(rule_name="Test_Rule", severity=Severity.HIGH, message="test alert", packet=_packet())


def _anomaly():
    return FlowAnomaly(anomaly_type=AnomalyType.PORT_SCAN, source_ip="10.0.0.1", message="test anomaly")


def test_alert_and_anomaly_tracked_independently():
    dashboard = TerminalDashboard()
    dashboard.add_alert(_alert())
    dashboard.add_anomaly(_anomaly())

    alerts, anomalies, a_seen, an_seen = dashboard._snapshot()
    assert len(alerts) == 1
    assert len(anomalies) == 1
    assert a_seen == 1
    assert an_seen == 1


def test_alert_deque_bounded_by_config():
    config = DashboardConfig(max_alerts=3)
    dashboard = TerminalDashboard(config)
    for _ in range(10):
        dashboard.add_alert(_alert())

    alerts, _, seen, _ = dashboard._snapshot()
    assert len(alerts) == 3         # only last 3 kept
    assert seen == 10               # but total count is accurate


def test_render_returns_layout_with_data():
    dashboard = TerminalDashboard()
    dashboard.add_alert(_alert())
    dashboard.add_anomaly(_anomaly())

    layout = dashboard.render()
    assert isinstance(layout, Layout)


def test_render_does_not_crash_when_empty():
    dashboard = TerminalDashboard()
    layout = dashboard.render()
    assert isinstance(layout, Layout)


def test_dashboard_alert_handler_adapter_feeds_dashboard():
    dashboard = TerminalDashboard()
    handler = DashboardAlertHandler(dashboard)
    handler.handle(_alert())

    alerts, _, seen, _ = dashboard._snapshot()
    assert seen == 1
    assert len(alerts) == 1


def test_dashboard_flow_event_handler_adapter_feeds_dashboard():
    dashboard = TerminalDashboard()
    handler = DashboardFlowEventHandler(dashboard)
    handler.handle(_anomaly())

    _, anomalies, _, seen = dashboard._snapshot()
    assert seen == 1
    assert len(anomalies) == 1


def test_concurrent_writes_from_multiple_threads_do_not_crash():
    dashboard = TerminalDashboard(DashboardConfig(max_alerts=50))

    def worker():
        for _ in range(200):
            dashboard.add_alert(_alert())

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    _, _, seen, _ = dashboard._snapshot()
    assert seen == 800