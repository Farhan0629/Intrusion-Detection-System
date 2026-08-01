import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packet_capture.models import PacketData, Protocol
from flow_analyzer import AnomalyType, FlowAnalyzer, FlowAnalyzerConfig, FlowEventHandler


def _tcp_packet(ts, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=51000, dst_port=80, flags=None, size=60):
    return PacketData(
        timestamp=ts,
        protocol=Protocol.TCP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        ttl=64,
        packet_size=size,
    )


class CollectingHandler(FlowEventHandler):
    def __init__(self):
        self.anomalies = []

    def handle(self, anomaly):
        self.anomalies.append(anomaly)


def test_flow_tracking_counts_packets_and_bytes():
    analyzer = FlowAnalyzer()
    base = datetime.now(timezone.utc)

    analyzer.handle(_tcp_packet(base, size=100))
    analyzer.handle(_tcp_packet(base + timedelta(seconds=1), size=200))

    assert analyzer.active_flow_count == 1
    flow = next(iter(analyzer.flows.values()))
    assert flow.packet_count == 2
    assert flow.byte_count == 300


def test_different_5_tuples_create_separate_flows():
    analyzer = FlowAnalyzer()
    base = datetime.now(timezone.utc)

    analyzer.handle(_tcp_packet(base, dst_port=80))
    analyzer.handle(_tcp_packet(base, dst_port=443))

    assert analyzer.active_flow_count == 2


def test_syn_fin_rst_counts_tracked():
    analyzer = FlowAnalyzer()
    base = datetime.now(timezone.utc)

    analyzer.handle(_tcp_packet(base, flags="SYN"))
    analyzer.handle(_tcp_packet(base + timedelta(seconds=1), flags="SYN,ACK"))
    analyzer.handle(_tcp_packet(base + timedelta(seconds=2), flags="FIN,ACK"))

    flow = next(iter(analyzer.flows.values()))
    assert flow.syn_count == 2
    assert flow.fin_count == 1


def test_idle_flow_expiry():
    config = FlowAnalyzerConfig(idle_timeout_seconds=5)
    analyzer = FlowAnalyzer(config)
    base = datetime.now(timezone.utc)

    analyzer.handle(_tcp_packet(base))
    assert analyzer.active_flow_count == 1

    analyzer.expire_idle_flows(now=base + timedelta(seconds=10))
    assert analyzer.active_flow_count == 0


def test_port_scan_detection_triggers_above_threshold():
    config = FlowAnalyzerConfig(port_scan_unique_port_threshold=5, port_scan_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i, port in enumerate(range(1, 7)):  # 6 unique ports, threshold is 5
        analyzer.handle(_tcp_packet(base + timedelta(milliseconds=i * 100), dst_port=port, flags="SYN"))

    port_scan_alerts = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.PORT_SCAN]
    assert len(port_scan_alerts) == 1
    assert port_scan_alerts[0].source_ip == "10.0.0.1"


def test_port_scan_not_triggered_below_threshold():
    config = FlowAnalyzerConfig(port_scan_unique_port_threshold=15, port_scan_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for port in range(1, 6):  # only 5 unique ports
        analyzer.handle(_tcp_packet(base, dst_port=port, flags="SYN"))

    assert len(collector.anomalies) == 0


def test_port_scan_window_excludes_old_activity():
    config = FlowAnalyzerConfig(port_scan_unique_port_threshold=5, port_scan_window_seconds=2)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # 3 ports well outside the window, then 3 more inside a fresh window — should never reach 5 within the window
    for port in range(1, 4):
        analyzer.handle(_tcp_packet(base, dst_port=port, flags="SYN"))
    for port in range(4, 7):
        analyzer.handle(_tcp_packet(base + timedelta(seconds=5), dst_port=port, flags="SYN"))

    assert len(collector.anomalies) == 0


def test_port_scan_not_triggered_by_udp_dns_server_replies():
    """
    Regression test: a DNS server replying to many different clients uses a
    different (client-chosen) reply port each time. That must never look
    like the server port-scanning its clients.
    """
    config = FlowAnalyzerConfig(port_scan_unique_port_threshold=5, port_scan_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    dns_server = "10.230.133.180"
    for i, client_reply_port in enumerate([64900, 50923, 53556, 55855, 52433, 60685]):
        pkt = PacketData(
            timestamp=base + timedelta(milliseconds=i * 100),
            protocol=Protocol.UDP,
            src_ip=dns_server,
            dst_ip="10.230.133.198",
            src_port=53,
            dst_port=client_reply_port,
            ttl=64,
            packet_size=120,
        )
        analyzer.handle(pkt)

    assert len(collector.anomalies) == 0


def test_port_scan_triggers_only_on_bare_syn_not_syn_ack():
    config = FlowAnalyzerConfig(port_scan_unique_port_threshold=3, port_scan_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # SYN,ACK replies to 4 different ports should NOT count as scanning
    for port in range(1, 5):
        analyzer.handle(_tcp_packet(base, dst_port=port, flags="SYN,ACK"))
    assert len(collector.anomalies) == 0

    # Bare SYN to 3 different ports SHOULD trigger (threshold is 3)
    for port in range(10, 13):
        analyzer.handle(_tcp_packet(base, dst_port=port, flags="SYN"))
    assert len(collector.anomalies) == 1


def test_syn_flood_detection_triggers_above_threshold():
    config = FlowAnalyzerConfig(syn_flood_count_threshold=10, syn_flood_window_seconds=5)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i in range(12):
        analyzer.handle(
            _tcp_packet(base + timedelta(milliseconds=i * 50), src_ip=f"10.0.1.{i}", dst_ip="10.0.0.2", flags="SYN")
        )

    flood_alerts = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.SYN_FLOOD]
    assert len(flood_alerts) == 1
    assert flood_alerts[0].source_ip == "10.0.0.2"  # the victim


def test_syn_flood_ignores_non_syn_packets():
    config = FlowAnalyzerConfig(syn_flood_count_threshold=5, syn_flood_window_seconds=5)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i in range(10):
        analyzer.handle(_tcp_packet(base, dst_ip="10.0.0.2", flags="ACK"))

    assert len(collector.anomalies) == 0


def test_anomaly_cooldown_suppresses_repeat_alerts():
    config = FlowAnalyzerConfig(
        port_scan_unique_port_threshold=3, port_scan_window_seconds=100, anomaly_cooldown_seconds=60
    )
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for port in range(1, 4):
        analyzer.handle(_tcp_packet(base, dst_port=port, flags="SYN"))
    # Trigger again shortly after — should be suppressed by cooldown
    for port in range(4, 7):
        analyzer.handle(_tcp_packet(base + timedelta(seconds=1), dst_port=port, flags="SYN"))

    port_scan_alerts = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.PORT_SCAN]
    assert len(port_scan_alerts) == 1


# -- Stage 5: five new detectors --------------------------------------------

def _udp_packet(ts, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=51000, dst_port=53, size=80, payload_len=64):
    return PacketData(
        timestamp=ts,
        protocol=Protocol.UDP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        ttl=64,
        packet_size=size,
        payload_length=payload_len,
        udp_payload=b"x" * payload_len,
    )


def _icmp_packet(ts, src_ip="10.0.0.1"):
    return PacketData(
        timestamp=ts,
        protocol=Protocol.ICMP,
        src_ip=src_ip,
        dst_ip="10.0.0.2",
        ttl=64,
        packet_size=60,
    )


def test_brute_force_detection_triggers_above_threshold():
    config = FlowAnalyzerConfig(brute_force_attempt_threshold=5, brute_force_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i in range(6):  # 6 attempts to the same (src, dst_port=22)
        analyzer.handle(
            _tcp_packet(base + timedelta(milliseconds=i * 100), dst_port=22, flags="SYN")
        )

    bf = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.BRUTE_FORCE]
    assert len(bf) == 1
    assert bf[0].source_ip == "10.0.0.1"
    assert bf[0].detail["target_port"] == 22


def test_brute_force_only_triggers_per_dst_port():
    """Hammering port 22 and 80 in turn should each trigger — counted per port,
    but cooldown is per (anomaly_type, src_ip) so a single attacker still only
    gets one alert per cooldown window regardless of which service they hit.
    """
    config = FlowAnalyzerConfig(brute_force_attempt_threshold=3, brute_force_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for port in (22, 80):
        for i in range(3):
            analyzer.handle(
                _tcp_packet(base + timedelta(milliseconds=i * 100), dst_port=port, flags="SYN")
            )
    # Both ports trip threshold, but cooldown suppresses the second alert.
    bf = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.BRUTE_FORCE]
    assert len(bf) == 1


def test_brute_force_ignores_syn_ack_replies():
    """SYN,ACK replies to connection attempts are not brute-force traffic."""
    config = FlowAnalyzerConfig(brute_force_attempt_threshold=3, brute_force_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i in range(6):
        analyzer.handle(_tcp_packet(base, dst_port=22, flags="SYN,ACK"))
    assert len(collector.anomalies) == 0


def test_udp_flood_detection_triggers_above_threshold():
    config = FlowAnalyzerConfig(udp_flood_count_threshold=10, udp_flood_window_seconds=5)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i in range(12):
        analyzer.handle(_udp_packet(base + timedelta(milliseconds=i * 50), dst_port=1234))

    floods = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.UDP_FLOOD]
    assert len(floods) == 1
    assert floods[0].source_ip == "10.0.0.1"


def test_icmp_flood_detection_triggers_above_threshold():
    config = FlowAnalyzerConfig(icmp_flood_count_threshold=10, icmp_flood_window_seconds=5)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for i in range(12):
        analyzer.handle(_icmp_packet(base + timedelta(milliseconds=i * 50)))

    floods = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.ICMP_FLOOD]
    assert len(floods) == 1


def test_dns_flood_only_counts_dst_port_53():
    config = FlowAnalyzerConfig(dns_flood_count_threshold=5, dns_flood_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # UDP to other ports should NOT count toward DNS flood.
    for i in range(10):
        analyzer.handle(_udp_packet(base, dst_port=1234))
    assert not any(a.anomaly_type == AnomalyType.DNS_FLOOD for a in collector.anomalies)

    # Reset deque for port 53 by using different src_ip so no cooldown kicks in.
    for i in range(6):
        analyzer.handle(
            _udp_packet(base + timedelta(milliseconds=i * 50), src_ip="10.0.0.9", dst_port=53)
        )
    floods = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.DNS_FLOOD]
    assert len(floods) == 1


def test_udp_port_scan_detection_triggers_above_threshold():
    config = FlowAnalyzerConfig(udp_port_scan_unique_port_threshold=5, udp_port_scan_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    for port in range(6):  # 6 distinct UDP ports with non-trivial payload
        analyzer.handle(_udp_packet(base + timedelta(milliseconds=port * 100), dst_port=port + 1))

    scans = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.UDP_PORT_SCAN]
    assert len(scans) == 1


def test_udp_port_scan_ignores_empty_replies():
    """Tiny/empty UDP payloads (e.g. service acks) shouldn't trip the scan detector."""
    config = FlowAnalyzerConfig(udp_port_scan_unique_port_threshold=3, udp_port_scan_window_seconds=10)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # Many distinct ports, all with empty payload → should be ignored.
    for port in range(10):
        analyzer.handle(
            PacketData(
                timestamp=base,
                protocol=Protocol.UDP,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=53,
                dst_port=port + 100,
                ttl=64,
                packet_size=40,
                payload_length=0,
                udp_payload=b"",
            )
        )

    assert not any(a.anomaly_type == AnomalyType.UDP_PORT_SCAN for a in collector.anomalies)
