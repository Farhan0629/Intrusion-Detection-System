"""
Tests for enhanced real-time anomaly detection capabilities:
  - Subnet Ping Sweep detection
  - HTTP Attack Burst detection
  - Instant Rate-Velocity Spike detection (zero delay)
  - Multi-stage Early Warning vs Critical Escalation
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packet_capture.models import PacketData, Protocol
from flow_analyzer import AnomalyType, FlowAnalyzer, FlowAnalyzerConfig, FlowEventHandler


class CollectingHandler(FlowEventHandler):
    def __init__(self):
        self.anomalies = []

    def handle(self, anomaly):
        self.anomalies.append(anomaly)


def _tcp_packet(ts, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=51000, dst_port=80, flags="SYN", payload=b""):
    return PacketData(
        timestamp=ts,
        protocol=Protocol.TCP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        ttl=64,
        packet_size=60 + len(payload),
        payload_length=len(payload),
        tcp_payload=payload,
    )


def _icmp_packet(ts, src_ip="10.0.0.1", dst_ip="10.0.0.2"):
    return PacketData(
        timestamp=ts,
        protocol=Protocol.ICMP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ttl=64,
        packet_size=60,
    )


def test_ping_sweep_detection_triggers():
    config = FlowAnalyzerConfig(ping_sweep_unique_target_threshold=5, ping_sweep_window_seconds=5)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # Target 6 distinct destination IPs with ICMP echo requests
    for i in range(6):
        analyzer.handle(_icmp_packet(base + timedelta(milliseconds=i * 100), dst_ip=f"192.168.1.{i+10}"))

    sweeps = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.PING_SWEEP]
    assert len(sweeps) >= 1
    high_sweeps = [a for a in sweeps if a.severity == "high"]
    assert len(high_sweeps) == 1
    assert high_sweeps[0].source_ip == "10.0.0.1"
    assert high_sweeps[0].detail["unique_targets"] == 5


def test_http_burst_detection_triggers():
    config = FlowAnalyzerConfig(http_burst_count_threshold=5, http_burst_window_seconds=5)
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # 6 rapid HTTP GET requests
    for i in range(6):
        pkt = _tcp_packet(
            base + timedelta(milliseconds=i * 100),
            dst_port=80,
            flags="PA",
            payload=b"GET /index.php?id=1' OR '1'='1 HTTP/1.1\r\nHost: target\r\n\r\n",
        )
        analyzer.handle(pkt)

    bursts = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.HTTP_BURST]
    assert len(bursts) >= 1
    high_bursts = [a for a in bursts if a.severity == "high"]
    assert len(high_bursts) == 1
    assert high_bursts[0].source_ip == "10.0.0.1"


def test_instant_velocity_spike_detection():
    config = FlowAnalyzerConfig(
        syn_flood_velocity_threshold=20.0,  # 20 pps
        syn_flood_count_threshold=100,      # normal threshold is 100
        syn_flood_window_seconds=5,
    )
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # Send 12 packets in 100ms (rate ~120 pps, well above 20 pps threshold)
    for i in range(12):
        analyzer.handle(
            _tcp_packet(
                base + timedelta(milliseconds=i * 8),
                src_ip=f"10.0.1.{i}",
                dst_ip="10.0.0.2",
                flags="SYN",
            )
        )

    # Anomaly should trigger instantly via velocity spike even though total count (12) < count threshold (100)
    syn_anomalies = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.SYN_FLOOD]
    assert len(syn_anomalies) >= 1
    assert any("velocity spike" in a.message for a in syn_anomalies)


def test_early_warning_escalation():
    config = FlowAnalyzerConfig(
        enable_early_warning=True,
        port_scan_early_threshold=3,
        port_scan_unique_port_threshold=6,
        port_scan_window_seconds=10,
        anomaly_cooldown_seconds=60,
    )
    analyzer = FlowAnalyzer(config)
    collector = CollectingHandler()
    analyzer.register_event_handler(collector)

    base = datetime.now(timezone.utc)
    # Touch 3 unique ports -> should trigger warning
    for port in range(1, 4):
        analyzer.handle(_tcp_packet(base + timedelta(milliseconds=port * 50), dst_port=port, flags="SYN"))

    warnings = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.PORT_SCAN and a.severity == "warning"]
    assert len(warnings) == 1

    # Continue scanning to touch 6 unique ports -> should escalate to high severity anomaly
    for port in range(4, 7):
        analyzer.handle(_tcp_packet(base + timedelta(milliseconds=port * 50), dst_port=port, flags="SYN"))

    highs = [a for a in collector.anomalies if a.anomaly_type == AnomalyType.PORT_SCAN and a.severity == "high"]
    assert len(highs) == 1
