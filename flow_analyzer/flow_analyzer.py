"""
Flow Analyzer.

Tracks per-5-tuple flow statistics (packet/byte counts, duration, TCP flag
counts) across packets, and layers sliding-window threshold detections on
top:

  - Port scan: one source IP touching many distinct destination ports quickly.
  - SYN flood: a destination IP receiving a flood of SYN packets quickly.
  - Brute force: one source IP hammering a single (dst_ip, dst_port) with TCP connection attempts.
  - UDP flood / ICMP flood / DNS flood: a single source IP emitting an unusually high volume of those packets in a short window.
  - UDP port scan: a source IP hitting many distinct UDP destination ports quickly.
  - Subnet Ping sweep: a source IP targeting many distinct hosts via ICMP probes.
  - HTTP attack burst: rapid web attack signature requests from one source.

Features zero-delay rate-velocity spike detection and multi-stage early warning
escalations for instant anomaly identification.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Optional

from packet_capture.interfaces import PacketHandler
from packet_capture.logger import get_logger
from packet_capture.models import PacketData

from .config import FlowAnalyzerConfig
from .interfaces import FlowEventHandler
from .models import AnomalyType, Flow, FlowAnomaly, FlowKey

logger = get_logger("ids.flow_analyzer")


def _is_bare_syn(packet: PacketData) -> bool:
    tf = packet.tcp_flags
    if not tf:
        return False
    if tf == "SYN":
        return True
    return "SYN" in tf and "ACK" not in tf


def _calc_velocity(dq: deque, now: datetime) -> float:
    if len(dq) < 2:
        return 0.0
    t_start = dq[0][0] if isinstance(dq[0], tuple) else dq[0]
    elapsed = (now - t_start).total_seconds()
    return len(dq) / (elapsed if elapsed >= 0.05 else 0.05)


class FlowAnalyzer(PacketHandler):
    def __init__(self, config: Optional[FlowAnalyzerConfig] = None) -> None:
        self.config = config or FlowAnalyzerConfig()
        self._flows: dict[FlowKey, Flow] = {}
        self._event_handlers: list[FlowEventHandler] = []

        # src_ip -> deque[(timestamp, dst_port)] for port-scan detection
        self._port_activity: dict[str, deque] = defaultdict(deque)

        # dst_ip -> deque[timestamp] of SYN packets, for SYN-flood detection
        self._syn_activity: dict[str, deque] = defaultdict(deque)

        # (anomaly_type, source_ip, severity) -> last time an alert fired, for cooldown
        self._last_alert_time: dict[tuple[AnomalyType, str, str], datetime] = {}

        # Activity trackers for sliding-window and velocity detections
        self._brute_force_activity: dict[tuple[str, int], deque] = defaultdict(deque)
        self._udp_flood_activity: dict[str, deque] = defaultdict(deque)
        self._icmp_flood_activity: dict[str, deque] = defaultdict(deque)
        self._dns_flood_activity: dict[str, deque] = defaultdict(deque)
        self._udp_port_activity: dict[str, deque] = defaultdict(deque)

        # Enhanced detectors
        self._ping_sweep_activity: dict[str, deque] = defaultdict(deque)
        self._http_burst_activity: dict[str, deque] = defaultdict(deque)

        logger.info(
            "FlowAnalyzer initialized | port_scan=%d/%.0fs syn_flood=%d/%.0fs "
            "brute_force=%d/%.0fs udp_flood=%d/%.0fs icmp_flood=%d/%.0fs "
            "dns_flood=%d/%.0fs udp_port_scan=%d/%.0fs ping_sweep=%d/%.0fs http_burst=%d/%.0fs",
            self.config.port_scan_unique_port_threshold,
            self.config.port_scan_window_seconds,
            self.config.syn_flood_count_threshold,
            self.config.syn_flood_window_seconds,
            self.config.brute_force_attempt_threshold,
            self.config.brute_force_window_seconds,
            self.config.udp_flood_count_threshold,
            self.config.udp_flood_window_seconds,
            self.config.icmp_flood_count_threshold,
            self.config.icmp_flood_window_seconds,
            self.config.dns_flood_count_threshold,
            self.config.dns_flood_window_seconds,
            self.config.udp_port_scan_unique_port_threshold,
            self.config.udp_port_scan_window_seconds,
            self.config.ping_sweep_unique_target_threshold,
            self.config.ping_sweep_window_seconds,
            self.config.http_burst_count_threshold,
            self.config.http_burst_window_seconds,
        )

    def register_event_handler(self, handler: FlowEventHandler) -> None:
        self._event_handlers.append(handler)
        logger.info("Registered flow event handler: %s", type(handler).__name__)

    # -- flow tracking -----------------------------------------------------

    def _flow_key(self, packet: PacketData) -> Optional[FlowKey]:
        if packet.src_ip is None or packet.dst_ip is None:
            return None
        return FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol.value,
        )

    def _update_flow(self, packet: PacketData) -> Optional[Flow]:
        key = self._flow_key(packet)
        if key is None:
            return None

        now = packet.timestamp
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(key=key, first_seen=now, last_seen=now)
            self._flows[key] = flow

        flow.last_seen = now
        flow.packet_count += 1
        flow.byte_count += packet.packet_size

        if packet.tcp_flags:
            if "SYN" in packet.tcp_flags:
                flow.syn_count += 1
            if "FIN" in packet.tcp_flags:
                flow.fin_count += 1
            if "RST" in packet.tcp_flags:
                flow.rst_count += 1

        return flow

    def expire_idle_flows(self, now: Optional[datetime] = None) -> int:
        """Drop flows that haven't seen a packet within idle_timeout_seconds."""
        now = now or datetime.now(timezone.utc)
        expired = [
            key
            for key, flow in self._flows.items()
            if (now - flow.last_seen).total_seconds() > self.config.idle_timeout_seconds
        ]
        for key in expired:
            del self._flows[key]
        if expired:
            logger.debug("Expired %d idle flow(s)", len(expired))
        return len(expired)

    # -- sliding-window anomaly detection -----------------------------------

    def _prune_window(self, dq: deque, now: datetime, window_seconds: float) -> None:
        while dq and (now - dq[0][0] if isinstance(dq[0], tuple) else now - dq[0]).total_seconds() > window_seconds:
            dq.popleft()

    def _cooldown_ok(self, anomaly_type: AnomalyType, source_ip: str, now: datetime, severity: str = "high") -> bool:
        last = self._last_alert_time.get((anomaly_type, source_ip, severity))
        if last is None:
            return True
        return (now - last).total_seconds() >= self.config.anomaly_cooldown_seconds

    def _raise_anomaly(self, anomaly: FlowAnomaly) -> None:
        self._last_alert_time[(anomaly.anomaly_type, anomaly.source_ip, anomaly.severity)] = anomaly.timestamp
        for handler in self._event_handlers:
            try:
                handler.handle(anomaly)
            except Exception:
                logger.exception("Flow event handler %s raised", type(handler).__name__)

    def _check_port_scan(self, packet: PacketData) -> None:
        if packet.protocol.value != "TCP" or not packet.tcp_flags or packet.src_ip is None or packet.dst_port is None:
            return
        if not _is_bare_syn(packet):
            return

        now = packet.timestamp
        dq = self._port_activity[packet.src_ip]
        dq.append((now, packet.dst_port))
        self._prune_window(dq, now, self.config.port_scan_window_seconds)

        unique_ports = {port for _, port in dq}
        thresh = self.config.port_scan_unique_port_threshold
        early_thresh = min(self.config.port_scan_early_threshold, max(1, thresh // 2))

        if len(unique_ports) >= thresh and self._cooldown_ok(
            AnomalyType.PORT_SCAN, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.PORT_SCAN,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} sent SYN to {len(unique_ports)} distinct ports "
                        f"within {self.config.port_scan_window_seconds:.0f}s — possible port scan"
                    ),
                    timestamp=now,
                    detail={"unique_ports": len(unique_ports), "window_seconds": self.config.port_scan_window_seconds},
                )
            )
        elif self.config.enable_early_warning and len(unique_ports) >= early_thresh and self._cooldown_ok(
            AnomalyType.PORT_SCAN, packet.src_ip, now, severity="warning"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.PORT_SCAN,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} sent SYN to {len(unique_ports)} distinct ports — early port scan warning"
                    ),
                    timestamp=now,
                    detail={"unique_ports": len(unique_ports), "window_seconds": self.config.port_scan_window_seconds},
                )
            )

    def _check_syn_flood(self, packet: PacketData) -> None:
        if packet.protocol.value != "TCP" or not packet.tcp_flags or packet.dst_ip is None:
            return
        if "SYN" not in packet.tcp_flags:
            return

        now = packet.timestamp
        dq = self._syn_activity[packet.dst_ip]
        dq.append(now)
        self._prune_window(dq, now, self.config.syn_flood_window_seconds)

        velocity = _calc_velocity(dq, now)
        thresh = self.config.syn_flood_count_threshold
        early_thresh = min(self.config.syn_flood_early_threshold, max(1, thresh // 2))

        if velocity >= self.config.syn_flood_velocity_threshold and len(dq) >= 10 and self._cooldown_ok(
            AnomalyType.SYN_FLOOD, packet.dst_ip, now, severity="critical"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.SYN_FLOOD,
                    source_ip=packet.dst_ip,
                    severity="critical",
                    message=(
                        f"{packet.dst_ip} receiving SYN velocity spike ({velocity:.0f} pps, "
                        f"{len(dq)} pkts) — instant SYN flood anomaly"
                    ),
                    timestamp=now,
                    detail={"syn_count": len(dq), "pps": round(velocity, 1), "window_seconds": self.config.syn_flood_window_seconds},
                )
            )
        elif len(dq) >= thresh and self._cooldown_ok(
            AnomalyType.SYN_FLOOD, packet.dst_ip, now, severity="critical"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.SYN_FLOOD,
                    source_ip=packet.dst_ip,
                    severity="critical",
                    message=(
                        f"{packet.dst_ip} received {len(dq)} SYN packets within "
                        f"{self.config.syn_flood_window_seconds:.0f}s — possible SYN flood"
                    ),
                    timestamp=now,
                    detail={"syn_count": len(dq), "window_seconds": self.config.syn_flood_window_seconds},
                )
            )
        elif self.config.enable_early_warning and len(dq) >= early_thresh and self._cooldown_ok(
            AnomalyType.SYN_FLOOD, packet.dst_ip, now, severity="warning"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.SYN_FLOOD,
                    source_ip=packet.dst_ip,
                    severity="warning",
                    message=(
                        f"{packet.dst_ip} receiving elevated SYN traffic ({len(dq)} pkts) — early SYN flood warning"
                    ),
                    timestamp=now,
                    detail={"syn_count": len(dq), "window_seconds": self.config.syn_flood_window_seconds},
                )
            )

    def _check_brute_force(self, packet: PacketData) -> None:
        if (
            packet.protocol.value != "TCP"
            or not packet.tcp_flags
            or packet.src_ip is None
            or packet.dst_port is None
        ):
            return
        if not _is_bare_syn(packet):
            return

        now = packet.timestamp
        key = (packet.src_ip, packet.dst_port)
        dq = self._brute_force_activity[key]
        dq.append(now)
        self._prune_window(dq, now, self.config.brute_force_window_seconds)

        thresh = self.config.brute_force_attempt_threshold
        early_thresh = min(self.config.brute_force_early_threshold, max(1, thresh // 2))

        if len(dq) >= thresh and self._cooldown_ok(
            AnomalyType.BRUTE_FORCE, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.BRUTE_FORCE,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} sent {len(dq)} TCP connect attempts to "
                        f"{packet.dst_ip}:{packet.dst_port} within "
                        f"{self.config.brute_force_window_seconds:.0f}s — possible brute force"
                    ),
                    timestamp=now,
                    detail={
                        "attempt_count": len(dq),
                        "target_ip": packet.dst_ip,
                        "target_port": packet.dst_port,
                        "window_seconds": self.config.brute_force_window_seconds,
                    },
                )
            )
        elif self.config.enable_early_warning and len(dq) >= early_thresh and self._cooldown_ok(
            AnomalyType.BRUTE_FORCE, packet.src_ip, now, severity="warning"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.BRUTE_FORCE,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} sent {len(dq)} TCP connect attempts to "
                        f"{packet.dst_ip}:{packet.dst_port} — early brute force warning"
                    ),
                    timestamp=now,
                    detail={
                        "attempt_count": len(dq),
                        "target_ip": packet.dst_ip,
                        "target_port": packet.dst_port,
                        "window_seconds": self.config.brute_force_window_seconds,
                    },
                )
            )

    def _check_udp_flood(self, packet: PacketData) -> None:
        if packet.protocol.value != "UDP" or packet.src_ip is None:
            return
        now = packet.timestamp
        dq = self._udp_flood_activity[packet.src_ip]
        dq.append(now)
        self._prune_window(dq, now, self.config.udp_flood_window_seconds)

        velocity = _calc_velocity(dq, now)
        thresh = self.config.udp_flood_count_threshold
        early_thresh = min(self.config.udp_flood_early_threshold, max(1, thresh // 2))

        if velocity >= self.config.udp_flood_velocity_threshold and len(dq) >= 15 and self._cooldown_ok(
            AnomalyType.UDP_FLOOD, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.UDP_FLOOD,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} UDP rate velocity spike ({velocity:.0f} pps, "
                        f"{len(dq)} pkts) — instant UDP flood anomaly"
                    ),
                    timestamp=now,
                    detail={"packet_count": len(dq), "pps": round(velocity, 1), "window_seconds": self.config.udp_flood_window_seconds},
                )
            )
        elif len(dq) >= thresh and self._cooldown_ok(
            AnomalyType.UDP_FLOOD, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.UDP_FLOOD,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} sent {len(dq)} UDP packets within "
                        f"{self.config.udp_flood_window_seconds:.0f}s — possible UDP flood"
                    ),
                    timestamp=now,
                    detail={"packet_count": len(dq), "window_seconds": self.config.udp_flood_window_seconds},
                )
            )
        elif self.config.enable_early_warning and len(dq) >= early_thresh and self._cooldown_ok(
            AnomalyType.UDP_FLOOD, packet.src_ip, now, severity="warning"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.UDP_FLOOD,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} elevated UDP packet volume ({len(dq)} pkts) — early UDP flood warning"
                    ),
                    timestamp=now,
                    detail={"packet_count": len(dq), "window_seconds": self.config.udp_flood_window_seconds},
                )
            )

    def _check_icmp_flood(self, packet: PacketData) -> None:
        if packet.protocol.value != "ICMP" or packet.src_ip is None:
            return
        now = packet.timestamp
        dq = self._icmp_flood_activity[packet.src_ip]
        dq.append(now)
        self._prune_window(dq, now, self.config.icmp_flood_window_seconds)

        velocity = _calc_velocity(dq, now)
        thresh = self.config.icmp_flood_count_threshold
        early_thresh = min(self.config.icmp_flood_early_threshold, max(1, thresh // 2))

        if velocity >= self.config.icmp_flood_velocity_threshold and len(dq) >= 10 and self._cooldown_ok(
            AnomalyType.ICMP_FLOOD, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.ICMP_FLOOD,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} ICMP rate velocity spike ({velocity:.0f} pps, "
                        f"{len(dq)} pkts) — instant ICMP flood anomaly"
                    ),
                    timestamp=now,
                    detail={"packet_count": len(dq), "pps": round(velocity, 1), "window_seconds": self.config.icmp_flood_window_seconds},
                )
            )
        elif len(dq) >= thresh and self._cooldown_ok(
            AnomalyType.ICMP_FLOOD, packet.src_ip, now, severity="medium"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.ICMP_FLOOD,
                    source_ip=packet.src_ip,
                    severity="medium",
                    message=(
                        f"{packet.src_ip} sent {len(dq)} ICMP packets within "
                        f"{self.config.icmp_flood_window_seconds:.0f}s — possible ICMP flood"
                    ),
                    timestamp=now,
                    detail={"packet_count": len(dq), "window_seconds": self.config.icmp_flood_window_seconds},
                )
            )
        elif self.config.enable_early_warning and len(dq) >= early_thresh and self._cooldown_ok(
            AnomalyType.ICMP_FLOOD, packet.src_ip, now, severity="warning"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.ICMP_FLOOD,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} elevated ICMP packet volume ({len(dq)} pkts) — early ICMP flood warning"
                    ),
                    timestamp=now,
                    detail={"packet_count": len(dq), "window_seconds": self.config.icmp_flood_window_seconds},
                )
            )

    def _check_dns_flood(self, packet: PacketData) -> None:
        if (
            packet.protocol.value != "UDP"
            or packet.dst_port != 53
            or packet.src_ip is None
        ):
            return
        now = packet.timestamp
        dq = self._dns_flood_activity[packet.src_ip]
        dq.append(now)
        self._prune_window(dq, now, self.config.dns_flood_window_seconds)

        velocity = _calc_velocity(dq, now)
        thresh = self.config.dns_flood_count_threshold
        early_thresh = min(self.config.dns_flood_early_threshold, max(1, thresh // 2))

        if velocity >= self.config.dns_flood_velocity_threshold and len(dq) >= 10 and self._cooldown_ok(
            AnomalyType.DNS_FLOOD, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.DNS_FLOOD,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} DNS query velocity spike ({velocity:.0f} qps, "
                        f"{len(dq)} queries) — instant DNS flood anomaly"
                    ),
                    timestamp=now,
                    detail={"query_count": len(dq), "qps": round(velocity, 1), "window_seconds": self.config.dns_flood_window_seconds},
                )
            )
        elif len(dq) >= thresh and self._cooldown_ok(
            AnomalyType.DNS_FLOOD, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.DNS_FLOOD,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} sent {len(dq)} DNS queries within "
                        f"{self.config.dns_flood_window_seconds:.0f}s — possible DNS flood"
                    ),
                    timestamp=now,
                    detail={"query_count": len(dq), "window_seconds": self.config.dns_flood_window_seconds},
                )
            )
        elif self.config.enable_early_warning and len(dq) >= early_thresh and self._cooldown_ok(
            AnomalyType.DNS_FLOOD, packet.src_ip, now, severity="warning"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.DNS_FLOOD,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} elevated DNS query volume ({len(dq)} queries) — early DNS flood warning"
                    ),
                    timestamp=now,
                    detail={"query_count": len(dq), "window_seconds": self.config.dns_flood_window_seconds},
                )
            )

    def _check_udp_port_scan(self, packet: PacketData) -> None:
        if (
            packet.protocol.value != "UDP"
            or packet.src_ip is None
            or packet.dst_port is None
        ):
            return
        if len(packet.udp_payload) < 4:
            return

        now = packet.timestamp
        dq = self._udp_port_activity[packet.src_ip]
        dq.append((now, packet.dst_port))
        self._prune_window(dq, now, self.config.udp_port_scan_window_seconds)

        unique_ports = {port for _, port in dq}
        thresh = self.config.udp_port_scan_unique_port_threshold
        early_thresh = min(self.config.udp_port_scan_early_threshold, max(1, thresh // 2))

        if (
            len(unique_ports) >= thresh
            and self._cooldown_ok(AnomalyType.UDP_PORT_SCAN, packet.src_ip, now, severity="high")
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.UDP_PORT_SCAN,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} probed {len(unique_ports)} distinct UDP ports "
                        f"within {self.config.udp_port_scan_window_seconds:.0f}s — possible UDP port scan"
                    ),
                    timestamp=now,
                    detail={
                        "unique_ports": len(unique_ports),
                        "window_seconds": self.config.udp_port_scan_window_seconds,
                    },
                )
            )
        elif (
            self.config.enable_early_warning
            and len(unique_ports) >= early_thresh
            and self._cooldown_ok(AnomalyType.UDP_PORT_SCAN, packet.src_ip, now, severity="warning")
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.UDP_PORT_SCAN,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} probed {len(unique_ports)} distinct UDP ports — early UDP port scan warning"
                    ),
                    timestamp=now,
                    detail={
                        "unique_ports": len(unique_ports),
                        "window_seconds": self.config.udp_port_scan_window_seconds,
                    },
                )
            )

    def _check_ping_sweep(self, packet: PacketData) -> None:
        if packet.protocol.value != "ICMP" or packet.src_ip is None or packet.dst_ip is None:
            return
        now = packet.timestamp
        dq = self._ping_sweep_activity[packet.src_ip]
        dq.append((now, packet.dst_ip))
        self._prune_window(dq, now, self.config.ping_sweep_window_seconds)

        unique_targets = {target for _, target in dq}
        thresh = self.config.ping_sweep_unique_target_threshold
        early_thresh = min(self.config.ping_sweep_early_threshold, max(1, thresh // 2))

        if (
            len(unique_targets) >= thresh
            and self._cooldown_ok(AnomalyType.PING_SWEEP, packet.src_ip, now, severity="high")
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.PING_SWEEP,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} probed {len(unique_targets)} distinct hosts via ICMP "
                        f"within {self.config.ping_sweep_window_seconds:.0f}s — subnet ping sweep detected"
                    ),
                    timestamp=now,
                    detail={"unique_targets": len(unique_targets), "window_seconds": self.config.ping_sweep_window_seconds},
                )
            )
        elif (
            self.config.enable_early_warning
            and len(unique_targets) >= early_thresh
            and self._cooldown_ok(AnomalyType.PING_SWEEP, packet.src_ip, now, severity="warning")
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.PING_SWEEP,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} probed {len(unique_targets)} hosts via ICMP — early ping sweep warning"
                    ),
                    timestamp=now,
                    detail={"unique_targets": len(unique_targets), "window_seconds": self.config.ping_sweep_window_seconds},
                )
            )

    def _check_http_burst(self, packet: PacketData) -> None:
        if packet.protocol.value != "TCP" or packet.src_ip is None:
            return
        if not packet.tcp_payload:
            return
        payload = packet.tcp_payload
        is_http_request = payload.startswith((
            b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT "
        ))
        if not is_http_request:
            return

        now = packet.timestamp
        dq = self._http_burst_activity[packet.src_ip]
        dq.append(now)
        self._prune_window(dq, now, self.config.http_burst_window_seconds)

        thresh = self.config.http_burst_count_threshold
        early_thresh = min(self.config.http_burst_early_threshold, max(1, thresh // 2))

        if len(dq) >= thresh and self._cooldown_ok(
            AnomalyType.HTTP_BURST, packet.src_ip, now, severity="high"
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.HTTP_BURST,
                    source_ip=packet.src_ip,
                    severity="high",
                    message=(
                        f"{packet.src_ip} generated {len(dq)} HTTP attack requests within "
                        f"{self.config.http_burst_window_seconds:.0f}s — high-velocity HTTP burst detected"
                    ),
                    timestamp=now,
                    detail={"request_count": len(dq), "window_seconds": self.config.http_burst_window_seconds},
                )
            )
        elif (
            self.config.enable_early_warning
            and len(dq) >= early_thresh
            and self._cooldown_ok(AnomalyType.HTTP_BURST, packet.src_ip, now, severity="warning")
        ):
            self._raise_anomaly(
                FlowAnomaly(
                    anomaly_type=AnomalyType.HTTP_BURST,
                    source_ip=packet.src_ip,
                    severity="warning",
                    message=(
                        f"{packet.src_ip} sent {len(dq)} HTTP requests — early HTTP burst warning"
                    ),
                    timestamp=now,
                    detail={"request_count": len(dq), "window_seconds": self.config.http_burst_window_seconds},
                )
            )

    # -- PacketHandler entrypoint --------------------------------------------

    def handle(self, packet: PacketData) -> None:
        self._update_flow(packet)
        self._check_port_scan(packet)
        self._check_syn_flood(packet)
        self._check_brute_force(packet)
        self._check_udp_flood(packet)
        self._check_icmp_flood(packet)
        self._check_dns_flood(packet)
        self._check_udp_port_scan(packet)
        # Enhanced detectors
        self._check_ping_sweep(packet)
        self._check_http_burst(packet)
        self.expire_idle_flows(now=packet.timestamp)

    @property
    def flows(self) -> dict[FlowKey, Flow]:
        return dict(self._flows)

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)
