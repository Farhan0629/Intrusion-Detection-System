"""
Data models for the Flow Analyzer.

Scope note: a "Flow" here is unidirectional, keyed by the 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol). A real bidirectional session
would merge both directions of a TCP conversation into one record — that's a
reasonable future refinement, but unidirectional flows are the standard
starting point and are sufficient to support the threshold-based detections
in this stage (port scans, SYN floods).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import NamedTuple, Optional


class FlowKey(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str


@dataclass
class Flow:
    """Running statistics for one 5-tuple, updated as packets arrive."""

    key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()


class AnomalyType(str, Enum):
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"

    # Stage 5: five new anomaly kinds covering the remaining simulator modules.
    BRUTE_FORCE = "brute_force"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    DNS_FLOOD = "dns_flood"
    UDP_PORT_SCAN = "udp_port_scan"

    # Enhanced detectors: subnet ping sweep & rapid HTTP attack bursts
    PING_SWEEP = "ping_sweep"
    HTTP_BURST = "http_burst"


@dataclass(frozen=True)
class FlowAnomaly:
    """Raised when flow-level statistics cross a configured threshold."""

    anomaly_type: AnomalyType
    source_ip: str
    message: str
    severity: str = "high"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "anomaly_type": self.anomaly_type.value,
            "source_ip": self.source_ip,
            "message": self.message,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "detail": self.detail,
        }
