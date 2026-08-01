"""
Data models for the Packet Capture Engine.

PacketData is the single contract that every downstream module (Flow Analyzer,
Rule Engine, Detection Engine, Database Layer, ...) will consume. Keeping it
here — decoupled from Scapy's own packet objects — means later stages never
need to import Scapy directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP = "ARP"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class PacketData:
    """Normalized representation of a single captured packet."""

    timestamp: datetime
    protocol: Protocol

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    ttl: Optional[int] = None
    packet_size: int = 0
    payload_length: int = 0

    tcp_flags: Optional[str] = None  # e.g. "SYN,ACK"

    # Raw application-layer bytes for payload-signature matching. Capped to
    # the first 4096 bytes per packet in the parser to bound memory use.
    tcp_payload: bytes = b""
    udp_payload: bytes = b""

    # ARP-specific
    arp_op: Optional[str] = None  # "who-has" / "is-at"

    raw_summary: str = field(default="", repr=False)

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp.isoformat(),
            "protocol": self.protocol.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "ttl": self.ttl,
            "packet_size": self.packet_size,
            "payload_length": self.payload_length,
            "tcp_flags": self.tcp_flags,
            "tcp_payload_preview": self.tcp_payload[:64].hex(),
            "udp_payload_preview": self.udp_payload[:64].hex(),
            "arp_op": self.arp_op,
        }
        return d
