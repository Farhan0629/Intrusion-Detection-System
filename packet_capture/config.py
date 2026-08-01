"""
Configuration for the Packet Capture Engine.

Kept as a small typed dataclass rather than scattered constants, so later
stages can load this from a YAML/env file without touching capture logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CaptureConfig:
    # None = Scapy picks the default interface. On Windows this must match
    # a Npcap-visible interface name/GUID, e.g. r"\Device\NPF_{...}"
    interface: Optional[str] = None

    # Berkeley Packet Filter expression, e.g. "tcp or udp or icmp or arp"
    bpf_filter: str = "tcp or udp or icmp or arp"

    # Stop after N packets (0 = unlimited, run until stop() is called)
    packet_count: int = 0

    # Max seconds to run (0 = unlimited)
    timeout: Optional[float] = None

    store_raw_summary: bool = False

    protocols_enabled: list[str] = field(
        default_factory=lambda: ["TCP", "UDP", "ICMP", "ARP"]
    )
