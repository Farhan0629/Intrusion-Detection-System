"""
Data models for the Rule Engine.

Rule is the parsed, in-memory representation of one rule-file entry.
Alert is what gets produced when a packet matches a rule — this becomes the
input to the future Alert Engine / Notification System stages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from packet_capture.models import PacketData


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Rule:
    """One parsed rule. Any field left as 'any' matches everything."""

    name: str
    protocol: str = "any"        # tcp | udp | icmp | arp | any
    src_ip: str = "any"          # exact IP or "any"
    dst_ip: str = "any"          # exact IP or "any"
    src_port: str = "any"        # exact | "a-b" range | "a,b,c" list | "any"
    dst_port: str = "any"
    flags: list[str] = field(default_factory=list)  # required TCP flags, e.g. ["SYN"]; [] = any/none checked
    severity: Severity = Severity.MEDIUM
    message: str = ""
    enabled: bool = True

    # Stage 5: optional payload-signature regex. When set, the rule only
    # matches if the regex finds a hit somewhere in the packet's TCP or
    # UDP application payload (depending on `protocol`). The parsed-and-
    # compiled regex lives on `Rule._compiled_regex` (set by the parser,
    # lazily on first evaluate when a Rule is constructed directly in
    # tests).
    payload_regex: Optional[str] = None
    is_payload_rule: bool = False
    _compiled_regex: Optional["re.Pattern[bytes]"] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.protocol = self.protocol.lower()


@dataclass(frozen=True)
class Alert:
    """Produced when a packet matches an enabled Rule."""

    rule_name: str
    severity: Severity
    message: str
    packet: PacketData
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "packet": self.packet.to_dict(),
        }
