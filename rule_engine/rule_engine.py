"""
Rule Engine.

Evaluates every captured PacketData against a set of loaded Rules and raises
an Alert for each match. Implements PacketHandler so it can be registered
directly with the Stage 1 CaptureEngine — no changes needed there.

Hot reload: checks the rules file's mtime before each packet (cheap
os.stat() call) and reparses automatically if it changed on disk.

Stage 5: payload-signature rules. Rules with `payload_regex` set are routed
to a separate handler list (`payload_alert_handlers`) so the dashboard can
surface HTTP/Shellshock/scanner-UA matches in their own panel without them
flooding the generic Rule Alerts panel.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from packet_capture.interfaces import PacketHandler
from packet_capture.logger import get_logger
from packet_capture.models import PacketData

from .interfaces import AlertHandler
from .models import Alert, Rule
from .rule_parser import RuleParseError, parse_rules_file, parse_rules_text

logger = get_logger("ids.rule_engine")


def _match_ip(rule_value: str, packet_value: Optional[str]) -> bool:
    if rule_value == "any":
        return True
    return rule_value == packet_value


def _match_port(rule_value: str, packet_value: Optional[int]) -> bool:
    if rule_value == "any":
        return True
    if packet_value is None:
        return False

    if "-" in rule_value:
        lo, hi = rule_value.split("-", 1)
        return int(lo) <= packet_value <= int(hi)

    if "," in rule_value:
        return packet_value in {int(p.strip()) for p in rule_value.split(",")}

    return packet_value == int(rule_value)


def _match_flags(required_flags: list[str], packet_flags: Optional[str]) -> bool:
    if not required_flags:
        return True

    packet_flag_set = set(packet_flags.split(",")) if packet_flags else set()

    if required_flags == ["NONE"]:
        return len(packet_flag_set) == 0

    # Exact match, not "at least these flags present": a rule for a lone
    # FIN (stealth scan) must NOT match a normal FIN,ACK connection close,
    # and a rule for a bare SYN (new connection attempt) must NOT match a
    # SYN,ACK reply. Subset matching previously conflated these.
    return set(required_flags) == packet_flag_set


def _match_payload(rule: Rule, packet: PacketData) -> bool:
    """Apply a rule's payload_regex against the packet's TCP/UDP bytes."""
    if not rule.payload_regex:
        return True
    if rule.protocol == "tcp":
        blob = packet.tcp_payload
    elif rule.protocol == "udp":
        blob = packet.udp_payload
    elif rule.protocol == "any":
        # If the rule doesn't restrict protocol, try TCP first then UDP —
        # they're disjoint fields on the packet, so it's safe.
        blob = packet.tcp_payload or packet.udp_payload
    else:
        return False
    if not blob:
        return False
    # Lazy-compile for rules constructed directly in tests (the parser
    # already pre-compiles them when loading from a file).
    if rule._compiled_regex is None:
        try:
            rule._compiled_regex = re.compile(rule.payload_regex.encode("utf-8"))
        except re.error:
            logger.exception("Failed to compile payload_regex on rule '%s'", rule.name)
            return False
    return rule._compiled_regex.search(blob) is not None


def rule_matches(rule: Rule, packet: PacketData) -> bool:
    if not rule.enabled:
        return False

    if rule.protocol != "any" and rule.protocol != packet.protocol.value.lower():
        return False

    if not _match_ip(rule.src_ip, packet.src_ip):
        return False
    if not _match_ip(rule.dst_ip, packet.dst_ip):
        return False
    if not _match_port(rule.src_port, packet.src_port):
        return False
    if not _match_port(rule.dst_port, packet.dst_port):
        return False
    if not _match_flags(rule.flags, packet.tcp_flags):
        return False

    if rule.payload_regex and not _match_payload(rule, packet):
        return False

    return True


class RuleEngine(PacketHandler):
    """Loads rules, evaluates each packet against them, and dispatches Alerts."""

    def __init__(self, rules_file: Optional[str | Path] = None, extra_rules: Optional[list[Rule]] = None) -> None:
        self._rules_file = Path(rules_file) if rules_file else None
        self._mtime: Optional[float] = None
        self._rules: list[Rule] = list(extra_rules or [])
        self._alert_handlers: list[AlertHandler] = []
        self._payload_alert_handlers: list[AlertHandler] = []

        if self._rules_file is not None:
            self._load_from_file()

        logger.info("RuleEngine initialized with %d rule(s)", len(self._rules))

    # -- setup -----------------------------------------------------------

    def register_alert_handler(self, handler: AlertHandler) -> None:
        self._alert_handlers.append(handler)
        logger.info("Registered alert handler: %s", type(handler).__name__)

    def register_payload_alert_handler(self, handler: AlertHandler) -> None:
        self._payload_alert_handlers.append(handler)
        logger.info("Registered payload alert handler: %s", type(handler).__name__)

    def load_rules_text(self, text: str, source: str = "<string>") -> None:
        """Replace the current rule set with rules parsed from raw text."""
        try:
            self._rules = parse_rules_text(text, source=source)
            logger.info("Loaded %d rule(s) from %s", len(self._rules), source)
        except RuleParseError:
            logger.exception("Failed to parse rules from %s; keeping previous rule set", source)

    def _load_from_file(self) -> None:
        try:
            self._rules = parse_rules_file(self._rules_file)
            self._mtime = os.path.getmtime(self._rules_file)
            logger.info("Loaded %d rule(s) from %s", len(self._rules), self._rules_file)
        except (RuleParseError, OSError):
            logger.exception("Failed to load rules file %s; keeping previous rule set", self._rules_file)

    def check_hot_reload(self) -> None:
        """If the rules file changed on disk since last load, reparse it."""
        if self._rules_file is None:
            return
        try:
            current_mtime = os.path.getmtime(self._rules_file)
        except OSError:
            return
        if self._mtime is None or current_mtime > self._mtime:
            logger.info("Detected change in %s; hot-reloading rules", self._rules_file)
            self._load_from_file()

    # -- evaluation --------------------------------------------------------

    def evaluate(self, packet: PacketData) -> list[Alert]:
        matches = []
        for rule in self._rules:
            if rule_matches(rule, packet):
                matches.append(
                    Alert(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=rule.message or f"Rule '{rule.name}' matched",
                        packet=packet,
                    )
                )
        return matches

    def _dispatch(self, handlers: list[AlertHandler], alert: Alert) -> None:
        for handler in handlers:
            try:
                handler.handle(alert)
            except Exception:
                logger.exception("Alert handler %s raised while processing an alert", type(handler).__name__)

    def handle(self, packet: PacketData) -> None:
        """PacketHandler entrypoint — called by CaptureEngine for every packet."""
        self.check_hot_reload()
        for alert in self.evaluate(packet):
            handlers = self._payload_alert_handlers if self._payload_rule_name(alert.rule_name) else self._alert_handlers
            self._dispatch(handlers, alert)

    def _payload_rule_name(self, rule_name: str) -> bool:
        """O(1)-ish: linear scan over rules; rule lists are tiny (tens)."""
        for r in self._rules:
            if r.name == rule_name and r.is_payload_rule:
                return True
        return False

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)
