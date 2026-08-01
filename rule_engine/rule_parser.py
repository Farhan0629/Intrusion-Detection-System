"""
Rule Parser.

Parses the simplified, readable rule syntax used by this IDS. Deliberately
not full Snort syntax — easier to read, edit, and (for a portfolio project)
easier to explain in an interview than reverse-engineering Snort's grammar.

Syntax
------
    rule <unique_name>
        protocol tcp|udp|icmp|arp|any
        src_ip any|1.2.3.4
        dst_ip any|1.2.3.4
        src_port any|22|20-1024|80,443
        dst_port any|22|20-1024|80,443
        flags SYN|SYN,ACK|none          # "none" = no flags set (e.g. NULL scan)
        payload_regex "regex"           # match against TCP/UDP payload bytes (Stage 5)
        severity critical|high|medium|low|info
        message "Human readable description"
        enabled true|false               # optional, defaults to true
    end

Blank lines and lines starting with '#' are ignored. Fields may appear in
any order; unspecified fields fall back to Rule's defaults ("any" / medium).
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Rule, Severity

_VALID_FIELDS = {
    "protocol",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "flags",
    "payload_regex",
    "severity",
    "message",
    "enabled",
}


class RuleParseError(ValueError):
    """Raised when a .rules file contains invalid syntax."""


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_rules_text(text: str, source: str = "<string>") -> list[Rule]:
    """Parse the full contents of a .rules file into a list of Rule objects."""
    rules: list[Rule] = []
    current: dict | None = None
    current_name: str | None = None

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("rule "):
            if current is not None:
                raise RuleParseError(
                    f"{source}:{line_no}: nested 'rule' before previous 'end' (rule '{current_name}')"
                )
            current_name = line[len("rule "):].strip()
            if not current_name:
                raise RuleParseError(f"{source}:{line_no}: 'rule' requires a name")
            current = {}
            continue

        if line == "end":
            if current is None:
                raise RuleParseError(f"{source}:{line_no}: 'end' with no matching 'rule'")
            rules.append(_build_rule(current_name, current, source, line_no))
            current = None
            current_name = None
            continue

        if current is None:
            raise RuleParseError(f"{source}:{line_no}: field outside of a rule block: '{line}'")

        parts = line.split(None, 1)
        if len(parts) != 2:
            raise RuleParseError(f"{source}:{line_no}: expected '<field> <value>', got '{line}'")
        key, value = parts[0].lower(), _strip_quotes(parts[1])

        if key not in _VALID_FIELDS:
            raise RuleParseError(f"{source}:{line_no}: unknown field '{key}'")

        current[key] = value

    if current is not None:
        raise RuleParseError(f"{source}: unterminated 'rule {current_name}' — missing 'end'")

    return rules


def _build_rule(name: str, fields: dict, source: str, line_no: int) -> Rule:
    flags_raw = fields.get("flags", "")
    if flags_raw and flags_raw.lower() != "none" and flags_raw.lower() != "any":
        flags = [f.strip().upper() for f in flags_raw.split(",") if f.strip()]
    elif flags_raw.lower() == "none":
        flags = ["NONE"]  # sentinel: packet must have zero flags set
    else:
        flags = []

    severity_raw = fields.get("severity", "medium").lower()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        raise RuleParseError(
            f"{source}:{line_no}: invalid severity '{severity_raw}' in rule '{name}'"
        )

    enabled_raw = fields.get("enabled", "true").strip().lower()
    if enabled_raw not in ("true", "false"):
        raise RuleParseError(
            f"{source}:{line_no}: 'enabled' must be true/false in rule '{name}'"
        )

    payload_regex_raw = fields.get("payload_regex", "").strip()
    compiled = None
    is_payload = False
    if payload_regex_raw:
        try:
            # Match against bytes (TCP/UDP payload on PacketData is bytes).
            compiled = re.compile(payload_regex_raw.encode("utf-8"))
        except re.error as e:
            raise RuleParseError(
                f"{source}:{line_no}: invalid payload_regex in rule '{name}': {e}"
            )
        is_payload = True

    return Rule(
        name=name,
        protocol=fields.get("protocol", "any"),
        src_ip=fields.get("src_ip", "any"),
        dst_ip=fields.get("dst_ip", "any"),
        src_port=fields.get("src_port", "any"),
        dst_port=fields.get("dst_port", "any"),
        flags=flags,
        severity=severity,
        message=fields.get("message", ""),
        enabled=(enabled_raw == "true"),
        payload_regex=payload_regex_raw or None,
        is_payload_rule=is_payload,
        _compiled_regex=compiled,
    )


def parse_rules_file(path: str | Path) -> list[Rule]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    return parse_rules_text(text, source=str(path))
