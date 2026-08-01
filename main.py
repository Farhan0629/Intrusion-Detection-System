"""
Stage 1 demo entrypoint.

Prints every captured packet to the console via a ConsolePacketHandler.
Later stages (Rule Engine, Flow Analyzer, Database Layer) will register
additional handlers alongside or instead of this one — capture_engine.py
does not change.

Stage 5: also prints payload-signature alerts (HTTP SQLi/XSS/traversal,
Shellshock UA, scanner UAs) via a dedicated ConsolePayloadAlertHandler so
they're clearly distinguishable from generic rule alerts.

Run (Windows, as Administrator, with Npcap installed):
    python main.py

Run (Linux, as root):
    sudo python3 main.py
"""

from __future__ import annotations

from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from packet_capture import CaptureConfig, CaptureEngine, PacketData, PacketHandler
from packet_capture.logger import get_logger
from rule_engine import Alert, AlertHandler, RuleEngine
from flow_analyzer import FlowAnalyzer, FlowAnomaly, FlowEventHandler

colorama_init(autoreset=True)

logger = get_logger("ids.main")

RULES_FILE = Path(__file__).parent / "rules" / "default_rules.rules"


def print_banner() -> None:
    print(Fore.YELLOW + Style.BRIGHT + "FARHAN")
    print(Fore.RED + Style.BRIGHT + "IDS")
    print()


class ConsolePacketHandler(PacketHandler):
    """Minimal handler: prints a one-line summary per packet."""

    def handle(self, packet: PacketData) -> None:
        if packet.protocol.value == "ARP":
            print(f"[ARP] {packet.arp_op:>7} | {packet.src_ip} -> {packet.dst_ip}")
            return

        flags = f" flags={packet.tcp_flags}" if packet.tcp_flags else ""
        print(
            f"[{packet.protocol.value:>4}] {packet.src_ip}:{packet.src_port} -> "
            f"{packet.dst_ip}:{packet.dst_port} | ttl={packet.ttl} "
            f"size={packet.packet_size}B{flags}"
        )


class ConsoleAlertHandler(AlertHandler):
    """Minimal handler: prints every rule-engine alert to the console."""

    def handle(self, alert: Alert) -> None:
        p = alert.packet
        print(
            f"\n*** ALERT [{alert.severity.value.upper()}] {alert.rule_name} ***\n"
            f"    {alert.message}\n"
            f"    {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port} ({p.protocol.value})\n"
        )


class ConsolePayloadAlertHandler(AlertHandler):
    """Stage 5: payload-signature alerts (HTTP SQLi/XSS/etc.), own header."""

    def handle(self, alert: Alert) -> None:
        p = alert.packet
        print(
            f"\n>>> PAYLOAD [{alert.severity.value.upper()}] {alert.rule_name} <<<\n"
            f"    {alert.message}\n"
            f"    {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port} ({p.protocol.value})\n"
        )


class ConsoleFlowEventHandler(FlowEventHandler):
    """Minimal handler: prints every flow-analyzer anomaly to the console."""

    def handle(self, anomaly: FlowAnomaly) -> None:
        print(
            f"\n### FLOW ANOMALY [{anomaly.severity.upper()}] {anomaly.anomaly_type.value} ###\n"
            f"    {anomaly.message}\n"
        )


def main() -> None:
    print_banner()

    config = CaptureConfig(
        interface=None,  # None = let Scapy/Npcap pick the default interface
        bpf_filter="tcp or udp or icmp or arp",
        packet_count=0,  # unlimited; Ctrl+C to stop
    )

    capture_engine = CaptureEngine(config)
    capture_engine.register_handler(ConsolePacketHandler())

    rule_engine = RuleEngine(rules_file=RULES_FILE)
    rule_engine.register_alert_handler(ConsoleAlertHandler())
    rule_engine.register_payload_alert_handler(ConsolePayloadAlertHandler())
    capture_engine.register_handler(rule_engine)  # RuleEngine is itself a PacketHandler

    flow_analyzer = FlowAnalyzer()
    flow_analyzer.register_event_handler(ConsoleFlowEventHandler())
    capture_engine.register_handler(flow_analyzer)  # FlowAnalyzer is itself a PacketHandler

    try:
        capture_engine.start(blocking=True)
    except KeyboardInterrupt:
        capture_engine.stop()
        print("\nStopped.", capture_engine.stats)
    except PermissionError:
        logger.error(
            "Permission denied. On Windows, run this terminal as Administrator "
            "(with Npcap installed). On Linux, run with sudo."
        )


if __name__ == "__main__":
    main()
