"""
Pipeline diagnostic.

Tells you exactly where the IDS pipeline is breaking in your environment.
Runs the real CaptureEngine + FlowAnalyzer + a counting handler, listens
for ~12 seconds, then prints a verdict:

  - "No packets captured"   -> Npcap / loopback problem, not detection.
  - "No flow anomalies"     -> packets flow in but thresholds aren't crossed.
  - "Flow anomalies fired"  -> everything works; dashboard issue only.

Usage:
    python debug_pipeline.py
    python debug_pipeline.py --target 127.0.0.1 --count 60

While this script runs, in another Admin terminal run one of:
    python ids_attack_simulator.py udp-flood --target 127.0.0.1 --port 80 --count 500
    python ids_attack_simulator.py icmp-flood --target 127.0.0.1 --count 500
"""

from __future__ import annotations

import argparse
import threading
import time
from collections import Counter
from datetime import datetime, timezone

from packet_capture import CaptureConfig, CaptureEngine, PacketData, Protocol
from packet_capture.interfaces import PacketHandler
from flow_analyzer import FlowAnalyzer, FlowAnomaly, FlowEventHandler


class CountingHandler(PacketHandler):
    """Counts packets by protocol and prints a live tally every second."""

    def __init__(self):
        self.lock = threading.Lock()
        self.counts: Counter = Counter()
        self.first_packet_at: float | None = None

    def handle(self, packet: PacketData) -> None:
        with self.lock:
            self.counts[packet.protocol.value] += 1
            if self.first_packet_at is None:
                self.first_packet_at = time.time()


class CollectingFlowHandler(FlowEventHandler):
    def __init__(self):
        self.anomalies: list[FlowAnomaly] = []

    def handle(self, anomaly: FlowAnomaly) -> None:
        self.anomalies.append(anomaly)
        print(f"\n  >>> ANOMALY [{anomaly.severity.upper()}] {anomaly.anomaly_type.value}: {anomaly.message}\n")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--interface", default=None)
    p.add_argument("--window", type=float, default=12.0, help="seconds to listen")
    args = p.parse_args()

    counter = CountingHandler()
    flow_collector = CollectingFlowHandler()

    analyzer = FlowAnalyzer()
    analyzer.register_event_handler(flow_collector)

    config = CaptureConfig(
        interface=args.interface,
        bpf_filter="tcp or udp or icmp or arp",
        packet_count=0,
    )
    engine = CaptureEngine(config)
    engine.register_handler(counter)
    engine.register_handler(analyzer)

    print(f"Listening for {args.window:.0f}s on interface={args.interface or '<default>'}")
    print("Now run the simulator in another terminal, e.g.:")
    print("  python ids_attack_simulator.py udp-flood --target 127.0.0.1 --port 80 --count 500")
    print()

    stop = threading.Event()

    def _live_tally() -> None:
        end = time.time() + args.window
        while time.time() < end and not stop.is_set():
            with counter.lock:
                counts = dict(counter.counts)
            total = sum(counts.values())
            print(f"\r  [t+{args.window - (end - time.time()):4.1f}s] packets captured: {total:5d}   "
                  f"TCP={counts.get('TCP',0)} UDP={counts.get('UDP',0)} "
                  f"ICMP={counts.get('ICMP',0)} ARP={counts.get('ARP',0)}   "
                  f"anomalies={len(flow_collector.anomalies)}   ", end="", flush=True)
            time.sleep(0.5)
        print()

    threading.Thread(target=_live_tally, daemon=True).start()

    def _run() -> None:
        engine.start(blocking=True)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(args.window)
    stop.set()
    engine.stop()
    t.join(timeout=3)

    print()
    print("=" * 64)
    print("DIAGNOSIS")
    print("=" * 64)
    with counter.lock:
        counts = dict(counter.counts)
    total = sum(counts.values())
    print(f"  Total packets captured: {total}")
    print(f"  By protocol: {counts}")
    print(f"  Flow anomalies fired:   {len(flow_collector.anomalies)}")
    for a in flow_collector.anomalies:
        print(f"    - {a.anomaly_type.value:14s} from {a.source_ip}: {a.message}")

    if total == 0:
        print()
        print("  >>> NO PACKETS WERE CAPTURED.")
        print("  This is a CAPTURE problem, not a detection problem:")
        print("    - Npcap may not be seeing loopback (127.0.0.1 -> 127.0.0.1) traffic")
        print("    - On Windows, run BOTH terminals as Administrator")
        print("    - Try targeting a real LAN IP instead of 127.0.0.1")
        print("    - Try a different interface: pass --interface '\\Device\\NPF_{...}'")
        print("      (run `python -c \"from scapy.all import get_if_list; print(get_if_list())\"` to find names)")
    elif len(flow_collector.anomalies) == 0:
        print()
        print("  >>> PACKETS CAPTURED but NO flow anomalies fired.")
        print("  Detection is running but the test traffic didn't cross thresholds.")
        print("  Try larger counts / more diverse traffic (see README for module-by-module guides).")
    else:
        print()
        print("  >>> EVERYTHING WORKS — packets captured AND anomalies fired.")
        print("  The dashboard panel should also show these. If it doesn't, the")
        print("  issue is in the rich Live / dashboard rendering layer.")


if __name__ == "__main__":
    main()