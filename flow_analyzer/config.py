"""Configuration for the Flow Analyzer — flow expiry and anomaly thresholds."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FlowAnalyzerConfig:
    # A flow with no new packets for this long is considered closed/idle
    # and is dropped from the active flow table.
    idle_timeout_seconds: float = 60.0

    # Port scan: alert if one source IP contacts this many unique
    # destination ports within the sliding window below.
    port_scan_unique_port_threshold: int = 15
    port_scan_window_seconds: float = 10.0

    # SYN flood: alert if this many SYN packets hit one destination IP
    # within the sliding window below.
    syn_flood_count_threshold: int = 100
    syn_flood_window_seconds: float = 5.0

    # Once an anomaly type fires for a given source, suppress repeat alerts
    # of the same type/source for this long, to avoid alert-spamming on
    # sustained attack traffic.
    anomaly_cooldown_seconds: float = 30.0

    # Stage 5 — five new detectors. Each defaults to a value that the IDS
    # attack simulator's default arguments (--count 500 floods, 100 brute-
    # force attempts, etc.) trips within a couple of seconds, while still
    # being wide enough not to false-positive on normal background traffic.

    # Brute force: ≥ N TCP connection attempts to one (src_ip, dst_port)
    # within the window. Catches `brute-force`/`brute_force_sim` (the
    # simulator's default 100 attempts to port 22 in ~5s trips this easily).
    brute_force_attempt_threshold: int = 20
    brute_force_window_seconds: float = 10.0

    # UDP flood: ≥ N UDP packets from one src_ip within the window.
    # Catches `udp-flood` (default 500 packets).
    udp_flood_count_threshold: int = 200
    udp_flood_window_seconds: float = 5.0

    # ICMP flood: ≥ N ICMP packets from one src_ip within the window.
    # Catches `icmp-flood` (default 500 packets).
    icmp_flood_count_threshold: int = 100
    icmp_flood_window_seconds: float = 5.0

    # DNS flood: ≥ N DNS queries (UDP dst_port=53) from one src_ip within
    # the window. Catches `dns-flood` (default 500 queries).
    dns_flood_count_threshold: int = 100
    dns_flood_window_seconds: float = 10.0

    # UDP port scan: ≥ N distinct UDP dst_ports from one src_ip within the
    # window. Catches UDP scan-style reconnaissance (the simulator doesn't
    # currently emit one, but real-world tools like Nmap -sU do).
    udp_port_scan_unique_port_threshold: int = 15
    udp_port_scan_window_seconds: float = 10.0

    # -----------------------------------------------------------------------
    # Enhanced Real-Time & Velocity-Spike Detection Settings
    # -----------------------------------------------------------------------

    # Enable multi-stage early warning anomalies before full thresholds are met
    enable_early_warning: bool = False

    # Early Warning thresholds (triggers a warning severity anomaly before full count)
    port_scan_early_threshold: int = 5
    syn_flood_early_threshold: int = 25
    brute_force_early_threshold: int = 5
    udp_flood_early_threshold: int = 50
    icmp_flood_early_threshold: int = 25
    dns_flood_early_threshold: int = 25
    udp_port_scan_early_threshold: int = 5

    # Velocity Spike thresholds (packets / queries / attempts per second over short bursts).
    # Enables instant anomaly triggering within <1s without waiting for count threshold limits.
    syn_flood_velocity_threshold: float = 25.0  # pps
    udp_flood_velocity_threshold: float = 40.0  # pps
    icmp_flood_velocity_threshold: float = 25.0  # pps
    dns_flood_velocity_threshold: float = 25.0  # qps

    # Ping Sweep: alert if one source IP targets this many distinct destination IPs
    # with ICMP probes within the sliding window below. Catches `ping-sweep`.
    ping_sweep_unique_target_threshold: int = 5
    ping_sweep_early_threshold: int = 3
    ping_sweep_window_seconds: float = 5.0

    # HTTP Attack Burst: alert if one source IP generates this many HTTP requests
    # within the sliding window below. Catches `http-attacks`.
    http_burst_count_threshold: int = 5
    http_burst_early_threshold: int = 3
    http_burst_window_seconds: float = 5.0

