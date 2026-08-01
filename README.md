<div align="center">

# 🛡️ Intrusion Detection System (IDS)

**A high-performance, modular Network Intrusion Detection System featuring real-time packet capture, hot-reloadable signature matching, sliding-window flow anomaly detection, payload inspection, and a live Rich terminal UI.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Test Suite](https://img.shields.io/badge/tests-82%20passed-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://npcap.com/)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Architecture](https://img.shields.io/badge/architecture-Modular%20--%20Plugin-orange.svg)](#architecture)

[Key Features](#key-features) •
[System Architecture](#system-architecture) •
[Quick Start](#quick-start) •
[Detection Engine](#detection-engine-reference) •
[Attack Simulator](#attack-simulation--validation) •
[Testing](#running-tests) •
[Project Structure](#project-structure)

</div>

---

## 📋 Overview

This Intrusion Detection System (IDS) provides real-time network security monitoring by inspecting raw network traffic, identifying known exploit signatures, tracking flow state statistics, and detecting volumetric and stealth network anomalies.

Designed with clean architectural separation, pure testable components, and zero hard dependencies on browser stacks, it delivers enterprise-grade detection performance directly to your terminal.

---

## ✨ Key Features

- 🔍 **Real-Time Packet Normalization Engine**: Multithreaded capture engine built on Scapy, normalizing raw TCP, UDP, ICMP, and ARP frames into structured `PacketData` contracts with automated Windows loopback adapter handling.
- ⚡ **Hot-Reloadable Signature Engine**: Custom declarative rule DSL featuring IP filter lists, port ranges, exact TCP flag matching (including NULL/FIN stealth scans), and live file hot-reloading without interrupting packet capture.
- 🔬 **Deep Packet Inspection (DPI)**: Payload signature extractor inspecting up to 4 KiB payload buffers for SQL Injection, XSS, Path Traversal, Command Injection, Webshell probes, RFI, and malicious scanner User-Agents (`sqlmap`, `Nikto`, `Nmap`).
- 📊 **Sliding-Window Flow Analyzer**: State-aware 5-tuple flow analyzer calculating real-time packet velocities, SYN ratios, and port access patterns to flag Port Scans, SYN Floods, UDP/ICMP/DNS Floods, and Brute Force attacks.
- 🖥️ **Live Terminal Dashboard**: High-refresh (~4 Hz) terminal UI powered by `Rich`, organizing live network telemetry, severity-coded rule alerts, and active flow anomalies into interactive panels.
- 🧪 **Built-In Attack Benchmarking**: Integrated attack simulator (`ids_attack_simulator.py`) for automated end-to-end detection validation under synthetic attack loads.

---

## 🏗️ System Architecture

```
                                 ┌─────────────────────────┐
                                 │   Raw Network Traffic   │
                                 └────────────┬────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │     CaptureEngine       │
                                 │ (Scapy / WinPcap / PCAP)│
                                 └────────────┬────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │      PacketParser       │
                                 │ (Normalized PacketData) │
                                 └────────────┬────────────┘
                                              │
                   ┌──────────────────────────┴──────────────────────────┐
                   ▼                                                     ▼
    ┌─────────────────────────────┐                       ┌─────────────────────────────┐
    │         RuleEngine          │                       │        FlowAnalyzer         │
    │  - DSL Rule Matcher         │                       │  - 5-Tuple State Tracking   │
    │  - Payload Regex Inspector  │                       │  - Sliding Window Metrics   │
    │  - Hot Reload (Watcher)     │                       │  - Anomaly Cooldown Engine  │
    └──────────────┬──────────────┘                       └──────────────┬──────────────┘
                   │                                                     │
                   │ Alerts                                              │ Flow Events
                   └──────────────────────────┬──────────────────────────┘
                                              ▼
                                 ┌─────────────────────────┐
                                 │   Terminal Dashboard    │
                                 │  (Rich Layout / UI)     │
                                 └─────────────────────────┘
```

---

## ⚡ Quick Start

### Prerequisites

1. **Python 3.10+** (Ensure Python is added to your system `PATH`).
2. **Npcap (Windows Users)**: Download and install from [npcap.com](https://npcap.com/).
   > ⚠️ **IMPORTANT**: During setup, check **"Install Npcap in WinPcap API-compatible Mode"** to allow raw packet sniffing on Windows interfaces.

---

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Farhan0629/Intrusion-Detection-System.git
   cd Intrusion-Detection-System
   ```

2. **Automated Setup (Windows):**
   Double-click `setup.bat` or run:
   ```cmd
   setup.bat
   ```
   *This automatically creates a Python virtual environment (`venv`) and installs required dependencies (`scapy`, `rich`, `pytest`).*

3. **Manual Setup (Linux / macOS / Manual Windows):**
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate

   pip install -r requirements.txt
   ```

---

### Running the IDS

> 🔑 **Privilege Requirement**: Packet capture engines require elevated administrative privileges to put network adapters into promiscuous mode.

#### 1. Live Terminal Dashboard Mode (Recommended)
Right-click `run_ids_dashboard.bat` → **Run as administrator**, or execute:
```cmd
# Windows (Administrator Command Prompt / PowerShell)
run_ids_dashboard.bat
```
```bash
# Linux / macOS
sudo python main_dashboard.py
```

#### 2. Scrolling Console Log Mode
For standard text log output:
```cmd
# Windows (Administrator Command Prompt)
run_ids_dashboard.bat
```
```bash
# Linux / macOS
sudo python main.py
```

---

## 🎯 Detection Engine Reference

### 1. Flow Anomaly Detectors

The `FlowAnalyzer` maintains real-time state tables for every 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) and evaluates sliding-window rates:

| Anomaly Type | Target Key | Threshold | Window | Severity | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `PORT_SCAN` | `src_ip` | 15 unique ports | 10s | `HIGH` | Bare SYN attempts across multiple destination ports |
| `SYN_FLOOD` | `dst_ip` | 100 SYN packets | 5s | `CRITICAL` | Excessive unacknowledged SYN packets to target IP |
| `BRUTE_FORCE` | `(src_ip, dst_port)` | 20 attempts | 10s | `HIGH` | High-frequency connection probes to specific service ports (e.g. 22, 445, 3389) |
| `UDP_FLOOD` | `src_ip` | 200 packets | 5s | `HIGH` | Volumetric UDP packet burst from single origin |
| `ICMP_FLOOD` | `src_ip` | 100 packets | 5s | `MEDIUM` | Excessive ICMP echo request rate |
| `DNS_FLOOD` | `src_ip` | 100 queries | 10s | `HIGH` | High-frequency UDP query burst targeting port 53 |
| `UDP_PORT_SCAN` | `src_ip` | 15 unique ports | 10s | `HIGH` | Multi-port UDP probing with non-empty payloads |

---

### 2. Signature-Based Rule Syntax

Rules are stored in `rules/default_rules.rules` using a clean declarative DSL.

#### Rule Syntax Specification:
```rules
rule <Rule_Identifier>
    protocol <tcp|udp|icmp|arp|any>
    src_ip <IP|any>
    dst_ip <IP|any>
    src_port <Port|Range|List|any>
    dst_port <Port|Range|List|any>
    flags <SYN|ACK|FIN|RST|PSH|URG|none>
    payload_regex "<regex_pattern>"
    severity <critical|high|medium|low|info>
    message "<human_readable_description>"
    enabled <true|false>
end
```

#### Example Rule: SQL Injection Detection
```rules
rule HTTP_SQLi_Union_Probe
    protocol tcp
    dst_port 80,443,8080
    payload_regex "UNION.*SELECT"
    severity critical
    message "SQL Injection UNION probe detected in payload"
end
```

> 💡 **Hot Reload Feature**: You can edit `rules/default_rules.rules` while the IDS is running. The `RuleEngine` automatically detects file modifications and reloads rules seamlessly without missing incoming traffic.

---

## 🧪 Attack Simulation & Validation

To test and benchmark the IDS against synthetic attack vectors, use the built-in attack simulator (`ids_attack_simulator.py`).

Open a **second Administrator terminal** while the IDS is running:

```bash
# Run full attack simulation suite against loopback
python ids_attack_simulator.py all --target 127.0.0.1 --port 80

# Run specific attack module (e.g., SYN Flood)
python ids_attack_simulator.py syn-flood --target 127.0.0.1

# Run web exploit payload suite (SQLi, XSS, Path Traversal)
python ids_attack_simulator.py http-attacks --target 127.0.0.1 --port 80
```

### Simulation Matrix:

| Simulator Command | IDS Panel / Output | Verified Detection |
| :--- | :--- | :--- |
| `tcp-scan` | Flow Anomalies + Rule Alerts | `PORT_SCAN` Anomaly & TCP SYN Alerts |
| `syn-flood` | Flow Anomalies | `SYN_FLOOD` Anomaly (CRITICAL) |
| `udp-flood` | Flow Anomalies | `UDP_FLOOD` & `DNS_FLOOD` Anomalies |
| `brute-force` | Flow Anomalies + Rule Alerts | `BRUTE_FORCE` Anomaly + SSH/RDP Alerts |
| `http-attacks` | Console Payload Alerts | SQLi, XSS, Shellshock & Web Probe Matches |

---

## 🧪 Running Tests

The test suite contains **82 unit and integration tests** covering packet parsing, rule matching, hot reloading, flow tracking, anomaly thresholds, and thread-safe UI rendering. Tests do not require administrative privileges.

Run the test suite using `run_tests.bat` or `pytest`:

```cmd
# Windows batch shortcut:
run_tests.bat
```

```bash
# Manual command execution:
python -m pytest tests/ --basetemp=.pytest_tmp -v
```

---

## 📁 Project Structure

```
My_IDS/
├── flow_analyzer/               # Sliding-window flow anomaly detection module
│   ├── config.py                # FlowAnalyzerConfig thresholds & windows
│   ├── flow_analyzer.py        # 5-tuple flow tracking & detector implementation
│   ├── interfaces.py            # FlowEventHandler abstract base class
│   └── models.py                # Flow, FlowKey, AnomalyType, and FlowAnomaly contracts
│
├── packet_capture/              # Raw packet sniffing & normalization layer
│   ├── capture_engine.py       # Scapy sniffer & Windows loopback route handler
│   ├── config.py                # CaptureConfig settings
│   ├── interfaces.py            # PacketHandler abstract base class
│   ├── logger.py                # Structured logging configuration
│   ├── models.py                # PacketData & Protocol enum contracts
│   └── packet_parser.py        # Pure packet-to-model parsing functions
│
├── rule_engine/                 # Signature matching & rule parsing layer
│   ├── interfaces.py            # AlertHandler abstract base class
│   ├── models.py                # Rule, Alert, and Severity contracts
│   ├── rule_engine.py           # Matcher engine, hot-reloader & alert dispatcher
│   └── rule_parser.py           # Custom DSL parser & regex compiler
│
├── rules/
│   └── default_rules.rules      # Declarative signature rule definitions
│
├── ui/                          # Terminal dashboard rendering module
│   ├── config.py                # DashboardConfig parameters
│   ├── dashboard.py             # Thread-safe data store & Rich layout renderer
│   └── handlers.py              # Event handler adapters feeding UI queues
│
├── tests/                       # Unit & integration test suite (82 tests)
│   ├── test_capture_engine_loopback.py
│   ├── test_enhanced_anomaly_detection.py
│   ├── test_flow_analyzer.py
│   ├── test_packet_parser.py
│   ├── test_rule_engine.py
│   ├── test_rule_parser.py
│   └── test_ui_dashboard.py
│
├── debug_pipeline.py            # Pipeline diagnostic utility script
├── ids_attack_simulator.py      # Synthetic attack generator for validation
├── main.py                      # Console log entrypoint
├── main_dashboard.py            # Live Rich terminal UI entrypoint
├── requirements.txt             # Python dependencies
├── run_ids.bat                  # Launch console IDS (Windows)
├── run_ids_dashboard.bat        # Launch Rich dashboard IDS (Windows)
├── run_tests.bat                # Test execution script (Windows)
└── setup.bat                    # Environment setup script (Windows)
```

---

## 🛣️ Roadmap

- [x] **Stage 1**: Raw Packet Capture & Model Normalization
- [x] **Stage 2**: Hot-Reloadable Signature Rule Engine
- [x] **Stage 3**: Flow Tracking & Anomaly Detectors (Port Scan / SYN Flood)
- [x] **Stage 4**: Real-Time Rich Terminal Dashboard
- [x] **Stage 5**: Deep Packet Inspection (DPI) & Expanded Flow Detectors
- [ ] **Stage 6**: SQLite / PostgreSQL Persistence Layer for Historical Analysis
- [ ] **Stage 7**: Modern Web Dashboard (FastAPI Backend + React UI)
- [ ] **Stage 8**: Machine Learning Anomaly Detection (Isolation Forest / Autoencoders)

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<div align="center">
  <sub>Built with ❤️ by <a href="https://github.com/Farhan0629">Farhan</a></sub>
</div>
