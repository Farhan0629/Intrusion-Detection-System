# IDS Project — Stage 5: Payload Inspection & Expanded Anomaly Detection

A portfolio-scoped Intrusion Detection System, built incrementally.

- **Stage 1 (done):** Packet Capture Engine
- **Stage 2 (done):** Rule Engine
- **Stage 3 (done):** Flow Analyzer
- **Stage 4 (done):** Terminal Dashboard (live UI)
- **Stage 5 (done):** Payload-signature rules + 5 new flow detectors + new "Payload Alerts" panel — covers every module of `ids_attack_simulator.py`
- Later stages (not built yet): Detection Engine, Database Layer, Web Dashboard

## Quick Start (Windows)

1. Install Python 3.10+ from [python.org](https://www.python.org/downloads/) if you don't have it (check "Add Python to PATH" during install).
2. Install [Npcap](https://npcap.com/) — during setup, check **"Install Npcap in WinPcap API-compatible Mode"**. This is required for Scapy to actually see network packets on Windows.
3. Unzip this project anywhere, e.g. `C:\ids_project`.
4. Open that folder, double-click **`setup.bat`**. This creates a virtual environment and installs everything needed.
5. To run the tests (no admin needed): double-click **`run_tests.bat`**. You should see ~81 passed.
6. To run the actual IDS: right-click **`run_ids.bat`** → **"Run as administrator"** (packet capture requires elevated privileges on every OS). It will print a colored startup banner, then begin printing live packets, rule-based alerts, payload-signature alerts, and flow anomalies to the console. Press `Ctrl+C` to stop.
7. For the live, in-place-updating dashboard version instead of scrolling text: maximize your terminal window, then right-click **`run_ids_dashboard.bat`** → **"Run as administrator"**. Press `Ctrl+C` to stop and return to your normal terminal.

If step 6 shows a permission or interface error, double check Npcap is installed and that you ran it as Administrator.

---

## What Stage 1 does

Captures live TCP, UDP, ICMP, and ARP traffic and normalizes every packet
into a single `PacketData` object containing: timestamps, IPs, ports, MACs,
TTL, packet/payload size, and TCP flags. That normalized object is the
contract every other module consumes.

## What Stage 2 does

Matches every captured packet against a set of rules written in a simplified,
readable syntax, and raises an `Alert` for each match. Rules are loaded from
`rules/default_rules.rules` and **hot-reload automatically** — edit the file
while the IDS is running and changes take effect on the next packet.

### Rule syntax

```
rule SSH_Connection_Attempt
    protocol tcp
    dst_port 22
    flags SYN
    severity medium
    message "Inbound SSH connection attempt"
end
```

Fields (all optional — unspecified fields default to "any" / medium severity):

| Field       | Values                                              |
|-------------|------------------------------------------------------|
| `protocol`  | `tcp` \| `udp` \| `icmp` \| `arp` \| `any`             |
| `src_ip` / `dst_ip` | exact IP or `any`                             |
| `src_port` / `dst_port` | exact (`22`), range (`20-1024`), list (`80,443`), or `any` |
| `flags`     | comma-separated required TCP flags (`SYN,ACK`), `none` (no flags set — NULL scan), or omit for "don't care". Matching is **exact** — a rule for `flags FIN` matches only a bare FIN packet, never a normal `FIN,ACK` connection close (an earlier version used subset matching, which caused every routine HTTPS disconnect to false-positive as a stealth FIN scan) |
| `payload_regex` | quoted Python regex (matched against first 4 KiB of TCP/UDP payload bytes) |
| `severity`  | `critical` \| `high` \| `medium` \| `low` \| `info`     |
| `message`   | quoted human-readable description                    |
| `enabled`   | `true` \| `false` (default `true`)                    |

10 default rules ship in `rules/default_rules.rules`, covering SSH/Telnet/FTP/
RDP/SMB connection attempts, NULL and FIN stealth scans, ICMP echo, ARP
requests, and DNS query traffic.

22 default rules after Stage 5 — the original 10 plus 12 payload-signature
rules covering SQLi (classic + UNION), XSS, path traversal (plain + URL-
encoded), command injection (`;cat /etc/passwd`), RFI, command execution,
webshell probes (shell.php / c99.php / r57.php), sensitive file probes
(.git/config), Shellshock exploit User-Agent, and scanner User-Agents
(sqlmap / Nikto / Nmap).

**Scope note:** this stage matches per-packet only (no counting/thresholds —
e.g. "20 attempts in 60s" brute-force detection needs state tracking, which
is the Flow Analyzer's job — see below).

## What Stage 3 does

Tracks running statistics per 5-tuple flow (`src_ip, dst_ip, src_port,
dst_port, protocol`) — packet count, byte count, SYN/FIN/RST counts,
duration — and layers two sliding-window threshold detections on top of
that state, which the (stateless) Rule Engine cannot do on its own:

- **Port scan:** one source IP sending a bare TCP SYN (a genuine connection
  attempt — no ACK) to `port_scan_unique_port_threshold` (default 15)
  distinct destination ports within `port_scan_window_seconds` (default
  10s). Restricted to bare SYN packets deliberately: an earlier version
  counted *any* packet, which meant a busy UDP responder (e.g. a DNS server
  replying to many clients on many different ephemeral reply ports) looked
  identical to a port scan and fired a false positive. This matches how
  real scanners (e.g. Nmap SYN scans) actually work.
- **SYN flood:** a destination IP receiving `syn_flood_count_threshold`
  (default 100) SYN packets within `syn_flood_window_seconds` (default 5s).

Both thresholds are configurable via `FlowAnalyzerConfig`. Idle flows are
automatically expired after `idle_timeout_seconds` (default 60s) to keep
the flow table bounded. A per-source cooldown (default 30s) prevents the
same sustained attack from re-firing an alert every single packet.

**Scope note:** flows here are unidirectional (one record per 5-tuple, not
a merged bidirectional session) — a reasonable simplification for this
stage; true session reassembly is a natural future refinement.

## What Stage 4 does

A live, in-place-updating terminal dashboard (`main_dashboard.py`) as an
alternative to `main.py`'s plain scrolling console output — same data sources
(packets, rule alerts, flow anomalies), just laid out and colored in a proper
live-refreshing layout instead of scrolling past. Built with
[`rich`](https://github.com/Textualize/rich); no browser involved.

- Header: the FARHAN/IDS banner plus running totals (packets/alerts/anomalies seen)
- Live Packets panel: last 15 packets, color-coded by protocol
- Rule Alerts panel: last 12 rule matches, color-coded by severity
- Flow Anomalies panel: last 20 port-scan / SYN-flood / brute-force / UDP-flood / ICMP-flood / DNS-flood / UDP-port-scan detections, color-coded by severity

Refreshes ~4 times/second regardless of traffic volume, so it stays
readable even under a flood rather than scrolling faster than you can read.

**Run it maximized** — the layout adapts to terminal width, and side
panels (alerts/anomalies) get squeezed at narrow widths (below ~100 columns).

## What Stage 5 does

Closes every gap in coverage of the `ids_attack_simulator.py` modules that
Stages 1-4 left on the table. Three additions, all sitting cleanly on top
of the existing architecture:

### 5.1 Payload extraction + payload-signature rules

The Stage 1 parser was deliberately content-agnostic — it captured
`payload_length` but discarded the bytes, because no consumer cared. Stage
5 changes that: `PacketData` now carries `tcp_payload: bytes` and
`udp_payload: bytes` (first 4 KiB, capped to bound memory). The rule
syntax gains one optional field:

```
rule HTTP_SQLi_Classic
    protocol tcp
    payload_regex "1' OR '1'='1"
    severity high
    message "Classic SQLi probe in URL parameter"
end
```

The regex is compiled once at rule-load time and matched against the
packet's payload bytes. 12 such rules ship by default, each one tied to a
specific literal in the simulator's `HTTP_ATTACK_PATHS` / `NASTY_USER_AGENTS`
lists — so a dashboard row tells you exactly which attack was attempted.
The existing flag/port/IP matchers still apply alongside `payload_regex`,
so rules compose normally.

The parser rejects invalid regexes at load time (`re.error` → `RuleParseError`),
and a runtime safety-net compiles any rule constructed directly in tests.

### 5.2 Five new flow-analyzer detectors

The Flow Analyzer now layers five new sliding-window detectors on top of
its existing port-scan and SYN-flood ones:

| Anomaly | Key | Default threshold | Default window | Severity |
|---|---|---|---|---|
| `BRUTE_FORCE` | `(src_ip, dst_port)` | 20 attempts | 10s | high |
| `UDP_FLOOD` | `src_ip` | 200 packets | 5s | high |
| `ICMP_FLOOD` | `src_ip` | 100 packets | 5s | medium |
| `DNS_FLOOD` | `src_ip` (UDP dst_port=53) | 100 queries | 10s | high |
| `UDP_PORT_SCAN` | `src_ip` | 15 distinct ports | 10s | high |

Defaults are tuned so the simulator's `--count 500` floods and 100-attempt
brute-force mode trip each detector within a couple of seconds, while still
being wide enough not to false-positive on normal background traffic. Tests
override thresholds explicitly so unit tests stay fast.

Two subtleties worth knowing:
- `BRUTE_FORCE` counts **bare TCP SYNs** to one (src, dst_port) — same
  signal as the TCP port-scan detector, but per-dst-port instead of
  per-unique-port. Cooldown keys on `(anomaly_type, src_ip)` only, so a
  single attacker hitting multiple services still gets one alert per
  window.
- `UDP_PORT_SCAN` requires **at least 4 bytes of payload** per packet so
  the detector doesn't false-positive on empty UDP service replies — same
  pattern as the TCP port-scan detector (which excludes SYN,ACK replies).

### 5.3 Payload alerts surface in the console, not the dashboard

Payload-signature alerts go to a **separate** handler list
(`payload_alert_handlers`) on the Rule Engine, distinct from regular rules —
this keeps the routing logic clean even though the dashboard intentionally
does not surface them. The console (`main.py`) registers a
`ConsolePayloadAlertHandler` that prints `>>> PAYLOAD [HIGH]
HTTP_SQLi_Classic <<<` headers, distinct from the regular `*** ALERT ***`
format. The dashboard itself omits these alerts to keep its three panels
(Live Packets / Rule Alerts / Flow Anomalies) focused on the highest-signal
views; sustained HTTP-attack-signature traffic would otherwise crowd the
Rule Alerts panel.

### 5.4 What Stage 5 lets the simulator prove

Run any single simulator module from a second admin terminal while the IDS
dashboard is running — each one now lights up the right panel:

| Simulator module | Dashboard outcome |
|---|---|
| `tcp-scan` | PORT_SCAN anomaly (Flow Anomalies) + per-port SYN alerts (Rule Alerts) |
| `syn-scan` | Per-port SYN alerts if target port has a rule |
| `ping-sweep` | One ICMP_Echo_Request alert per host (Rule Alerts) |
| `syn-flood` | SYN_FLOOD anomaly, CRITICAL (Flow Anomalies) |
| `udp-flood` | UDP_FLOOD anomaly (Flow Anomalies) + DNS_Query_Traffic info alerts if port 53 (Rule Alerts) |
| `icmp-flood` | ICMP_FLOOD anomaly (Flow Anomalies) + ICMP_Echo_Request alerts (Rule Alerts) |
| `brute-force` | BRUTE_FORCE anomaly (Flow Anomalies) + per-attempt SSH/SMB/RDP alerts (Rule Alerts) |
| `dns-flood` | DNS_FLOOD anomaly (Flow Anomalies) + DNS_Query_Traffic info alerts (Rule Alerts) |
| `http-attacks` | Each literal matches exactly one payload rule (printed to console via `main.py`, not on the dashboard) |
| `all` | All three panels fill; every counter advances |

The `run_all` mode (`python ids_attack_simulator.py all --target 127.0.0.1
--port 80`) is the most comprehensive single-command test — it exercises
every detector and every payload rule in one run.

## Architecture

```
packet_capture/
├── models.py             PacketData + Protocol enum — the shared contract
├── interfaces.py          PacketHandler abstract base — plug-in point for future modules
├── config.py              CaptureConfig — typed capture settings
├── packet_parser.py        Scapy packet -> PacketData (pure function, fully unit-testable)
├── capture_engine.py       Sniffs traffic, dispatches parsed packets to handlers
└── logger.py               Structured logging setup

rule_engine/
├── models.py              Rule + Alert + Severity — the rule engine's data contracts
├── interfaces.py           AlertHandler abstract base — plug-in point for Alert Engine/Notifications later
├── rule_parser.py           Parses the .rules text format into Rule objects (pure function)
├── rule_engine.py           RuleEngine: matches packets against rules, hot-reloads, dispatches Alerts
└── __init__.py

rules/
└── default_rules.rules    The hardcoded default rule set, editable + hot-reloadable

flow_analyzer/
├── models.py              FlowKey, Flow, FlowAnomaly, AnomalyType — this stage's data contracts
├── interfaces.py           FlowEventHandler abstract base — plug-in point for Detection Engine/Database later
├── config.py               FlowAnalyzerConfig — thresholds and timeouts
├── flow_analyzer.py         FlowAnalyzer: tracks flows, sliding-window detection, dispatches FlowAnomalys
└── __init__.py

ui/
├── config.py              DashboardConfig — row limits, refresh rate
├── dashboard.py             TerminalDashboard: thread-safe data store + rich render logic
├── handlers.py              Dashboard{Packet,Alert,FlowEvent}Handler — same plug-in pattern as main.py's console handlers
└── __init__.py

tests/
├── test_packet_parser.py     ~13 tests, synthetic packets + payload extraction
├── test_rule_parser.py       ~15 tests, valid + invalid rule syntax + payload_regex
├── test_rule_engine.py       ~20 tests, matching logic + hot reload + payload routing
├── test_flow_analyzer.py     ~19 tests, flow tracking + threshold detection + cooldown + 5 new detectors
└── test_ui_dashboard.py      ~14 tests, data intake, bounded deques, render() sanity, thread-safety, payload panel

main.py                    Stage 1-3 demo entrypoint: plain scrolling console output
main_dashboard.py          Stage 4 demo entrypoint: live in-place terminal dashboard
```

**Why split parser from engine (all stages):** `packet_parser.py` and
`rule_parser.py` are pure functions with zero knowledge of sniffing or file
I/O — fully unit-testable without a live interface or admin rights.
`capture_engine.py` is the only file touching a live interface;
`rule_engine.py` is the only file touching the filesystem (for hot reload);
`flow_analyzer.py` has no I/O at all — its sliding-window logic is testable
purely by constructing packets with controlled timestamps, as the test
suite does. `dashboard.py`'s data layer (`add_packet`/`add_alert`/
`add_anomaly`/`_snapshot`) is likewise decoupled from actual terminal
rendering, so it's tested directly without needing a real TTY.

**Why `RuleEngine` and `FlowAnalyzer` both implement `PacketHandler`:** both
register with `CaptureEngine` exactly like any other handler — Stage 1's
code needed zero changes to support either of them. The same plug-in
pattern repeats for `AlertHandler`, `FlowEventHandler`, and now the three
`Dashboard*Handler` adapters: `main_dashboard.py` reuses the exact same
`CaptureEngine`/`RuleEngine`/`FlowAnalyzer` objects as `main.py` — only the
handlers wired into them differ.

## Setup (Windows — your target platform)

1. Install [Npcap](https://npcap.com/) — check **"Install Npcap in WinPcap
   API-compatible Mode"** during setup. This is what lets Scapy actually see
   packets on Windows.
2. `pip install -r requirements.txt`
3. Run your terminal **as Administrator** (packet capture needs elevated
   privileges on every OS).
4. `python main.py`

Press `Ctrl+C` to stop; it will print a packets-seen/parsed summary.

## Running the tests

```
pytest tests/ -v
```

~81 tests total, none requiring admin rights or a real interface — including
in CI. `test_ui_dashboard.py` exercises the dashboard's data layer directly
(bounded deques, thread-safe concurrent writes, `render()` producing a
valid `Layout`) without needing a real terminal.

## What's next (later stages, not built yet)

- Detection Engine (higher-level attack signatures built on top of flows —
  beaconing, data exfiltration, multi-stage attack correlation)
- Database Layer (persist packets/flows/alerts/payload-alerts instead of only displaying them)
- Web Dashboard (React/FastAPI version, if you want it later — bigger stage)

Each will be proposed, designed, and approved as its own stage before code —
per the incremental process this project follows.

## Stage 5 — Validating Against `ids_attack_simulator.py`

The simulator (`ids_attack_simulator.py`) was built specifically as a
test bench for this IDS. Run it from a second admin terminal while the
dashboard is up:

```
python ids_attack_simulator.py all --target 127.0.0.1 --port 80
```

That's the single most comprehensive test: it runs every module in sequence
and the dashboard's four counters (packets / alerts / anomalies / payload)
should all advance visibly. Individual modules work too — see the "What
Stage 5 lets the simulator prove" table above for the per-module
expectations.

Use `127.0.0.1` as target since both run on the same machine. On Windows +
Npcap, the loopback adapter doesn't show up in `get_if_list()` by default,
so the CaptureEngine calls Scapy's `route_add_loopback()` automatically on
`sys.platform == "win32"` (see `packet_capture/capture_engine.py`); this is
the documented Scapy workaround and is a no-op on Linux/macOS. If loopback
still isn't visible on your Npcap install, use the LAN IP instead.
