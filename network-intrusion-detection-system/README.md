# Network Intrusion Detection System (NIDS)

A lightweight, Python-based Network Intrusion Detection System that analyzes
network traffic — either offline from a `.pcap` file or live from a network
interface — and flags port scans, brute-force attempts, suspicious port
access, and known-malicious IPs. Alerts are enriched with MITRE ATT&CK
context and a risk score, and can be viewed via the CLI or a live Flask web
dashboard.

## Features

- **Offline analysis** of `.pcap` capture files (`main.py`)
- **Live capture & detection** from a network interface (`live_ids.py`)
- **Web dashboard** with real-time charts of alerts, top talkers, and top
  ports, backed by a continuous background capture engine
  (`dashboard/app.py`)
- **Detection rules**: port scanning, brute force, suspicious/high-risk
  port access, and threat-intelligence IOC matching
- **MITRE ATT&CK mapping**, numeric risk scoring, and severity
  classification (LOW / MEDIUM / HIGH / CRITICAL) for every alert
- **Analytics utilities**: top talkers, top ports, protocol breakdown
- Structured, professional logging throughout (no ad-hoc `print` calls
  in the core library code)

## Architecture Overview

```
network-intrusion-detection-system/
├── data/                    # Packet ingestion: PCAP loading + live interface capture
├── detections/              # Detection rules (port scan, brute force, suspicious ports)
├── mappings/                # Static lookup tables: MITRE ATT&CK, risk scores, severity
├── threat_intel/            # IOC matching against a local malicious-IP feed
├── analytics/               # Statistics, top talkers/ports, protocol analysis
├── reports/                 # Alert/report formatting and export to exports/
├── dashboard/                # Flask web dashboard + background capture engine
├── network-event-library/    # Sample detection event fixtures for reference
├── pcap/                      # Sample .pcap capture used by the CLI tools
├── exports/                    # Generated JSON/text artifacts (gitignored, kept via .gitkeep)
├── main.py                      # CLI: run the full offline pipeline against a PCAP
├── live_ids.py                   # CLI: short foreground live-capture session
├── live_alert.py                  # Builds/logs a single enriched real-time alert
├── analyze_hosts.py                # CLI: top talkers in a PCAP
├── analyze_pcap.py                  # CLI: top destination ports in a PCAP
├── analyze_protocols.py              # CLI: protocol breakdown for a PCAP
├── test_pcap.py                       # Manual smoke test for PCAP loading
├── test_live.py                        # Manual smoke test for live capture
└── logging_config.py                    # Shared logging setup used by every entry point
```

**Data flow (offline pipeline):**

`pcap/*.pcap` → `data.pcap_loader.load_pcap` → `detections.detection_manager.run_detections`
→ enrichment (`mappings.mitre_mapping`, `mappings.risk_scores`, `mappings.severity`)
→ `reports.alert_generator` / `reports.network_report` → `reports.report_export`
(writes to `exports/`)

**Data flow (live pipeline):** `live_ids.py` and `dashboard/capture_engine.py`
both sniff packets with scapy, run each packet through
`detections.suspicious_ports.detect` and `threat_intel.threat_matcher.check_ip`
in real time, and route hits through `live_alert.generate_live_alert`. The
dashboard's engine additionally persists rolling snapshots to
`exports/alerts.json` and `exports/live_packets.json` every few seconds so
the Flask frontend can poll them.

## Installation

**Requirements:** Python 3.10+, and (for live capture) permission to open
raw sockets — plus [Npcap](https://npcap.com/) on Windows.

```bash
# 1. Clone / unzip the project, then from the project root:
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
```

## Running the CLI Analyzer

Analyze the bundled sample capture (`pcap/sample.pcap`) end-to-end — runs
detections, prints enriched alerts, and exports `alerts.json`,
`incident_report.txt`, `network_statistics.json`, and
`network_security_report.txt` to `exports/`:

```bash
python main.py
python main.py --pcap path/to/other.pcap --log-level DEBUG
```

Smaller, focused CLI utilities:

```bash
python analyze_hosts.py         # top talkers (source IPs)
python analyze_pcap.py          # top destination ports
python analyze_protocols.py     # protocol breakdown
python test_pcap.py             # sanity-check PCAP loading
```

Live capture from a network interface (requires elevated privileges):

```bash
sudo python live_ids.py --count 200 --interface eth0
```

## Running the Web Dashboard

The dashboard runs a continuous background capture thread and serves a
live-updating page of alerts, charts, and top talkers/ports. It requires
the same elevated privileges as live capture:

```bash
sudo python dashboard/app.py --interface eth0
# then open http://127.0.0.1:5000
```

Useful flags: `--host`, `--port`, `--debug` (Flask debug mode; the
auto-reloader is disabled deliberately to avoid spawning a second capture
thread — restart manually after code changes).

## Detection Rules

| Rule | Trigger | MITRE Technique |
|---|---|---|
| Port Scan | One source IP contacts >= 4 distinct destination ports | T1046 - Network Service Discovery |
| Brute Force | One source IP makes >= 5 attempts to the same destination port | T1110 - Brute Force |
| Suspicious Port Access | Traffic to a commonly-abused port (21, 22, 23, 80, 443, 3389, 5900) | T1595 - Active Scanning |
| Threat Intelligence Match | Source IP appears in `threat_intel/malicious_ips.json` | T1583 - Malicious Infrastructure |

Thresholds live as named constants at the top of each detection module
(`detections/port_scan.py`, `detections/brute_force.py`) and can be tuned
there.

## Notes

- `exports/` is regenerated on every run and is gitignored (aside from a
  `.gitkeep` placeholder) — nothing in it should be treated as a source
  file.
- `data/packet_data.py` and `network-event-library/*.json` are sample
  fixtures for manual experimentation, not part of the production
  pipeline.
- `analytics/flow_tracker.py` is an intentional stub for future
  session/flow-level correlation.
