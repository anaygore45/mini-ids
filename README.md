# Mini-IDS: Network Intrusion Detection System

A lightweight, modular, educational Network Intrusion Detection System (NIDS) built with Python, Scapy, SQLite, and Streamlit on Windows.

> [!NOTE]
> **Project Status: Live Packet Capture & Security Analytics Completed**
> The project provides dual ingestion pipelines (offline PCAP analysis and Npcap live packet capture), persistent SQLite database storage, heuristic detection rules (Port Scan, SYN Rate, Traffic Anomaly), an automated test suite (97 passed), and an interactive Streamlit Security Analytics Dashboard with alert investigation and live capture controls.

---

## 1. What is a Network IDS?

A **Network Intrusion Detection System (NIDS)** is a security tool that monitors network traffic passing through a network segment or host interface. By inspecting packet headers and traffic statistics, a NIDS identifies patterns matching known malicious activities (signature-based) or abnormal deviations from normal behavior (anomaly-based).

Mini-IDS operates as a **passive detection system**: it logs events and notifies analysts via a dashboard, but it does **not** block network traffic or alter packet routing. Detected anomalies indicate suspicious or elevated activity according to heuristic thresholds; they represent correlated network telemetry rather than definitive proof of malicious intent or host compromise.

---

## 2. Implemented Features & Detection Capabilities

- **Dual Ingestion Architecture:**
  - **Offline PCAP/PCAPNG Ingestion (Primary):** Deterministic, repeatable ingestion of network trace files via Scapy.
  - **Optional Live Capture:** Passive live sniffing on Windows interfaces (requires administrative privileges and Npcap).
- **Three Core Detection Modules:**
  1. **TCP Port Scan Detection:** Identifies rapid probing across multiple unique destination ports on a target host within a configurable time window.
  2. **TCP SYN Rate Anomaly:** Flags abnormally elevated rates of SYN packets without completed handshakes (e.g., SYN flood patterns or fast scans).
  3. **Traffic Volume Anomaly:** Detects sudden volumetric surges in packet rate or byte throughput exceeding baseline thresholds.
- **Persistent SQLite Storage:**
  - Structured storage for normalized packets and security alerts.
  - WAL journal mode enabled for high-concurrency read/write operations.
  - Indexed queries for time-range filtering, alert-packet correlation, and analytics aggregations.
- **Streamlit Security Analytics Dashboard:**
  - **Security Overview KPIs:** Total packet counts, alert counts, and high-severity counters.
  - **Scoped Filtering:** Independent alert filters (Rule, Severity, Time Range) and traffic filters (Protocol, Time Range) with explicit UI labels.
  - **Discrete Timeline Visualizations:** High-fidelity vertical column bar charts for alert frequencies and traffic volume over time without misleading continuous interpolations across observation gaps.
  - **Alert Investigation & Evidence Correlation:** Interactive alert selection that queries and displays correlated network packets within an adjustable +/- time buffer.
  - **Traffic Analytics:** Protocol distribution donuts, top targeted destination ports, and most active destination hosts.

---

## 3. Technology Stack

- **Language:** Python 3.10+ (Tested with Python 3.13)
- **Packet Ingestion & Dissection:** [Scapy](https://scapy.net/)
- **Data Manipulation & Analytics:** [Pandas](https://pandas.pydata.org/), [Altair](https://altair-viz.github.io/)
- **Persistent Storage:** SQLite3 (Python standard library)
- **Security Dashboard:** [Streamlit](https://streamlit.io/)
- **Automated Testing:** [pytest](https://docs.pytest.org/)

---

## 4. Project Directory Structure

```text
mini-ids/
├── capture/                    # Packet ingestion and normalization
│   ├── __init__.py
│   ├── packet_capture.py       # Scapy PCAP reader and packet normalizer
│   └── live_capture.py         # Npcap background sniffer worker and interface resolver
├── detection/                  # Heuristic detection algorithms
│   ├── __init__.py
│   ├── port_scan.py            # TCP port scan detector
│   ├── syn_rate.py             # TCP SYN rate anomaly detector
│   └── traffic_anomaly.py      # Volumetric traffic anomaly detector
├── storage/                    # Persistent alert & packet database
│   ├── __init__.py
│   └── database.py             # SQLite schema, queries, and aggregations
├── tests/                      # Comprehensive test suite (97 tests)
│   ├── __init__.py
│   ├── test_capture.py         # Capture and packet normalization tests
│   ├── test_detection.py       # Core detector logic and alert tests
│   ├── test_boundary_detection.py # Edge cases and boundary condition tests
│   ├── test_storage.py         # SQLite CRUD, indexing, and aggregation tests
│   ├── test_end_to_end.py      # Full pipeline CLI ingestion tests
│   ├── test_dashboard.py       # Headless Streamlit integration and chart tests
│   └── test_live_capture.py    # Live capture worker, interface enumeration, and UI tests
├── data/                       # Local data folder (.gitignore excludes *.db and *.pcap)
│   └── .gitkeep
├── docs/                       # Technical documentation
│   └── architecture.md         # System architecture and data flow
├── app.py                      # Interactive Streamlit security dashboard
├── main.py                     # CLI pipeline entry point
├── inspect_alerts.py           # Quick CLI diagnostic script for alerts
├── inspect_db.py               # Quick CLI diagnostic script for database summary
├── requirements.txt            # Project dependencies
├── README.md                   # Project documentation and setup guide
└── .gitignore                  # Git exclusions for databases, pcaps, caches, and venv
```

---

## 5. Prerequisites & System Requirements

1. **Python 3.10 or higher:** Verify with `python --version` in PowerShell or terminal.
2. **PowerShell Script Execution (Windows):** To enable virtual environment activation:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
   ```
3. **Npcap (Only for Live Capture):** If running live network capture on Windows, install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" enabled. **Offline PCAP ingestion does not require Npcap.**
4. **Data Privacy Notice:** Local SQLite databases (`*.db`) and raw capture files (`*.pcap`, `*.pcapng`) are intentionally excluded from Git tracking via `.gitignore` to protect privacy and keep the repository clean.

---

## 6. Installation & Environment Setup

Follow these steps from the project root directory:

### Step 1: Create a Virtual Environment
```powershell
python -m venv .venv
```

### Step 2: Activate the Virtual Environment
```powershell
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate
```

### Step 3: Upgrade pip and Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Run the Automated Test Suite
Verify that all 97 unit, integration, and dashboard tests pass:
```powershell
pytest -v
```

---

## 7. Usage Guide

### Offline PCAP Ingestion via CLI

Analyze any offline PCAP or PCAPNG capture file using `main.py`. This parses packets, evaluates all three detection rules, and persists records to SQLite:

```powershell
# Ingest your PCAP into the default database (data/mini_ids.db):
python main.py --pcap data/your_capture.pcap

# Ingest into a custom database path:
python main.py --pcap "data/your_capture.pcap" --db "data/custom_alerts.db"
```

> [!TIP]
> Replace `data/your_capture.pcap` with the path to your own packet capture file. Running `main.py` multiple times against the same database appends new records without deleting prior data.

### Live Packet Capture via CLI

Capture live network traffic directly from local network interfaces using `main.py`:

```powershell
# 1. List all network interfaces discovered by Scapy:
python main.py --list-interfaces

# 2. Run live capture with a packet limit (e.g., 100 packets):
python main.py --interface "Wi-Fi" --count 100

# 3. Run live capture with a duration timeout (e.g., 30 seconds):
python main.py --interface "Loopback Pseudo-Interface 1" --timeout 30.0

# 4. Continuous live capture (press Ctrl+C to terminate cleanly):
python main.py --interface "Wi-Fi" --db "data/live_alerts.db"
```

### Launching the Streamlit Security Dashboard

Start the interactive web dashboard to explore security KPIs, analyze traffic patterns, investigate alerts, and control live capture:

```powershell
streamlit run app.py
```

Open your browser to `http://localhost:8501`.

#### Dashboard Capabilities:
- **📡 Live Packet Capture Panel:**
  - Select any discovered network adapter (e.g., Wi-Fi, Ethernet, Loopback).
  - Configure stop conditions (Manual stop, Duration timeout, or Packet count limit).
  - Start, stop, and refresh capture with real-time status banners, packet counts, and alert counts.
  - Automatically commits packets and triggered alerts into the active SQLite database.
- **Custom Database Path:** Connects to `data/mini_ids.db` by default. You can point to any local SQLite database using the sidebar input.
- **Filter Scoping:**
  - **Alert Filters (Rule, Severity, Time Range):** Scope the Security KPIs, Alert Breakdown by Rule, Alert Severity Distribution, Alert Timeline, and Recent Security Alerts.
  - **Traffic Filters (Protocol, Time Range):** Scope Protocol Breakdown, Top Targeted Ports, Traffic Volume Timeline, Most Active Hosts, and Recent Network Traffic.
- **Discrete Timeline Visualizations:** Timeline charts represent discrete time intervals as bars. Empty intervals correctly represent periods of zero activity without misleading continuous lines connecting distant dates.
- **Alert Investigation & Evidence Correlation:** Select an alert from the interactive dropdown to view full details alongside correlated packets observed around the detector window (+/- buffer seconds).

---

## 8. Automated Testing & Verification

The test suite covers unit logic, edge cases, database persistence, live capture workers, and dashboard rendering:

```powershell
pytest -v
```

**Test Coverage Summary (97 tests passed):**
- `test_capture.py`: Packet parsing, IP/TCP/UDP extraction, malformed packet handling (10 tests).
- `test_detection.py`: Port scan, SYN rate, and traffic volume anomaly detection rules (16 tests).
- `test_boundary_detection.py`: Window boundary timing, threshold edge cases, packet suppression (13 tests).
- `test_storage.py`: SQLite schema creation, insertion batching, time-range queries, protocol filtering, and sparse timeline aggregation (21 tests).
- `test_end_to_end.py`: CLI ingestion pipeline execution and database verification (5 tests).
- `test_dashboard.py`: Headless Streamlit runner tests, data framing, and Altair chart construction (12 tests).
- `test_live_capture.py`: Interface enumeration, worker lifecycle, duplicate-start prevention, packet limits, timeout triggers, synthetic integration, and UI controls (20 tests).

---

## 9. Known Limitations & Troubleshooting

- **Npcap Installation:** On Windows, live capture requires [Npcap](https://npcap.com/) installed with *"WinPcap API-compatible Mode"* enabled. If Npcap is missing, `main.py --list-interfaces` will indicate no interfaces found.
- **Administrator Privileges:** Capturing promiscuous traffic on physical Wi-Fi or Ethernet adapters often requires running PowerShell / Terminal as Administrator. If access is denied, run the terminal as Administrator or use the Loopback interface (`127.0.0.1`) for local testing.
- **Passive Sniffing:** Mini-IDS is strictly passive. It does not inject packets, reset TCP sessions, or block traffic.
- **Heuristic Detectors:** Detection rules evaluate sliding-window statistics against threshold heuristics. They provide decision-support telemetry rather than definitive proof of host compromise.
- **Offline PCAP Support:** Offline PCAP ingestion remains fully functional and does not require Npcap or administrator privileges.

---

## 10. Security & Ethical Monitoring Statement

> [!CAUTION]
> **Ethical Monitoring Notice:**
> Live network packet inspection captures sensitive payload headers and metadata. Passive monitoring must strictly be confined to networks, interfaces, and systems that you own or have explicit authorization to inspect. Offline PCAP analysis should only be performed on authorized capture files. Detectors rely on statistical and signature heuristics and should be used as decision-support telemetry rather than autonomous enforcement.
