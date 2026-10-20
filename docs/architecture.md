# Mini-IDS Architecture & Design Specification

## 1. System Overview

**Mini-IDS** is a lightweight, educational Network Intrusion Detection System (NIDS) designed for Windows environments. It analyzes network traffic—either ingested from pre-recorded PCAP files or captured live from a local network interface—to detect suspicious activity and generate actionable security alerts.

> [!IMPORTANT]
> **Passive Detection (NIDS vs. NIPS):**
> Mini-IDS is strictly a *detection* system (NIDS). It passively observes, parses, and evaluates network traffic to record security alerts. It **does not** act as an inline Intrusion Prevention System (NIPS): it does not drop packets, reset TCP sessions, or alter firewall rules.

---

## 2. End-to-End Pipeline & Data Flow

Regardless of whether the input originates from an offline PCAP file or a live network adapter, all packets pass through the exact same processing pipeline:

```
+---------------------------+     +-------------------------------+
|  Offline PCAP File        |     |  Live Network Interface       |
|  (e.g., sample.pcap)      |     |  (via Scapy + Npcap)          |
+-------------+-------------+     +---------------+---------------+
              |                                   |
              +-----------------+-----------------+
                                |
                                v
               +---------------------------------+
               |  Packet Ingestion & Reading     |
               |  (capture/packet_capture.py)    |
               +----------------+----------------+
                                |
                                v
               +---------------------------------+
               |  Normalization & Metadata       |
               |  Extraction                     |
               |  (Timestamp, IP, Port, Flags)   |
               +----------------+----------------+
                                |
                                v
               +---------------------------------+
               |  Detection Engine Coordinator   |
               |  (detection/...)                |
               +----------------+----------------+
                                |
              +-----------------+-----------------+
              |                 |                 |
              v                 v                 v
     +-----------------+ +-------------+ +------------------+
     | TCP Port Scan   | | TCP SYN     | | Traffic Rate     |
     | Rule            | | Rate Rule   | | Anomaly Rule     |
     +--------+--------+ +------+------+ +--------+---------+
              |                 |                 |
              +-----------------+-----------------+
                                | (Alert Events)
                                v
               +---------------------------------+
               |  Alert Manager & Persistence    |
               |  (storage/database.py)          |
               +----------------+----------------+
                                |
                                v
               +---------------------------------+
               |  SQLite Database                |
               |  (alerts.db)                    |
               +----------------+----------------+
                                |
                                v
               +---------------------------------+
               |  Streamlit Security Dashboard   |
               |  (app.py)                       |
               +---------------------------------+
```

---

## 3. Module Responsibilities

### 3.1 Packet Capture & Normalization (`capture/`)
- **Offline PCAP Reader (`capture/packet_capture.py`):** Uses Scapy's `PcapReader` to stream packets iteratively from `.pcap` / `.pcapng` files without loading entire captures into memory.
- **Live Interface Capture (`capture/live_capture.py`):**
  - Interfaces with Windows packet drivers (Npcap) using Scapy's `AsyncSniffer`.
  - Safe enumeration of adapters via `get_available_interfaces()`.
  - Uses an internal bounded `queue.Queue` to decouple raw packet capture from detector execution and SQLite disk I/O, preventing packet drops.
  - Manages background thread execution via `LiveCaptureWorker` with atomic status telemetry and stop triggers (duration timeout, packet count limit, manual stop).
- **Packet Normalizer:** Decouples downstream detection from raw Scapy packet structures by extracting a normalized dataclass (`NormalizedPacket`):
  - `timestamp`: Float (epoch seconds)
  - `src_ip`: String
  - `dst_ip`: String
  - `protocol`: String (TCP, UDP, ICMP, OTHER)
  - `src_port`: Integer (optional)
  - `dst_port`: Integer (optional)
  - `tcp_flags`: String (e.g., 'S', 'SA', 'FA', 'R')
  - `length`: Integer (bytes)

By normalizing traffic at ingestion, **offline replay and live capture share identical detection logic**.

### 3.2 Detection Engine (`detection/`)
The detection engine comprises three specialized detection modules operating over sliding time windows:

1. **Potential TCP Port Scan (`detection/port_scan.py`):**
   - *Threat Model:* An adversary probing a host to identify open listening ports and attack surface.
   - *Logic:* Tracks unique destination ports contacted by a given `src_ip` within a rolling time window $\Delta t$. If the count of distinct `dst_port` values exceeds a threshold $N_{ports}$, an alert is raised.

2. **Unusually High TCP SYN Rate (`detection/syn_rate.py`):**
   - *Threat Model:* SYN flood denial-of-service (DoS) attempts or fast network scanners.
   - *Logic:* Counts TCP packets where only the SYN flag is set (`flags == 'S'`) originating from a source IP or targeted at a destination IP within time window $\Delta t$. An alert is raised when the rate exceeds $N_{syn}$ packets/sec.

3. **Traffic-Rate Volume Anomaly (`detection/traffic_anomaly.py`):**
   - *Threat Model:* Network floods, data exfiltration, or sudden infrastructure anomalies.
   - *Logic:* Aggregates aggregate packet counts and byte volumes across uniform rolling intervals. If the packet rate or byte throughput surges beyond a configured multiple of the rolling baseline or fixed safety threshold, an anomaly alert is triggered.

### 3.3 Storage Layer (`storage/`)
- **Database Engine:** Lightweight, embedded SQLite (`sqlite3`) with WAL (Write-Ahead Logging) journal mode for concurrent read/write access.
- **Schema Design:**
  - `packets` table: `id`, `timestamp` (epoch float), `src_ip`, `dst_ip`, `protocol`, `length`, `src_port`, `dst_port`, `tcp_flags`.
  - `alerts` table: `id`, `timestamp` (epoch float), `rule_name`, `src_ip`, `dst_ip`, `observed_value`, `threshold`, `window_seconds`, `severity`, `message`.
  - Indexes: B-tree indexes on `timestamp`, `src_ip`, `dst_ip`, and `rule_name` for sub-second analytical querying.
- **Analysis Run Scoping:** The schema preserves raw cumulative records across offline PCAP and live sessions. Analysis isolation is performed via parameterized timestamp interval queries (`[start_time, end_time]`).

### 3.4 User Interface & Dashboard (`app.py`)
- **Dashboard Framework:** Streamlit + Altair for declarative interactive visualizations.
- **Features:**
  - **Live Packet Capture Controls:** Interface selection, stop condition controls (duration/count/manual), real-time status banners, and refreshable telemetry.
  - **Executive summary KPIs:** Cumulative stored packets, total alerts, high-severity events, distinct alert sources.
  - **Security analytics:** Alert severity distribution, detection rule breakdown, discrete column bar alert timeline, top offending sources, and top targeted destination hosts.
  - **Traffic analytics:** Protocol distribution, top destination ports, network volume timeline, and top traffic destinations.
  - **Alert investigation workflow:** Drill-down by alert ID with correlated packet evidence within sliding evaluation windows.
  - **Scoped time-range filtering** and protocol/rule filters.

### 3.5 Core Coordinator (`main.py`)
- CLI entrypoint supporting both offline PCAP ingestion (`--pcap`) and live capture (`--interface`, `--count`, `--timeout`, `--list-interfaces`).

---

## 4. Live Capture Concurrency & Safety Model

```
+---------------------------------------------------------------------------------+
|                                Streamlit Main Thread                            |
|  - Renders UI controls (Start / Stop / Refresh)                                 |
|  - Queries worker snapshot via worker.get_status()                              |
|  - Reads database records via read-only DatabaseManager                         |
+----------------------------------------+----------------------------------------+
                                         | (Configures & Starts Worker)
                                         v
+---------------------------------------------------------------------------------+
|                       LiveCaptureWorker Thread (Daemon)                         |
|  - Opens dedicated, thread-confined DatabaseManager instance                    |
|  - Spawns Scapy AsyncSniffer on specified adapter                               |
|  - Pulls normalized packets from thread-safe queue.Queue                        |
|  - Evaluates PortScanDetector, SynRateDetector, TrafficAnomalyDetector          |
|  - Batches packet and alert writes to SQLite (WAL mode)                         |
|  - Monitors duration timeouts, packet limits, and manual stop events            |
|  - Closes database connection cleanly upon completion                           |
+----------------------------------------+----------------------------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
             [AsyncSniffer Sniff Thread]         [SQLite Database (WAL)]
             - Captures raw L2/L3 frames         - Independent connections
             - Normalizes packet metadata        - Atomic batch transactions
             - Pushes to queue (non-blocking)    - Preserves historical records
```

---

## 5. Current Status vs. Milestone Plan

| Component | Status | Target Milestone |
|---|---|---|
| Project Structure & Environment | **Completed** | Milestone 0 |
| PCAP Reader & Normalizer | **Completed** | Milestone 1 |
| Detection Rules (Port scan, SYN, Volume) | **Completed** | Milestone 2 |
| SQLite Alert & Packet Storage | **Completed** | Milestone 3 |
| Streamlit Dashboard & CLI Runner | **Completed** | Milestone 4 |
| Live Packet Capture & Npcap Sniffing | **Completed** | Live Capture Milestone |

