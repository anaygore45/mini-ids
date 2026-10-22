# Mini-IDS: Intelligent Network Intrusion Detection & Prevention System (IDPS)

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20Linux-lightgrey.svg)](https://www.microsoft.com/windows)
[![Tests](https://img.shields.io/badge/Tests-143%20Passed-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/IDPS-Hybrid%20Detection%20%2B%20Multi--Mode%20Prevention-orange.svg)](docs/architecture.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An integrated, machine-learning-assisted **Intrusion Detection and Prevention System (IDPS)** and Exploratory Security Analytics Platform built with Python, Scapy, scikit-learn, SQLite, and Streamlit.

Designed for Computer Science & Engineering final-year evaluations, technical reviews, and cybersecurity operations research, Mini-IDS integrates three interconnected disciplines:
1. **Cybersecurity & Network Defense:** Stateful heuristic rule detection, raw packet dissection, bidirectional flow reconstruction, composite threat scoring, multi-mode prevention execution (Simulation, Manual Approval, Authorized OS Firewall Enforcement), automated verification, and clean shutdown rollback.
2. **Artificial Intelligence & Machine Learning:** Supervised classification (Random Forest, Logistic Regression) and unsupervised anomaly detection (Isolation Forest) trained on real benchmark datasets (CIC-IDS2017) with strict feature schemas, model explainability, and defensive triage playbooks.
3. **Data Science & Traffic Analytics:** Statistical dataset profiling, correlation analysis, discrete interval traffic binning, interactive exploratory data analysis (EDA), and immutable forensic audit trails.

---

## 1. System Architecture & Prevention Pipeline

```
                       Network Traffic / Uploaded PCAP
                                      |
                                      v
                              Traffic Ingestion
                        (Live Sniffer / PCAP Reader)
                                      |
                                      v
                        Packet Parsing & Normalization
                                      |
                                      v
                        Bidirectional Flow Aggregation
                           (28 Canonical Features)
                                      |
                                      v
                           Hybrid Detection Engine
             +------------------------+------------------------+
             |                        |                        |
             v                        v                        v
     Heuristic Rules         Supervised Classifiers    Isolation Forest
 (PortScan, SynRate, Vol)      (RF, Logistic Reg)      (Anomaly Outlier)
             |                        |                        |
             +------------------------+------------------------+
                                      |
                                      v
                        Threat Scoring & Correlation
                        (Composite Score 0.0 - 1.0)
                                      |
                                      v
                            Response Policy Engine
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
   [Allowlist Match / Low Risk]                            [High Threat Score]
         |                                                         |
         v                                                         v
    LOG_ALERT Only                                         Prevention Mode
 (Zero Action Taken)                         +---------------------+---------------------+
                                             |                     |                     |
                                             v                     v                     v
                                          MODE A:               MODE B:               MODE C:
                                        Simulation          Manual Approval          Authorized
                                      (Safe Default)        (Operator Queue)         Enforcement
                                             |                     |              (Host Firewall)
                                             |                     v                     |
                                             |              [Human Review]               |
                                             |              Approve / Reject             |
                                             +---------------------+---------------------+
                                                                   |
                                                                   v
                                                        Firewall Adapter Execution
                                                      (Simulation / netsh advfirewall)
                                                                   |
                                                                   v
                                                        Verification Subsystem
                                                      (Query Active Rule State)
                                                                   |
                                                                   v
                                                        Immutable Audit Logging
                                                      (sqlite3 audit_log table)
                                                                   |
                                                                   v
                                                      Streamlit Prevention Center
                                                        & Forensic Audit Console
```

---

## 2. Key Prevention Safeguards & Operating Modes

Mini-IDS enforces strict defense-in-depth safeguards to ensure safe, ethical, and reliable prevention operations:

### 2.1 Multi-Mode Prevention Engine
- **Mode A — Simulation Mode (Safe Default):** Detections generate calibrated response recommendations and simulated firewall entries in memory and database. The host operating system firewall is **never** altered. Recommended for evaluations, classroom settings, and non-administrative environments.
- **Mode B — Manual Approval Mode (Human-in-the-Loop):** Suspected attacks are placed in the **Pending Approvals Queue**. An authorized security analyst must explicitly inspect the rationale, threat score, and target before approving execution.
- **Mode C — Authorized Enforcement Mode (Opt-in Host Firewall):** Direct host-level inbound packet blocking via Windows Defender Firewall (`netsh advfirewall`) or Linux `iptables`. Requires explicit operator activation and elevated administrator privileges.

### 2.2 Built-in Safety Constraints
1. **Self-Lockout Immunity:** Core infrastructure addresses can **never** be blocked:
   - Loopback: `127.0.0.1`, `::1`, `localhost`
   - Network Infrastructure: `0.0.0.0`, `255.255.255.255`
   - Public Resolvers: `8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, `9.9.9.9`
   - Configurable local subnets (gateways and operator IPs)
2. **Offline Data Containment:** Ingestion of offline PCAP captures or synthetic demonstration data is permanently restricted to **Simulation Mode**. Captures from other networks can never block local computer traffic.
3. **Prefix Rule Scoping:** All created host firewall rules are strictly prefixed with `MiniIDS_Block_*`. The application can never modify or delete external system or user rules.
4. **State Verification:** An action is only marked `VERIFIED` after querying the firewall driver to confirm the rule is present and active.
5. **Timed Rollback & Clean Shutdown:** All blocking rules possess configurable expiration limits (default: 300s). An automated background monitor prunes expired rules, and a clean shutdown hook removes all active rules upon exit.

---

## 3. Real Benchmark Machine Learning Results (CIC-IDS2017)

All reported metrics are measured from genuine evaluation runs on held-out test splits (2,250 records for multiclass, 1,500 records for binary) extracted directly from the Canadian Institute for Cybersecurity **CIC-IDS2017** benchmark via Hugging Face (`bvsam/cic-ids-2017`). None of these numbers are fabricated or simulated.

| Model Version | Algorithm | Task Type | Accuracy | Precision (Macro) | Recall (Macro) | F1-Score (Macro) | Train Samples | Test Samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `random_forest_binary` | Random Forest | Binary | **99.93%** | **99.94%** | **99.93%** | **99.93%** | 7,000 | 1,500 |
| `logistic_regression_binary` | Logistic Regression | Binary | **96.00%** | **96.02%** | **95.88%** | **95.95%** | 7,000 | 1,500 |
| `random_forest_multiclass` | Random Forest | Multiclass | **99.87%** | **99.87%** | **99.87%** | **99.87%** | 10,500 | 2,250 |
| `logistic_regression_multiclass` | Logistic Regression | Multiclass | **99.60%** | **99.60%** | **99.60%** | **99.60%** | 10,500 | 2,250 |
| `isolation_forest_anomaly` | Isolation Forest | Anomaly | *Inlier Baseline* | *N/A* | *Unsupervised* | *N/A* | 3,500 (Benign) | 2,250 |

### Multiclass Confusion Matrix (Random Forest, Held-Out Test Set, N=2,250)
```
Classes: ['BENIGN', 'DDoS', 'PortScan']
[[748    0    2]    <- BENIGN    (Recall: 99.7%)
 [  0  750    0]    <- DDoS      (Recall: 100.0%)
 [  1    2  747]]   <- PortScan  (Recall: 99.6%)
```

---

## 4. Installation & Windows Setup

### 4.1 Prerequisites
1. **Python 3.10+ (Tested through Python 3.14):** Verify with `python --version`.
2. **Npcap for Windows (Required only for live interface capture):**
   - Download and install [Npcap](https://npcap.com/#download).
   - Ensure the option **"Install Npcap in WinPcap API-compatible Mode"** is checked.
   - *Note: Npcap is NOT required for offline PCAP analysis, model training, prevention simulation, or demonstration mode.*

### 4.2 Clone & Virtual Environment Setup
Open PowerShell as Administrator (or standard user for simulation/demo):

```powershell
# 1. Enable execution of PowerShell scripts if needed
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# 2. Clone repository and navigate to workspace
git clone https://github.com/anaygore45/mini-ids.git
cd mini-ids

# 3. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 4. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 5. Quick Start & Demonstration

### 5.1 Run the Interactive Prevention Demonstration
Execute the end-to-end prevention verification script to observe threat scoring, simulation, manual approval, allowlist protection, and rollback:
```powershell
python scripts/demo_prevention.py
```

### 5.2 Launch the Streamlit IDPS Security Dashboard
```powershell
streamlit run app.py
```
Navigate to `http://localhost:8501` in your browser. The dashboard automatically initializes the database and launches into the warm-neutral security console.

### 5.3 Offline PCAP Hybrid Analysis
To analyze a recorded network capture and correlate heuristic rules with ML models and policy recommendations:
```powershell
python main.py --pcap data/sample.pcap --hybrid
```

### 5.4 Live Windows Packet Capture
```powershell
# List available network adapters discovered by Npcap
python main.py --list-interfaces

# Sniff packets live on interface (e.g. Wi-Fi) with limits
python main.py --interface "Wi-Fi" --count 500 --timeout 30 --hybrid
```

---

## 6. Machine Learning Lifecycle & Training Pipeline

Mini-IDS provides a fully reproducible training and evaluation pipeline backed by genuine public datasets:

```powershell
# 1. Programmatically acquire and sample CIC-IDS2017 Parquet datasets from Hugging Face
python training/download_dataset.py

# 2. Prepare, harmonize to 28 canonical features, and create leakage-free splits
python training/prepare_data.py --task-type multiclass
python training/prepare_data.py --task-type binary

# 3. Train Random Forest, Logistic Regression, and Isolation Forest models
python training/train_models.py --task-type multiclass
python training/train_models.py --task-type binary

# 4. Rigorously evaluate models on held-out test partitions and generate JSON metrics
python training/evaluate_models.py --task-type multiclass
python training/evaluate_models.py --task-type binary
```

### 6.1 Executable Jupyter Notebook
For interactive data science evaluation and thesis documentation, run the end-to-end notebook:
```powershell
jupyter notebook notebooks/mini_ids_model_training.ipynb
```
The notebook walks through:
- Ingestion and checksum verification of CIC-IDS2017 flows.
- Exploratory Data Analysis (EDA) and class distributions.
- Handling of infinite/NaN values and leakage column exclusion (`src_ip`, `dst_ip`, `timestamp`).
- Preprocessor fitting strictly on `X_train`.
- Model training and hyperparameter selection.
- Metric tables, confusion matrices, and ROC-AUC curves.
- Artifact export and real-time inference testing.

---

## 7. Running the Automated Test Suite

Mini-IDS includes **143 automated unit, integration, boundary, and headless Streamlit UI tests** with 100% pass rate:

```powershell
# Run the full test suite
python -m pytest

# Run with concise summary
python -m pytest -q

# Run specific prevention and training suites
python -m pytest tests/test_prevention.py tests/test_training_cli.py tests/test_hybrid.py
```

---

## 8. 11-Page Security Analytics Interface

The Streamlit dashboard provides 11 distinct, focused analytical workspaces:

1. **Overview:** Executive security posture, KPI scorecards, model readiness cards, alert distribution charts, and quick capture controls.
2. **Live Monitoring:** Interface selection, packet/duration limits, active sniffer telemetry, and real-time event streaming.
3. **Prevention Center (NEW):** Multi-mode execution toggle (Simulation, Manual Approval, Authorized Enforcement), pending approval queue with inline Accept/Reject buttons, active firewall blocks table, manual unblock controls, and allowlist safeguards.
4. **Audit Log (NEW):** Immutable forensic audit trail of all policy evaluations, simulated blocks, host firewall modifications, operator approvals, and automated rollbacks with deep JSON payload inspection.
5. **Alert Investigation:** Deep forensic workbench with detection method filters, correlated raw packet inspection, and contextual defensive playbooks.
6. **Traffic Intelligence:** Protocol breakdowns, top destination ports, most active hosts, and discrete interval traffic throughput.
7. **AI/ML Detection:** Live flow inference console, comparison between heuristic rules vs ML predictions, and anomaly scoring diagnostics.
8. **Model Laboratory:** Registered model versions, evaluation metrics comparison table, feature importance ranking, and one-click model activation.
9. **Data Explorer:** Tabular dataset profiling, missing/infinite value health checks, class distribution charts, and Pearson correlation matrices.
10. **Detection Rules:** Configuration and threshold documentation for heuristic rules and ML confidence boundaries.
11. **System & Settings:** Database diagnostics, table row counts, schema status, log viewer, and demonstration mode toggle.

---

## 9. Limitations & Ethical Considerations

> [!CAUTION]
> **Defensive and Educational Scope Only:**
> Mini-IDS is designed strictly for authorized security monitoring, educational demonstrations, and defense research. It must not be deployed to monitor or alter networks or hosts without explicit authorization.

- **Host Firewall Elevation:** Real firewall enforcement on Windows requires administrative elevation. If non-elevated, Mini-IDS gracefully restricts execution to Simulation Mode without crashing.
- **Model Generalization:** Machine learning models trained on benchmark datasets (e.g. CIC-IDS2017) may experience performance degradation on divergent network environments due to distribution shift. Continuous retraining and heuristic baseline hybrid detection are recommended.
- **High-Throughput Limitations:** Python and Scapy are optimized for educational clarity and modularity. In gigabit enterprise production environments, dedicated kernel-bypass solutions (e.g. DPDK, PF_RING) and hardware-accelerated engines (e.g. Suricata, Zeek) are standard.

---

## 10. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
