"""Mini-IDS Security Monitoring Dashboard.

Streamlit web interface for visual inspection of network packets and intrusion
alerts persisted in the Mini-IDS SQLite database.

Features:
- Configurable database path with existence and empty-state validation.
- Cumulative stored-data metrics across all analyses.
- Alert count breakdown by detection rule/type.
- Recent alerts table with rule, severity, IPs, metrics, and descriptions.
- Recent network traffic table with timestamps, IPs, protocols, ports, and flags.
- Interactive filtering by severity, rule, protocol, and record limit.
- Graceful database error handling and reliable connection closure.

NOTE: PCAP processing and detection are performed offline via `main.py`.
This dashboard is strictly a read-only presentation layer.
"""

from collections import Counter
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Union

import altair as alt
import pandas as pd
import streamlit as st

from capture.live_capture import get_available_interfaces, get_live_worker
from storage.database import DEFAULT_DB_PATH, DatabaseManager
from storage.demo_data import DEFAULT_DEMO_DB_PATH, get_or_create_demo_database

logger = logging.getLogger("mini_ids.dashboard")



def format_timestamp(ts: Union[float, int, str, None]) -> str:
    """Format UNIX epoch float to a readable datetime string (UTC).

    Args:
        ts: UNIX epoch timestamp in seconds.

    Returns:
        str: Formatted UTC timestamp string, or fallback string representation.
    """
    if ts is None:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def build_severity_chart(severity_data: List[Dict[str, Any]]) -> Optional[alt.Chart]:
    """Construct an Altair horizontal bar chart for alert severity distribution."""
    if not severity_data:
        return None
    df = pd.DataFrame(severity_data)
    color_scale = alt.Scale(
        domain=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        range=["#dc2626", "#ef4444", "#f59e0b", "#06b6d4"],
    )
    chart = (
        alt.Chart(df)
        .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
        .encode(
            x=alt.X("count:Q", title="Alert Count"),
            y=alt.Y("severity:N", sort=["CRITICAL", "HIGH", "MEDIUM", "LOW"], title="Severity Tier"),
            color=alt.Color("severity:N", scale=color_scale, legend=None),
            tooltip=[
                alt.Tooltip("severity:N", title="Severity"),
                alt.Tooltip("count:Q", title="Alert Count", format=","),
            ],
        )
        .properties(height=180)
    )
    return chart


def build_rule_chart(rule_data: List[Dict[str, Any]]) -> Optional[alt.Chart]:
    """Construct an Altair horizontal bar chart for alerts by detection rule."""
    if not rule_data:
        return None
    df = pd.DataFrame(rule_data)
    chart = (
        alt.Chart(df)
        .mark_bar(color="#0284c7", cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
        .encode(
            x=alt.X("count:Q", title="Alert Count"),
            y=alt.Y("rule_name:N", sort="-x", title="Detection Rule"),
            tooltip=[
                alt.Tooltip("rule_name:N", title="Rule"),
                alt.Tooltip("count:Q", title="Alert Count", format=","),
            ],
        )
        .properties(height=180)
    )
    return chart


def build_timeline_chart(
    timeline_data: List[Dict[str, Any]],
    color: str = "#0284c7",
    fill_color: str = "#38bdf8",
    y_field: str = "count",
    y_title: str = "Alert Count",
) -> Optional[alt.Chart]:
    """Construct an Altair discrete column bar chart for event timeline aggregation.

    Uses discrete column bars instead of continuous area interpolation to ensure
    sparse datasets, multi-day/year intervals, and single-observation buckets
    accurately display their true distribution without false activity slopes.
    """
    if not timeline_data:
        return None
    df = pd.DataFrame(timeline_data)
    chart = (
        alt.Chart(df)
        .mark_bar(color=color, cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
        .encode(
            x=alt.X("bucket:N", sort=None, title="Time Bucket (UTC)"),
            y=alt.Y(f"{y_field}:Q", title=y_title),
            tooltip=[
                alt.Tooltip("bucket:N", title="Interval (UTC)"),
                alt.Tooltip(f"{y_field}:Q", title=y_title, format=","),
            ],
        )
        .properties(height=200)
    )
    return chart


def build_ranking_chart(
    data: List[Dict[str, Any]],
    category_field: str,
    value_field: str,
    category_title: str,
    value_title: str,
    bar_color: str = "#6366f1",
) -> Optional[alt.Chart]:
    """Construct a horizontal bar chart for ranked entities (IPs, Ports)."""
    if not data:
        return None
    df = pd.DataFrame(data)
    df[category_field] = df[category_field].astype(str)
    chart = (
        alt.Chart(df)
        .mark_bar(color=bar_color, cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
        .encode(
            x=alt.X(f"{value_field}:Q", title=value_title),
            y=alt.Y(f"{category_field}:N", sort="-x", title=category_title),
            tooltip=[
                alt.Tooltip(f"{category_field}:N", title=category_title),
                alt.Tooltip(f"{value_field}:Q", title=value_title, format=","),
            ],
        )
        .properties(height=180)
    )
    return chart


def render_live_capture_section(target_db_path: Path, is_demo_mode: bool = False) -> None:
    """Render the Live Packet Capture control panel and real-time status."""
    st.markdown("### 📡 Live Packet Capture (Passive Sniffer)")

    if is_demo_mode:
        st.info(
            "☁️ **Live Packet Capture is disabled in Hosted Demonstration Mode.**\n\n"
            "Passive live packet sniffing requires direct physical network adapter access, administrative "
            "privileges, and local Npcap kernel drivers on a host workstation. In this hosted cloud "
            "demonstration, the dashboard operates in safe, read-only forensic mode.\n\n"
            "To perform real-time packet capture on your local Wi-Fi or Ethernet adapter, run Mini-IDS "
            "locally on Windows using:\n"
            "```powershell\n"
            "streamlit run app.py\n"
            "```"
        )
        st.divider()
        return

    st.caption(
        "Capture live traffic from local network adapters using Npcap. Packets are evaluated "
        "against detection rules and saved directly to the active SQLite database."
    )

    worker = get_live_worker()
    status = worker.get_status()

    # Capture status banner
    if status["status"] == "STOPPING":
        st.warning(
            f"⏳ **Stopping capture on `{status['interface']}`... finalizing queue and database writes.**\n\n"
            f"**Packets Captured:** {status['packets_captured']:,} | "
            f"**Persisted to DB:** {status['packets_persisted']:,} | "
            f"**Queue Drops:** {status['packets_dropped']:,} | "
            f"**Alerts Triggered:** {status['alerts_generated']:,}"
        )
    elif status["is_running"]:
        st.info(
            f"🟢 **Live Capture Active on `{status['interface']}`**\n\n"
            f"**Packets Captured:** {status['packets_captured']:,} | "
            f"**Persisted to DB:** {status['packets_persisted']:,} | "
            f"**Queue Drops:** {status['packets_dropped']:,} | "
            f"**Alerts Triggered:** {status['alerts_generated']:,} | "
            f"**Elapsed Time:** {status['elapsed_seconds']:.1f}s"
        )
    elif status["status"] == "COMPLETED":
        st.success(
            f"✅ **Capture Completed on `{status['interface']}`**\n\n"
            f"Captured: **{status['packets_captured']:,}** packets | "
            f"Persisted: **{status['packets_persisted']:,}** | "
            f"Queue Drops: **{status['packets_dropped']:,}** | "
            f"Alerts Triggered: **{status['alerts_generated']:,}** | "
            f"Duration: **{status['elapsed_seconds']:.1f}s**"
        )
    elif status["status"] == "STOPPED":
        st.warning(
            f"⏹️ **Capture Stopped on `{status['interface']}`**\n\n"
            f"Captured: **{status['packets_captured']:,}** packets | "
            f"Persisted: **{status['packets_persisted']:,}** | "
            f"Queue Drops: **{status['packets_dropped']:,}** | "
            f"Alerts Triggered: **{status['alerts_generated']:,}** | "
            f"Duration: **{status['elapsed_seconds']:.1f}s**"
        )
    elif status["status"] == "ERROR":
        st.error(f"❌ **Capture Error:** {status.get('error_message')}")
    elif status["status"] == "IDLE":
        st.caption("ℹ️ **Sniffer Status:** `IDLE` — Ready to capture. Select an interface in the configuration panel below and click **Start Capture**.")

    with st.expander("⚙️ Capture Configuration & Controls", expanded=status["is_running"] or status["status"] == "IDLE"):
        available_ifaces = get_available_interfaces()

        if not available_ifaces:
            st.warning(
                "⚠️ **No network interfaces discovered.**\n\n"
                "Ensure Npcap is installed on Windows with 'WinPcap API-compatible Mode' enabled. "
                "Administrative privileges may be required to access raw network adapters."
            )
            return

        # Interface selection
        iface_labels = [i["display_name"] for i in available_ifaces]
        selected_label = st.radio(
            "Select Network Interface",
            options=iface_labels,
            index=0,
            help="Choose the network adapter to monitor. Passive sniffing only; traffic is not injected or altered.",
            key="live_capture_iface_select",
        )
        selected_iface = next((i for i in available_ifaces if i["display_name"] == selected_label), available_ifaces[0])

        col_cond, col_val = st.columns(2)
        with col_cond:
            stop_condition = st.radio(
                "Stop Condition",
                options=["Manual Stop", "Duration Timeout", "Packet Count Limit"],
                index=0,
                horizontal=True,
                key="live_capture_condition_type",
            )
        with col_val:
            duration_limit: Optional[float] = None
            packet_limit: Optional[int] = None
            if stop_condition == "Duration Timeout":
                duration_limit = float(
                    st.number_input(
                        "Timeout (Seconds)",
                        min_value=1.0,
                        max_value=3600.0,
                        value=15.0,
                        step=5.0,
                        key="live_capture_duration_val",
                    )
                )
            elif stop_condition == "Packet Count Limit":
                packet_limit = int(
                    st.number_input(
                        "Max Packets",
                        min_value=5,
                        max_value=100000,
                        value=100,
                        step=25,
                        key="live_capture_packet_val",
                    )
                )

        btn_start, btn_stop, btn_refresh = st.columns([1, 1, 2])
        with btn_start:
            can_start = not status["is_running"]
            if st.button("▶️ Start Capture", disabled=not can_start, type="primary", key="live_btn_start"):
                iface_id = selected_iface["name"] if selected_iface["name"] else selected_iface["guid"]
                try:
                    worker.configure(
                        interface=iface_id,
                        db_path=target_db_path,
                        packet_limit=packet_limit,
                        duration_seconds=duration_limit,
                    )
                    worker.start()
                    st.rerun()
                except Exception as ex:
                    st.error(f"Failed to start capture: {ex}")

        with btn_stop:
            can_stop = status["is_running"]
            if st.button("⏹️ Stop Capture", disabled=not can_stop, key="live_btn_stop"):
                worker.stop()
                st.rerun()

        with btn_refresh:
            if st.button("🔄 Refresh Live Telemetry", key="live_btn_refresh"):
                st.rerun()

    st.divider()


def render_dashboard() -> None:
    """Render the main Streamlit dashboard UI."""

    st.set_page_config(
        page_title="Mini-IDS Security Dashboard",
        page_icon="🛡️",
        layout="wide",
    )

    # Custom Cybersecurity Console Theme Styling
    st.markdown(
        """
        <style>
        /* Modern Cybersecurity Theme Enhancements */
        [data-testid="stMetric"] {
            background-color: #0f172a;
            border: 1px solid #1e293b;
            padding: 12px 16px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
            transition: border-color 0.2s ease;
        }
        [data-testid="stMetric"]:hover {
            border-color: #0284c7;
        }
        [data-testid="stMetricLabel"] {
            font-size: 0.85rem !important;
            font-weight: 500 !important;
            color: #94a3b8 !important;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        [data-testid="stMetricValue"] {
            font-size: 1.65rem !important;
            font-weight: 700 !important;
            color: #f8fafc !important;
        }
        [data-baseweb="tab-list"] {
            gap: 8px;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 4px;
        }
        [data-baseweb="tab"] {
            border-radius: 6px 6px 0 0 !important;
            padding: 8px 16px !important;
            font-weight: 600 !important;
        }
        .stAlert {
            border-radius: 6px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("🛡️ Mini-IDS Security Dashboard")
    st.caption("Network Intrusion Detection System — Real-Time Packet Sniffing & Forensic Security Analytics")

    # Sidebar: Database Configuration & Refresh
    st.sidebar.header("Database Configuration")
    db_path_input = st.sidebar.text_input(
        "Database Path",
        value=str(DEFAULT_DB_PATH),
        help="Path to SQLite database containing stored packets and alerts.",
    )

    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()

    # Automatically activate demo mode if DEFAULT_DB_PATH does not exist or if MINI_IDS_DEMO_MODE is set
    default_demo_active = (not DEFAULT_DB_PATH.is_file()) or (
        os.environ.get("MINI_IDS_DEMO_MODE", "").lower() in ("1", "true", "yes")
    )

    demo_toggle = st.sidebar.toggle(
        "Demonstration Mode (Synthetic)",
        value=default_demo_active,
        help="Enable sanitized synthetic demonstration dataset for cloud hosting or evaluation without local capture files.",
        key="app_demo_toggle",
    )

    # If the user or test explicitly customized the text input path, respect it; otherwise use demo mode if toggle is active
    raw_path = Path(db_path_input.strip())
    custom_path_provided = bool(raw_path != DEFAULT_DB_PATH)
    is_demo_mode = demo_toggle and not custom_path_provided

    if is_demo_mode:
        target_db_path = get_or_create_demo_database()
        st.sidebar.info("🧪 **Operational Mode:** Demo Mode (Synthetic)")
        st.sidebar.caption(
            "Using deterministic synthetic demonstration dataset with RFC 5737 documentation IPs. "
            "Real captures and local databases are not accessed."
        )
    else:
        target_db_path = raw_path
        st.sidebar.caption(f"📁 **Active Database:** `{target_db_path}`")

    # Requirement 3: Check database existence BEFORE opening connection.
    # Do not silently create a new database file just by launching the dashboard.
    if not is_demo_mode and not target_db_path.is_file():
        st.warning(f"Database file not found: `{target_db_path}`")
        st.info(
            "**No database exists at the specified path.**\n\n"
            "The Mini-IDS dashboard does not automatically create empty database files. "
            "To generate data, run offline analysis from your terminal:\n\n"
            "```powershell\n"
            "python main.py --pcap data/sample.pcap\n"
            "```\n\n"
            "Or toggle **Demonstration Mode (Synthetic)** in the sidebar to explore simulated telemetry."
        )
        return

    # Live Packet Capture Section
    render_live_capture_section(target_db_path, is_demo_mode=is_demo_mode)

    # Demonstration Mode top notification banner
    if is_demo_mode:
        st.info(
            "🧪 **Demonstration Mode Active** — Displaying sanitized synthetic network telemetry and simulated intrusion "
            "alerts for evaluation and mentor review. All events are synthetic and explicitly labeled. "
            "No real network packets, private host data, or live packet captures are active in this mode."
        )

    # Database Retrieval and UI Rendering with reliable connection cleanup
    try:
        with DatabaseManager(target_db_path) as db:
            packet_count = db.get_packet_count()
            alert_count = db.get_alert_count()

            # Empty database state
            if packet_count == 0 and alert_count == 0:
                st.info(
                    f"Connected to database `{target_db_path}`, but it contains no stored packets or alerts.\n\n"
                    "Run an offline PCAP analysis to populate this database:\n\n"
                    "```powershell\n"
                    f"python main.py --pcap <path_to_pcap> --db \"{target_db_path}\"\n"
                    "```"
                )
                return

            # Retrieve all alerts for metrics and recent table
            all_alerts = db.get_alerts(order="DESC")

            # Sidebar Filters
            st.sidebar.header("Filter Options")

            # Alert filters
            st.sidebar.subheader("Alert Filters")
            st.sidebar.caption("Applies to Alert Analytics and Recent Security Alerts.")
            available_rules = sorted(list({a["rule_name"] for a in all_alerts if a.get("rule_name")}))
            available_severities = sorted(list({a["severity"] for a in all_alerts if a.get("severity")}))

            selected_rule = st.sidebar.selectbox(
                "Detection Rule",
                options=["All"] + available_rules,
                index=0,
            )
            selected_severity = st.sidebar.selectbox(
                "Severity",
                options=["All"] + available_severities,
                index=0,
            )
            alert_limit = st.sidebar.selectbox(
                "Alerts Display Limit",
                options=[25, 50, 100, 250, "All"],
                index=1,
            )

            # Traffic filters
            st.sidebar.subheader("Traffic Filters")
            st.sidebar.caption("Applies to Network Traffic Analytics and Recent Network Traffic.")
            packet_limit = st.sidebar.selectbox(
                "Recent Packets Limit",
                options=[50, 100, 250, 500, 1000],
                index=1,
            )
            selected_protocol = st.sidebar.selectbox(
                "Protocol",
                options=["All", "TCP", "UDP", "ICMP"],
                index=0,
            )

            # Optional Analysis Scope / Time Filter (Step 4)
            st.sidebar.subheader("Analysis Scope")
            bounds = db.get_timestamp_bounds()
            min_ts = bounds.get("min_timestamp")
            max_ts = bounds.get("max_timestamp")

            enable_time_filter = st.sidebar.checkbox(
                "Filter by Time Range",
                value=False,
                help="Isolate records to a specific capture interval without modifying the database.",
            )
            scope_start_ts: Optional[float] = None
            scope_end_ts: Optional[float] = None
            if enable_time_filter and min_ts is not None and max_ts is not None:
                st.sidebar.caption(f"Stored bounds: {format_timestamp(min_ts)} — {format_timestamp(max_ts)}")
                scope_start_ts = st.sidebar.number_input(
                    "Start Timestamp (Epoch s)",
                    value=float(min_ts),
                    step=1.0,
                    format="%.2f",
                )
                scope_end_ts = st.sidebar.number_input(
                    "End Timestamp (Epoch s)",
                    value=float(max_ts),
                    step=1.0,
                    format="%.2f",
                )

            # Apply scope filtering if active
            active_alerts = all_alerts
            if enable_time_filter and scope_start_ts is not None and scope_end_ts is not None:
                active_alerts = [
                    a for a in active_alerts
                    if scope_start_ts <= float(a.get("timestamp", 0.0)) <= scope_end_ts
                ]

            # Retrieve recent packets
            fetch_limit = int(packet_limit) * 2 if selected_protocol != "All" else int(packet_limit)
            if enable_time_filter and scope_start_ts is not None and scope_end_ts is not None:
                raw_packets = db.get_related_packets(
                    start_time=scope_start_ts,
                    end_time=scope_end_ts,
                    protocol=selected_protocol if selected_protocol != "All" else None,
                    limit=fetch_limit,
                    order="DESC",
                )
            else:
                raw_packets = db.get_packets(limit=fetch_limit, order="DESC")

            # Main Panel: Security Overview KPIs (Step 2)
            kpis = db.get_security_kpis(
                start_time=scope_start_ts if enable_time_filter else None,
                end_time=scope_end_ts if enable_time_filter else None,
            )

            if enable_time_filter and scope_start_ts is not None and scope_end_ts is not None:
                st.subheader("Security Overview (Scoped to Selected Interval)")
                st.caption(
                    f"Showing metrics between `{format_timestamp(scope_start_ts)}` and `{format_timestamp(scope_end_ts)}`. "
                    "Uncheck 'Filter by Time Range' in sidebar to view cumulative totals across all stored history."
                )
            else:
                st.subheader("Stored Totals (Cumulative Across All Analyses)")
                st.caption(
                    "Cumulative metrics reflect the complete database state across all ingested PCAP runs and live captures. "
                    "Historical PCAP data (October 2015) and recent captures (October 2026) are preserved. "
                    "Use 'Filter by Time Range' in the sidebar to isolate specific observation periods."
                )

            metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
            metric_col1.metric(
                "Total Stored Packets",
                f"{kpis['total_packets']:,}",
                help="Cumulative network frames decoded and indexed in the active SQLite database across all capture runs.",
            )
            metric_col2.metric(
                "Total Stored Alerts",
                f"{kpis['total_alerts']:,}",
                help="Cumulative intrusion alerts generated by detection heuristics across all runs.",
            )
            metric_col3.metric(
                "High-Severity Alerts",
                f"{kpis['high_severity_alerts']:,}",
                help="Alerts classified as HIGH or CRITICAL severity (e.g. rapid port scans or high-volume floods).",
            )
            metric_col4.metric(
                "Distinct Alert Sources",
                f"{kpis['distinct_alert_sources']:,}",
                help="Count of unique source IP addresses that triggered at least one detection alert in the database.",
            )

            # Grouped rule counts (preserves previous metric cards for compatibility)
            rule_counts = Counter(a["rule_name"] for a in all_alerts if a.get("rule_name"))
            if rule_counts:
                st.markdown("**Alert Counts Grouped by Rule / Type:**")
                rule_columns = st.columns(max(len(rule_counts), 1))
                for col, (rule_name, count) in zip(rule_columns, sorted(rule_counts.items())):
                    col.metric(rule_name, f"{count:,}")

            st.divider()

            # Security Analytics Section (Step 3 & Step 4)
            st.subheader("📊 Security Analytics")
            if enable_time_filter and scope_start_ts is not None and scope_end_ts is not None:
                st.caption(
                    f"Analytics scoped to interval: `{format_timestamp(scope_start_ts)}` to `{format_timestamp(scope_end_ts)}`."
                )
            else:
                st.caption("Visualizations summarize cumulative stored history in the database.")

            tab_alerts, tab_traffic = st.tabs(["🚨 Alert Analytics", "🌐 Network Traffic Analytics"])

            with tab_alerts:
                st.caption(
                    f"Showing alert analytics filtered by Rule: **{selected_rule}** | Severity: **{selected_severity}**."
                )
                # Distribution Row
                dist_col1, dist_col2 = st.columns(2)
                with dist_col1:
                    st.markdown("##### Alert Severity Distribution")
                    sev_data = db.get_alert_severity_distribution(
                        start_time=scope_start_ts if enable_time_filter else None,
                        end_time=scope_end_ts if enable_time_filter else None,
                        rule=selected_rule,
                    )
                    sev_chart = build_severity_chart(sev_data)
                    if sev_chart is not None:
                        st.altair_chart(sev_chart, width="stretch")
                    else:
                        st.info("No alert severity records available for current filter.")

                with dist_col2:
                    st.markdown("##### Alerts by Detection Rule")
                    rule_data = db.get_alerts_by_rule(
                        start_time=scope_start_ts if enable_time_filter else None,
                        end_time=scope_end_ts if enable_time_filter else None,
                        severity=selected_severity,
                    )
                    rule_chart = build_rule_chart(rule_data)
                    if rule_chart is not None:
                        st.altair_chart(rule_chart, width="stretch")
                    else:
                        st.info("No detection rule records available for current filter.")

                # Timeline Row
                st.markdown("##### Alert Timeline (UTC)")
                alert_timeline_data = db.get_alert_timeline(
                    start_time=scope_start_ts if enable_time_filter else None,
                    end_time=scope_end_ts if enable_time_filter else None,
                    rule=selected_rule,
                    severity=selected_severity,
                    bucket_resolution="auto",
                )
                alert_tl_chart = build_timeline_chart(
                    alert_timeline_data,
                    color="#0284c7",
                    fill_color="#38bdf8",
                    y_field="count",
                    y_title="Alerts Generated",
                )
                if alert_tl_chart is not None:
                    st.altair_chart(alert_tl_chart, width="stretch")
                    if len(alert_timeline_data) > 1:
                        st.caption(
                            "ℹ️ Discrete column bars represent time buckets with recorded alerts. "
                            "Gaps between bars indicate periods with zero alerts."
                        )
                else:
                    st.info("No alert timeline records available for current filter.")

                # Top Alert Sources & Targets
                rank_col1, rank_col2 = st.columns(2)
                with rank_col1:
                    st.markdown("##### Top Offending Source IPs")
                    top_sources = db.get_top_alert_sources(
                        limit=5,
                        start_time=scope_start_ts if enable_time_filter else None,
                        end_time=scope_end_ts if enable_time_filter else None,
                        rule=selected_rule,
                        severity=selected_severity,
                    )
                    src_chart = build_ranking_chart(
                        top_sources,
                        category_field="src_ip",
                        value_field="count",
                        category_title="Source IP",
                        value_title="Alert Count",
                        bar_color="#ef4444",
                    )
                    if src_chart is not None:
                        st.altair_chart(src_chart, width="stretch")
                    else:
                        st.info("No source IP records associated with alerts.")

                with rank_col2:
                    st.markdown("##### Top Targeted Destination IPs")
                    top_dests = db.get_top_alert_destinations(
                        limit=5,
                        start_time=scope_start_ts if enable_time_filter else None,
                        end_time=scope_end_ts if enable_time_filter else None,
                        rule=selected_rule,
                        severity=selected_severity,
                    )
                    dst_chart = build_ranking_chart(
                        top_dests,
                        category_field="dst_ip",
                        value_field="count",
                        category_title="Destination IP",
                        value_title="Alert Count",
                        bar_color="#8b5cf6",
                    )
                    if dst_chart is not None:
                        st.altair_chart(dst_chart, width="stretch")
                    else:
                        st.info("No destination IP records associated with alerts.")

            with tab_traffic:
                st.caption(
                    f"Showing raw packet traffic filtered by Protocol: **{selected_protocol}**. "
                    "Alert-specific filters (Rule, Severity) apply strictly to the Alert Analytics tab."
                )
                # Protocol & Ports Row
                proto_col1, proto_col2 = st.columns(2)
                with proto_col1:
                    st.markdown("##### Protocol Distribution")
                    proto_data = db.get_protocol_distribution(
                        start_time=scope_start_ts if enable_time_filter else None,
                        end_time=scope_end_ts if enable_time_filter else None,
                        protocol=selected_protocol if selected_protocol != "All" else None,
                    )
                    proto_chart = build_ranking_chart(
                        proto_data,
                        category_field="protocol",
                        value_field="count",
                        category_title="Protocol",
                        value_title="Packet Count",
                        bar_color="#06b6d4",
                    )
                    if proto_chart is not None:
                        st.altair_chart(proto_chart, width="stretch")
                    else:
                        st.info("No packet protocol records available.")

                with proto_col2:
                    st.markdown("##### Top Destination Ports")
                    port_data = db.get_top_destination_ports(
                        limit=5,
                        start_time=scope_start_ts if enable_time_filter else None,
                        end_time=scope_end_ts if enable_time_filter else None,
                        protocol=selected_protocol if selected_protocol != "All" else None,
                    )
                    port_chart = build_ranking_chart(
                        port_data,
                        category_field="dst_port",
                        value_field="packet_count",
                        category_title="Destination Port",
                        value_title="Packet Count",
                        bar_color="#0284c7",
                    )
                    if port_chart is not None:
                        st.altair_chart(port_chart, width="stretch")
                    else:
                        st.info("No destination port records available.")

                # Traffic Volume Timeline
                st.markdown("##### Network Traffic Volume Over Time (UTC)")
                traffic_timeline_data = db.get_traffic_timeline(
                    start_time=scope_start_ts if enable_time_filter else None,
                    end_time=scope_end_ts if enable_time_filter else None,
                    protocol=selected_protocol if selected_protocol != "All" else None,
                    bucket_resolution="auto",
                )
                traffic_tl_chart = build_timeline_chart(
                    traffic_timeline_data,
                    color="#059669",
                    fill_color="#10b981",
                    y_field="packet_count",
                    y_title="Packet Count",
                )
                if traffic_tl_chart is not None:
                    st.altair_chart(traffic_tl_chart, width="stretch")
                    if len(traffic_timeline_data) > 1:
                        st.caption(
                            "ℹ️ Discrete column bars represent volume per time bucket. "
                            "Gaps between bars indicate periods with zero recorded packets."
                        )
                else:
                    st.info("No traffic volume timeline records available.")

                st.caption(
                    "ℹ️ **Traffic Telemetry Notice:** Volume metrics indicate network throughput. "
                    "High traffic volume or common ports do not in themselves indicate malicious activity."
                )

                # Top Traffic Destinations
                st.markdown("##### Top Traffic Destination Hosts")
                traffic_dest_data = db.get_top_packet_destinations(
                    limit=5,
                    start_time=scope_start_ts if enable_time_filter else None,
                    end_time=scope_end_ts if enable_time_filter else None,
                    protocol=selected_protocol if selected_protocol != "All" else None,
                )
                dest_traffic_chart = build_ranking_chart(
                    traffic_dest_data,
                    category_field="dst_ip",
                    value_field="packet_count",
                    category_title="Destination IP",
                    value_title="Packet Count",
                    bar_color="#3b82f6",
                )
                if dest_traffic_chart is not None:
                    st.altair_chart(dest_traffic_chart, width="stretch")
                else:
                    st.info("No packet destination records available.")

            st.divider()

            # Section 1: Recent Alerts Table
            st.subheader("Recent Security Alerts")
            if enable_time_filter and scope_start_ts is not None and scope_end_ts is not None:
                st.caption(
                    f"Showing alerts within time scope: `{format_timestamp(scope_start_ts)}` "
                    f"to `{format_timestamp(scope_end_ts)}`."
                )

            filtered_alerts = active_alerts
            if selected_rule != "All":
                filtered_alerts = [a for a in filtered_alerts if a.get("rule_name") == selected_rule]
            if selected_severity != "All":
                filtered_alerts = [a for a in filtered_alerts if a.get("severity") == selected_severity]
            if alert_limit != "All":
                filtered_alerts = filtered_alerts[: int(alert_limit)]

            if not filtered_alerts:
                if alert_count == 0:
                    st.info("No security alerts have been generated in this database.")
                else:
                    st.info("No alerts match the selected filter criteria.")
            else:
                alert_rows = []
                for a in filtered_alerts:
                    alert_rows.append({
                        "Alert ID": a.get("id"),
                        "Timestamp": format_timestamp(a.get("timestamp")),
                        "Rule": a.get("rule_name", "UNKNOWN"),
                        "Severity": a.get("severity", "UNKNOWN"),
                        "Source IP": a.get("src_ip") or "N/A",
                        "Destination IP": a.get("dst_ip") or "N/A",
                        "Observed": round(float(a.get("observed_value", 0.0)), 2),
                        "Threshold": round(float(a.get("threshold", 0.0)), 2),
                        "Window (s)": round(float(a.get("window_seconds", 0.0)), 1),
                        "Description / Reason": a.get("message", ""),
                    })
                df_alerts = pd.DataFrame(alert_rows)
                st.dataframe(df_alerts, width="stretch")

            st.divider()

            # Section 2: Alert Investigation Workflow (Step 2 & Step 3)
            st.subheader("🔍 Alert Investigation")
            st.caption(
                "Select a specific security alert from filtered results to review its complete details "
                "and inspect correlated packet evidence from the database."
            )

            if not filtered_alerts:
                st.info("No alerts available to investigate with the current filter criteria.")
            else:
                # Build alert mapping by database ID
                alert_id_to_label = {
                    a["id"]: (
                        f"Alert #{a['id']} | {a.get('rule_name', 'UNKNOWN')} [{a.get('severity', 'UNKNOWN')}] | "
                        f"{a.get('src_ip') or 'N/A'} -> {a.get('dst_ip') or 'N/A'} | "
                        f"{format_timestamp(a.get('timestamp'))}"
                    )
                    for a in filtered_alerts
                }
                alert_id_options = list(alert_id_to_label.keys())

                selected_alert_id = st.selectbox(
                    "Select Alert to Investigate",
                    options=alert_id_options,
                    format_func=lambda aid: alert_id_to_label[aid],
                    help="Choose an alert by ID from the filtered alert list to load its details and packet evidence.",
                )

                # Fetch selected alert directly by database ID (Step 2: Actual database row)
                selected_alert = db.get_alert_by_id(selected_alert_id)
                if selected_alert is None:
                    st.warning(f"Alert ID #{selected_alert_id} could not be retrieved from the database.")
                else:
                    # Render Selected Alert Details Card
                    st.markdown(f"#### Alert Details — ID #{selected_alert['id']}")

                    detail_col1, detail_col2, detail_col3, detail_col4 = st.columns(4)
                    detail_col1.metric("Detection Rule", selected_alert.get("rule_name", "UNKNOWN"))
                    detail_col2.metric("Severity", selected_alert.get("severity", "UNKNOWN"))
                    detail_col3.metric(
                        "Observed / Threshold",
                        f"{selected_alert.get('observed_value', 0):.2f} / {selected_alert.get('threshold', 0):.2f}",
                    )
                    detail_col4.metric(
                        "Evaluation Window",
                        f"{selected_alert.get('window_seconds', 0):.1f} s",
                    )

                    st.markdown(
                        f"- **Detection Timestamp:** {format_timestamp(selected_alert.get('timestamp'))} "
                        f"(`epoch: {selected_alert.get('timestamp')}`)\n"
                        f"- **Source IP:** `{selected_alert.get('src_ip') or 'N/A'}`\n"
                        f"- **Destination IP:** `{selected_alert.get('dst_ip') or 'N/A'}`\n"
                        f"- **Trigger Message:** {selected_alert.get('message', 'No details provided.')}"
                    )

                    # Query and display Related Packet Evidence (Step 3)
                    st.markdown("---")
                    st.markdown("#### Related Packet Evidence")
                    st.caption(
                        "**Detection Window Interval:** Detectors evaluate network activity across a sliding window "
                        "preceding the alert trigger: `[alert_timestamp - window_seconds, alert_timestamp]`. "
                        "The query below retrieves stored packets matching the alert's source/destination IP "
                        "during this evaluation interval."
                    )

                    # Time window calculation
                    alert_ts = float(selected_alert.get("timestamp", 0.0))
                    win_sec = float(selected_alert.get("window_seconds", 0.0))
                    default_start = alert_ts - win_sec
                    default_end = alert_ts

                    evidence_col1, evidence_col2 = st.columns([3, 1])
                    with evidence_col2:
                        window_buffer = st.number_input(
                            "Window Buffer (± s)",
                            min_value=0.0,
                            max_value=60.0,
                            value=0.0,
                            step=1.0,
                            help="Expand evaluation interval before and after detection timestamp.",
                        )
                    with evidence_col1:
                        effective_start = default_start - window_buffer
                        effective_end = default_end + window_buffer
                        st.write(
                            f"**Search Interval:** `{format_timestamp(effective_start)}` to "
                            f"`{format_timestamp(effective_end)}` "
                            f"(Duration: {effective_end - effective_start:.1f}s)"
                        )

                    # Retrieve matching packet evidence via parameterized query
                    alert_src = selected_alert.get("src_ip")
                    alert_dst = selected_alert.get("dst_ip")

                    evidence_packets = db.get_related_packets(
                        src_ip=alert_src,
                        dst_ip=alert_dst,
                        start_time=effective_start,
                        end_time=effective_end,
                        limit=500,
                        order="ASC",
                    )

                    if not evidence_packets:
                        st.warning(
                            f"No matching packet records found for "
                            f"{alert_src or 'any'} -> {alert_dst or 'any'} "
                            f"within the detection interval `[{format_timestamp(effective_start)} — {format_timestamp(effective_end)}]`."
                        )
                    else:
                        st.success(
                            f"Found **{len(evidence_packets)}** related packet record(s) matching "
                            f"IP pair `{alert_src} -> {alert_dst}` in the detection window."
                        )
                        evidence_rows = []
                        for p in evidence_packets:
                            evidence_rows.append({
                                "Timestamp": format_timestamp(p.get("timestamp")),
                                "Epoch": f"{p.get('timestamp', 0.0):.6f}",
                                "Protocol": p.get("protocol", ""),
                                "Source IP": p.get("src_ip", ""),
                                "Destination IP": p.get("dst_ip", ""),
                                "Source Port": str(p["src_port"]) if p.get("src_port") is not None else "-",
                                "Destination Port": str(p["dst_port"]) if p.get("dst_port") is not None else "-",
                                "Length (Bytes)": p.get("length", 0),
                                "TCP Flags": p.get("tcp_flags") if p.get("tcp_flags") is not None else "-",
                            })
                        df_evidence = pd.DataFrame(evidence_rows)
                        st.dataframe(df_evidence, width="stretch")

                        st.caption(
                            "⚠️ **Investigative Notice:** Matching packets are related network telemetry collected "
                            "during the detection window. They serve as investigative evidence and do not by themselves "
                            "definitively prove malicious intent or compromise."
                        )

                    # Correlation limitation note
                    st.caption(
                        "ℹ️ **Correlation Limitation:** The Mini-IDS database schema does not maintain foreign keys "
                        "between individual packet rows and alerts. Evidence is heuristically correlated using source/destination IP "
                        "and the detector's sliding time window. Records outside this window or involving other endpoints are not displayed."
                    )

            st.divider()

            # Section 3: Recent Network Traffic Table
            st.subheader("Recent Network Traffic")
            filtered_packets = raw_packets
            if selected_protocol != "All":
                filtered_packets = [
                    p for p in filtered_packets
                    if p.get("protocol", "").upper() == selected_protocol.upper()
                ]
            filtered_packets = filtered_packets[: int(packet_limit)]

            if not filtered_packets:
                st.info("No packets match the selected traffic filters.")
            else:
                packet_rows = []
                for p in filtered_packets:
                    packet_rows.append({
                        "Timestamp": format_timestamp(p.get("timestamp")),
                        "Source IP": p.get("src_ip", ""),
                        "Destination IP": p.get("dst_ip", ""),
                        "Protocol": p.get("protocol", ""),
                        "Length (Bytes)": p.get("length", 0),
                        "Source Port": str(p["src_port"]) if p.get("src_port") is not None else "-",
                        "Destination Port": str(p["dst_port"]) if p.get("dst_port") is not None else "-",
                        "TCP Flags": p.get("tcp_flags") if p.get("tcp_flags") is not None else "-",
                    })
                df_packets = pd.DataFrame(packet_rows)
                st.dataframe(df_packets, width="stretch")

    except sqlite3.Error as sql_err:
        st.error(f"Database error while reading `{target_db_path}`: {sql_err}")
        return
    except Exception as err:
        st.error(f"Failed to access database `{target_db_path}`: {err}")
        return


if __name__ == "__main__":
    render_dashboard()
