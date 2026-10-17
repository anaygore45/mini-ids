"""Mini-IDS Core CLI Entrypoint.

Command-line interface to coordinate offline PCAP analysis:
1. Ingest packets via the capture module (`iter_pcap`).
2. Feed each normalized packet to detection rules exactly once.
3. Persist normalized packets and generated alerts into SQLite (`DatabaseManager`).
4. Output analysis statistics and alert summaries to console.
"""

import argparse
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Union

# Suppress runtime warnings from Scapy if libpcap is absent
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from capture.packet_capture import iter_pcap
from detection import (
    Alert,
    PortScanDetector,
    SynRateDetector,
    TrafficAnomalyDetector,
)
from storage.database import DEFAULT_DB_PATH, DatabaseManager

logger = logging.getLogger("mini_ids")


def process_pcap_stream(
    pcap_path: Union[str, Path],
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    detectors: Optional[List[Any]] = None,
    batch_size: int = 500,
    print_alerts: bool = True,
) -> Dict[str, Any]:
    """Process an offline PCAP/PCAPNG file through detectors and persist results.

    Each normalized packet is passed to every configured detector exactly once.
    Packets and triggered alerts are stored in the SQLite database.

    Args:
        pcap_path: Path to the .pcap or .pcapng file.
        db_path: Path to the target SQLite database file.
        detectors: Optional list of detector instances. If None, default
                   PortScanDetector, SynRateDetector, and TrafficAnomalyDetector
                   are instantiated with fresh state.
        batch_size: Number of packets to accumulate before committing to database.
        print_alerts: If True, prints alert notifications to stdout as they occur.

    Returns:
        Dict[str, Any]: Summary dictionary containing:
            - 'packets_processed': Total normalized packets ingested and persisted.
            - 'alerts_generated': Total alerts emitted and persisted.
            - 'rule_counts': Dictionary mapping rule names to trigger counts.
            - 'db_path': Path to the SQLite database.

    Raises:
        FileNotFoundError: If pcap_path does not exist or is not a file.
        ValueError: If batch_size <= 0.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if batch_size <= 0:
        raise ValueError(f"batch_size must be positive, got {batch_size}")

    # 1. Initialize database and ensure tables exist
    target_db_path = Path(db_path)
    db = DatabaseManager(target_db_path)
    db.init_db()

    # 2. Instantiate fresh detector instances if not provided
    if detectors is None:
        active_detectors = [
            PortScanDetector(),
            SynRateDetector(),
            TrafficAnomalyDetector(),
        ]
    else:
        active_detectors = detectors

    packets_processed = 0
    alerts_generated = 0
    rule_counts: Dict[str, int] = {}
    packet_batch = []

    try:
        # 3. Stream packets iteratively (memory-safe for large captures)
        for packet in iter_pcap(path):
            packets_processed += 1
            packet_batch.append(packet)

            # Flush packet batch periodically
            if len(packet_batch) >= batch_size:
                db.insert_packets(packet_batch)
                packet_batch.clear()

            # 4. Pass each packet to each detector exactly once
            for detector in active_detectors:
                alert = detector.process_packet(packet)
                if alert is not None:
                    db.insert_alert(alert)
                    alerts_generated += 1
                    rule_counts[alert.rule_name] = rule_counts.get(alert.rule_name, 0) + 1

                    if print_alerts:
                        print(
                            f"  -> [{alert.severity}] {alert.rule_name} | "
                            f"{alert.src_ip} -> {alert.dst_ip} | {alert.message}"
                        )

        # 5. Flush any remaining packets in the buffer
        if packet_batch:
            db.insert_packets(packet_batch)
            packet_batch.clear()

    finally:
        # Guarantee database connection is cleanly closed
        db.close()

    return {
        "packets_processed": packets_processed,
        "alerts_generated": alerts_generated,
        "rule_counts": rule_counts,
        "db_path": target_db_path,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build and return command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="mini-ids",
        description="Mini-IDS: Offline PCAP Network Intrusion Detection Pipeline",
    )
    parser.add_argument(
        "-p",
        "--pcap",
        required=True,
        type=str,
        help="Path to the offline PCAP or PCAPNG capture file to analyze.",
    )
    parser.add_argument(
        "-d",
        "--db",
        default=str(DEFAULT_DB_PATH),
        type=str,
        help=f"Path to SQLite database for persisting packets and alerts (default: {DEFAULT_DB_PATH}).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    pcap_file = Path(args.pcap)
    db_file = Path(args.db)

    print("=" * 60)
    print("Mini-IDS: Offline Network Intrusion Detection System")
    print("=" * 60)
    print(f"Target PCAP: {pcap_file}")
    print(f"Database:    {db_file}")
    print("-" * 60)
    print("Ingesting packets and evaluating detection rules...")

    try:
        summary = process_pcap_stream(
            pcap_path=pcap_file,
            db_path=db_file,
            print_alerts=True,
        )
    except FileNotFoundError as fnf_err:
        print(f"\n[ERROR] {fnf_err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"\n[ERROR] Failed to process PCAP: {err}", file=sys.stderr)
        return 1

    print("-" * 60)
    print("Analysis Complete!")
    print(f"  * Packets analyzed: {summary['packets_processed']}")
    print(f"  * Alerts triggered: {summary['alerts_generated']}")
    if summary["rule_counts"]:
        print("  * Alerts by Rule:")
        for rule, count in summary["rule_counts"].items():
            print(f"      - {rule}: {count}")
    print(f"  * Database saved:   {summary['db_path']}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
