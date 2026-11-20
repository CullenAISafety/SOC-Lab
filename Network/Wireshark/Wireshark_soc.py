
#!/usr/bin/env python3
"""
Wireshark SOC-Lab Integration
Version: 1.0.0

Capabilities:
- List available network interfaces.
- Capture live network traffic using TShark.
- Save live captures as PCAPNG using dumpcap.
- Analyze existing PCAP/PCAPNG files.
- Export packet events to CSV.
- Generate candidate security alerts in JSONL.
- Detect potential TCP SYN scanning behavior.

Requirements:
- Python 3.10+
- Wireshark / TShark
- Npcap for Windows live capture

Uses Python standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time

from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------
# PATH CONFIGURATION
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = BASE_DIR / "captures"
OUTPUT_DIR = BASE_DIR / "output"

SOC_ROOT = BASE_DIR.parent.parent
ALERT_DIR = SOC_ROOT / "Alerts"

ALERT_FILE = ALERT_DIR / "wireshark_alerts.jsonl"

CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
ALERT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

SYN_THRESHOLD = 25
SYN_WINDOW_SECONDS = 10

TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "dns.qry.name",
    "_ws.col.Protocol",
    "_ws.col.Info",
]

FIELD_NAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "tcp_source_port",
    "tcp_destination_port",
    "udp_source_port",
    "udp_destination_port",
    "tcp_syn",
    "tcp_ack",
    "dns_query",
    "protocol",
    "info",
]


# ---------------------------------------------------------
# LOGGING
# ---------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("Wireshark-SOC")


# ---------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------

def find_executable(name: str) -> str:
    """Locate a Wireshark executable."""

    executable = shutil.which(name)

    if executable:
        return executable

    common_paths = [
        Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        / "Wireshark"
        / f"{name}.exe",

        Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
        / "Wireshark"
        / f"{name}.exe",
    ]

    for path in common_paths:
        if path.exists():
            return str(path)

    raise FileNotFoundError(
        f"{name} was not found. Install Wireshark and ensure "
        "its installation directory is available."
    )


def timestamp_string() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def parse_timestamp(value: str) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return time.time()


def verify_tools() -> tuple[str, str]:
    """Find TShark and dumpcap."""

    tshark = find_executable("tshark")
    dumpcap = find_executable("dumpcap")

    return tshark, dumpcap


# ---------------------------------------------------------
# ALERT ENGINE
# ---------------------------------------------------------

class DetectionEngine:
    """
    Lightweight network behavior detector.

    Detects a high volume of TCP SYN packets from one
    source IP within a configurable time window.

    This is a heuristic, not a definitive attack verdict.
    """

    def __init__(
        self,
        threshold: int = SYN_THRESHOLD,
        window: int = SYN_WINDOW_SECONDS,
    ):
        self.threshold = threshold
        self.window = window

        self.syn_activity = defaultdict(deque)
        self.alerted_sources = set()

    def process(self, event: dict) -> list[dict]:

        alerts = []

        source_ip = event.get("source_ip", "")
        syn = event.get("tcp_syn", "")
        ack = event.get("tcp_ack", "")
        timestamp = parse_timestamp(event.get("timestamp", ""))

        # Look for TCP SYN without ACK.
        if source_ip and syn == "1" and ack == "0":

            activity = self.syn_activity[source_ip]

            activity.append(timestamp)

            # Remove events outside detection window.
            while activity and timestamp - activity[0] > self.window:
                activity.popleft()

            if (
                len(activity) >= self.threshold
                and source_ip not in self.alerted_sources
            ):

                alert = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "MEDIUM",
                    "type": "POSSIBLE_TCP_SYN_SCAN",
                    "source_ip": source_ip,
                    "event_count": len(activity),
                    "window_seconds": self.window,
                    "description": (
                        "High volume of TCP SYN packets detected "
                        "from one source within the configured "
                        "time window."
                    ),
                    "recommended_action": (
                        "Review destination ports, connection "
                        "patterns, and source authorization."
                    ),
                    "status": "REQUIRES_ANALYST_REVIEW",
                }

                alerts.append(alert)
                self.alerted_sources.add(source_ip)

        # DNS queries are recorded as events, not automatically
        # considered malicious.
        return alerts


# ---------------------------------------------------------
# OUTPUT HANDLING
# ---------------------------------------------------------

class OutputManager:

    def __init__(self, filename: str):

        self.csv_path = OUTPUT_DIR / f"{filename}.csv"

        self.csv_file = open(
            self.csv_path,
            "w",
            newline="",
            encoding="utf-8",
        )

        self.writer = csv.DictWriter(
            self.csv_file,
            fieldnames=FIELD_NAMES,
        )

        self.writer.writeheader()

    def write_event(self, event: dict):

        self.writer.writerow(event)
        self.csv_file.flush()

    def write_alert(self, alert: dict):

        with ALERT_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(alert) + "\n")

        logger.warning(
            "SECURITY ALERT: %s | Source: %s",
            alert["type"],
            alert["source_ip"],
        )

    def close(self):

        self.csv_file.close()


# ---------------------------------------------------------
# TSHARK EVENT PROCESSING
# ---------------------------------------------------------

def build_tshark_command(
    tshark: str,
    interface: str | None = None,
    pcap: Path | None = None,
) -> list[str]:

    command = [tshark, "-n", "-l"]

    if pcap:
        command.extend(["-r", str(pcap)])

    elif interface:
        command.extend(["-i", interface, "-f", "ip or ip6"])

    else:
        raise ValueError("An interface or PCAP file is required.")

    command.extend([
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ])

    for field in TSHARK_FIELDS:
        command.extend(["-e", field])

    return command


def parse_tshark_line(line: str) -> dict:

    values = line.rstrip("\r\n").split("\t")

    # TShark emits one value for every requested field.
    values = (values + [""] * len(FIELD_NAMES))[:len(FIELD_NAMES)]

    event = dict(zip(FIELD_NAMES, values))

    return event


def process_stream(
    process: subprocess.Popen,
    output: OutputManager,
    detector: DetectionEngine,
):

    try:

        if process.stdout is None:
            raise RuntimeError("TShark output stream unavailable.")

        for line in process.stdout:

            if not line.strip():
                continue

            event = parse_tshark_line(line)

            output.write_event(event)

            for alert in detector.process(event):
                output.write_alert(alert)

    except KeyboardInterrupt:
        logger.info("Stopping packet analysis.")

    finally:

        if process.poll() is None:
            process.terminate()

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


# ---------------------------------------------------------
# INTERFACE DISCOVERY
# ---------------------------------------------------------

def list_interfaces():

    tshark, _ = verify_tools()

    result = subprocess.run(
        [tshark, "-D"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Interface discovery failed.")

    print("\nAvailable network interfaces:\n")
    print(result.stdout)


# ---------------------------------------------------------
# OFFLINE PCAP ANALYSIS
# ---------------------------------------------------------

def analyze_pcap(pcap: Path):

    if not pcap.is_file():
        raise FileNotFoundError(f"Capture file not found: {pcap}")

    if pcap.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Expected a PCAP, PCAPNG, or CAP file.")

    tshark, _ = verify_tools()

    filename = f"offline_analysis_{timestamp_string()}"

    output = OutputManager(filename)
    detector = DetectionEngine()

    command = build_tshark_command(
        tshark=tshark,
        pcap=pcap.resolve(),
    )

    logger.info("Analyzing capture: %s", pcap)
    logger.info("CSV output: %s", output.csv_path)

    try:

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        process_stream(process, output, detector)

        if process.returncode not in (0, None):
            raise RuntimeError("TShark reported an analysis error.")

    finally:
        output.close()

    logger.info("Offline analysis completed.")


# ---------------------------------------------------------
# LIVE NETWORK MONITORING
# ---------------------------------------------------------

def live_monitor(interface: str):

    tshark, dumpcap = verify_tools()

    filename = f"live_capture_{timestamp_string()}"

    pcap_path = CAPTURE_DIR / f"{filename}.pcapng"

    output = OutputManager(filename)
    detector = DetectionEngine()

    capture_process = None
    analysis_process = None

    try:

        logger.info("Starting live packet capture.")
        logger.info("Interface: %s", interface)

        # Save original packet capture to PCAPNG.
        capture_process = subprocess.Popen(
            [
                dumpcap,
                "-i", interface,
                "-w", str(pcap_path),
                "-q",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        time.sleep(1)

        if capture_process.poll() is not None:
            error = capture_process.stderr.read() if capture_process.stderr else ""
            raise RuntimeError(
                f"dumpcap failed to start: {error}"
            )

        # Independently stream packets through TShark.
        command = build_tshark_command(
            tshark=tshark,
            interface=interface,
        )

        analysis_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        logger.info("Live monitoring active. Press Ctrl+C to stop.")
        logger.info("PCAPNG: %s", pcap_path)

        process_stream(analysis_process, output, detector)

    except KeyboardInterrupt:
        logger.info("Stopping live monitoring.")

    finally:

        if analysis_process and analysis_process.poll() is None:
            analysis_process.terminate()

        if capture_process and capture_process.poll() is None:
            capture_process.terminate()

            try:
                capture_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                capture_process.kill()
                capture_process.wait()

        output.close()

    logger.info("Live monitoring stopped.")
    logger.info("Capture saved: %s", pcap_path)


# ---------------------------------------------------------
# COMMAND LINE INTERFACE
# ---------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Wireshark SOC-Lab Network Monitoring Engine"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "interfaces",
        help="List available network interfaces.",
    )

    live_parser = subparsers.add_parser(
        "live",
        help="Start live network monitoring.",
    )

    live_parser.add_argument(
        "--interface",
        required=True,
        help="Interface number or name from tshark -D.",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an offline PCAP/PCAPNG capture.",
    )

    analyze_parser.add_argument(
        "--pcap",
        required=True,
        type=Path,
        help="Path to the PCAP or PCAPNG file.",
    )

    args = parser.parse_args()

    try:

        if args.command == "interfaces":
            list_interfaces()

        elif args.command == "live":
            live_monitor(args.interface)

        elif args.command == "analyze":
            analyze_pcap(args.pcap)

    except (FileNotFoundError, RuntimeError, ValueError) as error:

        logger.error("%s", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
