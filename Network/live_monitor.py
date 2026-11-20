
import argparse
import csv
import json
import subprocess
import shutil
import time

from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALERT_FILE = ROOT / "Alerts" / "wireshark_alerts.jsonl"

FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.dstport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "dns.qry.name",
    "_ws.col.Protocol",
]


def emit_alert(severity, source, destination, description):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "destination": destination,
        "severity": severity,
        "source_tool": "Wireshark/TShark",
        "description": description,
    }

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")

    print("[ALERT]", json.dumps(alert))


def monitor(interface, threshold, window):
    tshark = shutil.which("tshark")

    if not tshark:
        raise RuntimeError("TShark is not installed or not in PATH.")

    command = [
        tshark,
        "-l",
        "-n",
        "-i", str(interface),
        "-f", "ip or ip6",
        "-T", "fields",
        "-E", "separator=/t",
        "-E", "quote=d",
        "-E", "occurrence=f",
    ]

    for field in FIELDS:
        command.extend(["-e", field])

    syn_events = defaultdict(deque)

    print("Starting live SOC network monitoring...")
    print("Interface:", interface)
    print("Press Ctrl+C to stop.")

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        bufsize=1
    )

    try:
        reader = csv.reader(
            process.stdout,
            delimiter="\t",
            quotechar='"'
        )

        for row in reader:
            if len(row) < len(FIELDS):
                continue

            (
                packet_time, source, destination,
                tcp_port, udp_port, syn, ack,
                dns_query, protocol
            ) = row[:len(FIELDS)]

            if not source or not destination:
                continue

            now = time.time()

            print(
                f"[TRAFFIC] {source} -> {destination} "
                f"| {protocol} | TCP:{tcp_port} UDP:{udp_port}"
            )

            # Count new TCP connection attempts.
            if syn == "1" and ack != "1":
                events = syn_events[source]
                events.append(now)

                while events and now - events[0] > window:
                    events.popleft()

                if len(events) == threshold:
                    emit_alert(
                        "medium",
                        source,
                        destination,
                        f"Possible TCP SYN scan: "
                        f"{len(events)} connection attempts "
                        f"within {window} seconds."
                    )

            # Record DNS activity for investigation.
            if dns_query:
                print(f"[DNS] {source} queried {dns_query}")

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--interface", required=True)
    parser.add_argument("--threshold", type=int, default=30)
    parser.add_argument("--window", type=int, default=10)

    args = parser.parse_args()

    if args.threshold < 1 or args.window < 1:
        parser.error("Threshold and window must be positive.")

    monitor(args.interface, args.threshold, args.window)
