
import csv
from datetime import datetime
from pathlib import Path
from detection_rules import detect_threats

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs.csv"
REPORT_FILE = BASE_DIR / "security_alerts.csv"

FIELDNAMES = [
    "ip_address",
    "username",
    "severity",
    "detection",
    "failed_attempts",
    "timestamp"
]


def analyze_logs():
    events = []

    print("=" * 50)
    print("       PYTHON SECURITY LOG ANALYZER")
    print("=" * 50)

    try:
        with LOG_FILE.open("r", newline="", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)

            for row in reader:
                events.append({
                    "timestamp": datetime.strptime(
                        row["timestamp"], "%Y-%m-%d %H:%M:%S"
                    ),
                    "ip_address": row["ip_address"].strip(),
                    "username": row["username"].strip(),
                    "event": row["event"].strip()
                })

    except FileNotFoundError:
        print("ERROR: sample_logs.csv was not found.")
        return
    except (ValueError, KeyError, AttributeError) as error:
        print(f"ERROR: Invalid log data: {error}")
        return

    alerts = detect_threats(events)

    if alerts:
        for alert in alerts:
            print(f"\n[{alert['severity']} SEVERITY ALERT]")
            print(f"IP Address: {alert['ip_address']}")
            print(f"Username: {alert['username']}")
            print(f"Detection: {alert['detection']}")
            print(f"Failed Attempts: {alert['failed_attempts']}")
            print(f"Timestamp: {alert['timestamp']}")
    else:
        print("\nNo suspicious activity detected.")

    with REPORT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nAnalysis complete. {len(alerts)} alert(s) generated.")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_logs()
