
from collections import defaultdict, deque
from datetime import datetime, timedelta

THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)


def detect_threats(events):
    """Detect suspicious authentication activity."""
    alerts = []
    failed_by_ip = defaultdict(deque)
    failed_by_account = defaultdict(deque)
    brute_force_alerted = set()

    events = sorted(events, key=lambda event: event["timestamp"])

    for event in events:
        timestamp = event["timestamp"]
        ip = event["ip_address"]
        username = event["username"]
        event_type = event["event"]

        account_key = (ip, username)

        ip_window = failed_by_ip[ip]
        account_window = failed_by_account[account_key]

        while ip_window and timestamp - ip_window[0] > TIME_WINDOW:
            ip_window.popleft()

        while account_window and timestamp - account_window[0] > TIME_WINDOW:
            account_window.popleft()

        if event_type == "FAILED_LOGIN":
            ip_window.append(timestamp)
            account_window.append(timestamp)

            if len(ip_window) >= THRESHOLD and ip not in brute_force_alerted:
                alerts.append({
                    "ip_address": ip,
                    "username": username,
                    "severity": "HIGH",
                    "detection": "Possible Brute Force",
                    "failed_attempts": len(ip_window),
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
                })
                brute_force_alerted.add(ip)

        elif event_type == "SUCCESS_LOGIN":
            if len(account_window) >= THRESHOLD:
                alerts.append({
                    "ip_address": ip,
                    "username": username,
                    "severity": "CRITICAL",
                    "detection": "Successful Login After Multiple Failures",
                    "failed_attempts": len(account_window),
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")
                })

            account_window.clear()

    return alerts
