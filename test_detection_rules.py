import unittest
from datetime import datetime, timedelta
from detection_rules import detect_threats


class TestDetectionRules(unittest.TestCase):

    def create_events(
        self, failures=5, interval_seconds=30,
        success=False, ip="203.0.113.10"
    ):
        start = datetime(2026, 10, 10, 10, 0, 0)
        events = []

        for i in range(failures):
            events.append({
                "timestamp": start + timedelta(
                    seconds=i * interval_seconds
                ),
                "ip_address": ip,
                "username": "admin",
                "event": "FAILED_LOGIN"
            })

        if success:
            events.append({
                "timestamp": start + timedelta(
                    seconds=failures * interval_seconds
                ),
                "ip_address": ip,
                "username": "admin",
                "event": "SUCCESS_LOGIN"
            })

        return events

    def test_brute_force_detection(self):
        events = self.create_events()
        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_below_threshold(self):
        events = self.create_events(failures=4)
        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 0)

    def test_outside_time_window(self):
        events = self.create_events(interval_seconds=150)
        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 0)

    def test_successful_login_after_failures(self):
        events = self.create_events(success=True)
        alerts = detect_threats(events)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            [alert["severity"] for alert in alerts],
            ["HIGH", "CRITICAL"]
        )

    def test_normal_successful_login(self):
        events = [{
            "timestamp": datetime(2026, 10, 10, 10, 0, 0),
            "ip_address": "203.0.113.20",
            "username": "john",
            "event": "SUCCESS_LOGIN"
        }]

        self.assertEqual(detect_threats(events), [])

    def test_separate_ip_addresses(self):
        events = (
            self.create_events(failures=3, ip="203.0.113.10")
            + self.create_events(failures=3, ip="203.0.113.20")
        )

        self.assertEqual(detect_threats(events), [])


if __name__ == "__main__":
    unittest.main()
