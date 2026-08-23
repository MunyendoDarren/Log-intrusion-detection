"""
Unit tests for detector.py.
Run with: python -m unittest discover tests -v
"""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import (  # noqa: E402
    parse_timestamp,
    LOG_LINE_RE,
    FAILED_RE,
    ACCEPTED_RE,
    INVALID_USER_RE,
    detect_brute_force,
    detect_post_attack_compromise,
)


class TestLineParsing(unittest.TestCase):
    def test_failed_password_line_matches(self):
        line = "Aug 23 09:12:03 web-prod-01 sshd[3340]: Failed password for invalid user admin from 185.220.101.47 port 55035 ssh2"
        outer = LOG_LINE_RE.match(line)
        self.assertIsNotNone(outer)
        inner = FAILED_RE.match(outer.group("message"))
        self.assertIsNotNone(inner)
        self.assertEqual(inner.group("user"), "admin")
        self.assertEqual(inner.group("ip"), "185.220.101.47")

    def test_accepted_password_line_matches(self):
        line = "Aug 23 09:13:27 web-prod-01 sshd[1234]: Accepted password for admin from 185.220.101.47 port 55040 ssh2"
        outer = LOG_LINE_RE.match(line)
        inner = ACCEPTED_RE.match(outer.group("message"))
        self.assertIsNotNone(inner)
        self.assertEqual(inner.group("user"), "admin")

    def test_invalid_user_line_matches(self):
        line = "Aug 23 09:12:03 web-prod-01 sshd[3340]: Invalid user admin from 185.220.101.47"
        outer = LOG_LINE_RE.match(line)
        inner = INVALID_USER_RE.match(outer.group("message"))
        self.assertIsNotNone(inner)
        self.assertEqual(inner.group("user"), "admin")

    def test_unrelated_line_does_not_match(self):
        line = "Aug 23 09:12:03 web-prod-01 sshd[3340]: Server listening on 0.0.0.0 port 22."
        outer = LOG_LINE_RE.match(line)
        self.assertIsNotNone(outer)  # outer format still matches
        self.assertIsNone(FAILED_RE.match(outer.group("message")))
        self.assertIsNone(ACCEPTED_RE.match(outer.group("message")))
        self.assertIsNone(INVALID_USER_RE.match(outer.group("message")))

    def test_parse_timestamp(self):
        dt = parse_timestamp("Aug", "23", "09:12:03", 2026)
        self.assertEqual(dt, datetime(2026, 8, 23, 9, 12, 3))


class TestBruteForceDetection(unittest.TestCase):
    def _make_event(self, ts, user, ip):
        return {"type": "failed_login", "timestamp": ts, "user": user, "ip": ip, "line_num": 0, "raw": ""}

    def test_detects_burst_over_threshold(self):
        base = datetime(2026, 8, 23, 9, 0, 0)
        events = [
            self._make_event(base.replace(second=i * 5), f"user{i}", "10.0.0.1")
            for i in range(6)
        ]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertIn("10.0.0.1", alerts)
        self.assertGreaterEqual(alerts["10.0.0.1"]["attempt_count"], 5)

    def test_no_alert_below_threshold(self):
        base = datetime(2026, 8, 23, 9, 0, 0)
        events = [
            self._make_event(base.replace(second=i * 5), f"user{i}", "10.0.0.1")
            for i in range(3)
        ]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertNotIn("10.0.0.1", alerts)

    def test_spread_out_attempts_not_flagged(self):
        # Same total count, but spread far outside the window -> should not alert
        base = datetime(2026, 8, 23, 9, 0, 0)
        events = [
            self._make_event(base.replace(hour=(9 + i) % 24), f"user{i}", "10.0.0.2")
            for i in range(6)
        ]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertNotIn("10.0.0.2", alerts)

    def test_separate_ips_tracked_independently(self):
        base = datetime(2026, 8, 23, 9, 0, 0)
        events = [
            self._make_event(base.replace(second=i * 2), "root", "10.0.0.1")
            for i in range(5)
        ] + [
            self._make_event(base.replace(second=i * 2), "root", "10.0.0.9")
            for i in range(2)
        ]
        alerts = detect_brute_force(events, threshold=5, window_seconds=60)
        self.assertIn("10.0.0.1", alerts)
        self.assertNotIn("10.0.0.9", alerts)


class TestCompromiseDetection(unittest.TestCase):
    def test_flags_login_shortly_after_burst(self):
        burst_end = datetime(2026, 8, 23, 9, 13, 7)
        brute_force_alerts = {
            "185.220.101.47": {"start": burst_end, "end": burst_end, "attempt_count": 30, "usernames_tried": ["admin"]}
        }
        events = [{
            "type": "accepted_login",
            "timestamp": datetime(2026, 8, 23, 9, 13, 27),
            "user": "admin",
            "ip": "185.220.101.47",
            "line_num": 0,
            "raw": "",
        }]
        compromises = detect_post_attack_compromise(events, brute_force_alerts, grace_period_seconds=300)
        self.assertEqual(len(compromises), 1)
        self.assertEqual(compromises[0]["user"], "admin")

    def test_does_not_flag_unrelated_ip(self):
        burst_end = datetime(2026, 8, 23, 9, 13, 7)
        brute_force_alerts = {
            "185.220.101.47": {"start": burst_end, "end": burst_end, "attempt_count": 30, "usernames_tried": ["admin"]}
        }
        events = [{
            "type": "accepted_login",
            "timestamp": datetime(2026, 8, 23, 9, 13, 27),
            "user": "papi",
            "ip": "41.90.12.34",  # different, non-flagged IP
            "line_num": 0,
            "raw": "",
        }]
        compromises = detect_post_attack_compromise(events, brute_force_alerts, grace_period_seconds=300)
        self.assertEqual(len(compromises), 0)

    def test_does_not_flag_login_outside_grace_period(self):
        burst_end = datetime(2026, 8, 23, 9, 13, 7)
        brute_force_alerts = {
            "185.220.101.47": {"start": burst_end, "end": burst_end, "attempt_count": 30, "usernames_tried": ["admin"]}
        }
        events = [{
            "type": "accepted_login",
            "timestamp": datetime(2026, 8, 23, 10, 30, 0),  # over an hour later
            "user": "admin",
            "ip": "185.220.101.47",
            "line_num": 0,
            "raw": "",
        }]
        compromises = detect_post_attack_compromise(events, brute_force_alerts, grace_period_seconds=300)
        self.assertEqual(len(compromises), 0)


if __name__ == "__main__":
    unittest.main()
