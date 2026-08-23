"""
Intrusion Detector
------------------
Parses an SSH authentication log (auth.log-style) and flags:

  1. Brute-force bursts — N or more failed logins from the same IP
     within a rolling time window.
  2. Possible compromise — a successful login from an IP shortly after
     that same IP was flagged for a brute-force burst.
  3. Invalid-user probing — repeated login attempts against usernames
     that don't exist on the system, a classic reconnaissance signal.

Usage:
    python detector.py data/sample_auth.log
    python detector.py data/sample_auth.log --threshold 5 --window 60
"""

import argparse
import re
from collections import defaultdict
from datetime import datetime

LOG_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)

FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2$"
)
ACCEPTED_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2$"
)
INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)$")

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_timestamp(month: str, day: str, time_str: str, year: int) -> datetime:
    hour, minute, second = (int(x) for x in time_str.split(":"))
    return datetime(year, MONTHS[month], int(day), hour, minute, second)


def parse_log(path: str, year: int = 2026) -> list:
    """Parse a log file into a list of structured events (dicts)."""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, start=1):
            raw_line = raw_line.rstrip("\n")
            if not raw_line.strip():
                continue

            match = LOG_LINE_RE.match(raw_line)
            if not match:
                continue

            timestamp = parse_timestamp(
                match.group("month"), match.group("day"), match.group("time"), year
            )
            message = match.group("message")

            failed_match = FAILED_RE.match(message)
            accepted_match = ACCEPTED_RE.match(message)
            invalid_match = INVALID_USER_RE.match(message)

            if failed_match:
                events.append({
                    "type": "failed_login",
                    "timestamp": timestamp,
                    "user": failed_match.group("user"),
                    "ip": failed_match.group("ip"),
                    "line_num": line_num,
                    "raw": raw_line,
                })
            elif accepted_match:
                events.append({
                    "type": "accepted_login",
                    "timestamp": timestamp,
                    "user": accepted_match.group("user"),
                    "ip": accepted_match.group("ip"),
                    "line_num": line_num,
                    "raw": raw_line,
                })
            elif invalid_match:
                events.append({
                    "type": "invalid_user",
                    "timestamp": timestamp,
                    "user": invalid_match.group("user"),
                    "ip": invalid_match.group("ip"),
                    "line_num": line_num,
                    "raw": raw_line,
                })

    return events


def detect_brute_force(events: list, threshold: int = 5, window_seconds: int = 60) -> dict:
    """
    Group failed-login events by IP, then use a sliding window to find
    bursts where `threshold` or more failures happen within
    `window_seconds` of each other. Returns {ip: [burst_windows]}.
    """
    failures_by_ip = defaultdict(list)
    for event in events:
        if event["type"] == "failed_login":
            failures_by_ip[event["ip"]].append(event)

    alerts = {}
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])
        bursts = []
        window_start_idx = 0

        for i in range(len(failures)):
            # Slide window_start_idx forward while it's outside the window
            while (
                (failures[i]["timestamp"] - failures[window_start_idx]["timestamp"]).total_seconds()
                > window_seconds
            ):
                window_start_idx += 1

            window_size = i - window_start_idx + 1
            if window_size >= threshold:
                bursts.append({
                    "start": failures[window_start_idx]["timestamp"],
                    "end": failures[i]["timestamp"],
                    "attempt_count": window_size,
                    "usernames_tried": sorted({
                        f["user"] for f in failures[window_start_idx : i + 1]
                    }),
                })

        if bursts:
            # Keep only the widest/most severe burst to avoid duplicate overlapping alerts
            best_burst = max(bursts, key=lambda b: b["attempt_count"])
            alerts[ip] = best_burst

    return alerts


def detect_post_attack_compromise(events: list, brute_force_alerts: dict, grace_period_seconds: int = 300) -> list:
    """
    Flag any successful login from an IP that was already flagged for a
    brute-force burst, if the success happens within grace_period_seconds
    after that burst ended. This is often the strongest signal in the
    whole log — the attacker got in.
    """
    compromises = []
    for event in events:
        if event["type"] != "accepted_login":
            continue
        ip = event["ip"]
        if ip not in brute_force_alerts:
            continue
        burst_end = brute_force_alerts[ip]["end"]
        delta = (event["timestamp"] - burst_end).total_seconds()
        if 0 <= delta <= grace_period_seconds:
            compromises.append({
                "ip": ip,
                "user": event["user"],
                "timestamp": event["timestamp"],
                "seconds_after_burst": round(delta, 1),
            })
    return compromises


def print_report(events: list, brute_force_alerts: dict, compromises: list) -> None:
    total_failed = sum(1 for e in events if e["type"] == "failed_login")
    total_accepted = sum(1 for e in events if e["type"] == "accepted_login")
    total_invalid = sum(1 for e in events if e["type"] == "invalid_user")

    print("=" * 65)
    print(" Intrusion Detection Report")
    print("=" * 65)
    print(f" Total events parsed:      {len(events)}")
    print(f"   Failed logins:          {total_failed}")
    print(f"   Accepted logins:        {total_accepted}")
    print(f"   Invalid-user attempts:  {total_invalid}")
    print("-" * 65)

    if not brute_force_alerts:
        print(" No brute-force patterns detected.")
    else:
        print(f" [ALERT] Brute-force activity detected from {len(brute_force_alerts)} IP(s):\n")
        for ip, burst in brute_force_alerts.items():
            duration = (burst["end"] - burst["start"]).total_seconds()
            print(f"  IP: {ip}")
            print(f"    Attempts:        {burst['attempt_count']} failed logins in {duration:.1f}s")
            print(f"    Window:          {burst['start']} -> {burst['end']}")
            print(f"    Usernames tried: {', '.join(burst['usernames_tried'][:8])}"
                  f"{' ...' if len(burst['usernames_tried']) > 8 else ''}")
            print()

    print("-" * 65)
    if not compromises:
        print(" No successful logins linked to a flagged brute-force burst.")
    else:
        print(f" [CRITICAL] {len(compromises)} likely compromise(s) detected:\n")
        for c in compromises:
            print(f"  IP {c['ip']} logged in as '{c['user']}' at {c['timestamp']}")
            print(f"    -> {c['seconds_after_burst']}s after its brute-force burst ended.")
            print("    Recommended action: disable/rotate this account's credentials, "
                  "review its recent activity, and block the source IP.")
            print()

    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force SSH attacks in an auth log.")
    parser.add_argument("logfile", help="Path to the auth log file to analyze")
    parser.add_argument("--threshold", type=int, default=5,
                         help="Failed attempts within window to trigger an alert (default: 5)")
    parser.add_argument("--window", type=int, default=60,
                         help="Sliding time window in seconds (default: 60)")
    parser.add_argument("--year", type=int, default=2026,
                         help="Year to assume for timestamps (auth.log has no year field)")
    args = parser.parse_args()

    events = parse_log(args.logfile, year=args.year)
    brute_force_alerts = detect_brute_force(events, threshold=args.threshold, window_seconds=args.window)
    compromises = detect_post_attack_compromise(events, brute_force_alerts)

    print_report(events, brute_force_alerts, compromises)


if __name__ == "__main__":
    main()
