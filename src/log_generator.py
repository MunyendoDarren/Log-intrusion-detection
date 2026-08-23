"""
Log Generator
-------------
Generates a synthetic SSH authentication log (in the same format Linux's
/var/log/auth.log uses) containing a mix of normal logins and a
simulated brute-force attack, so the detector script has something
realistic to analyze.

This does NOT touch your real system logs or any real accounts — it
writes a plain sample log file to data/sample_auth.log.

Usage:
    python log_generator.py
"""

import os
import random
from datetime import datetime, timedelta

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sample_auth.log")

NORMAL_USERS = ["papi", "alice", "bmwangi", "deploy", "admin"]
NORMAL_IPS = ["41.90.12.34", "197.232.14.9", "102.68.79.201", "196.207.32.11"]

ATTACKER_IP = "185.220.101.47"
ATTACKER_USERNAMES = [
    "root", "admin", "test", "user", "oracle", "postgres", "guest",
    "ubuntu", "administrator", "ftpuser", "pi", "vagrant", "support",
    "backup", "git", "www-data", "sysadmin", "info", "temp", "demo",
]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
HOST = "web-prod-01"


def fmt_timestamp(dt: datetime) -> str:
    # e.g. "Aug 23 09:14:02"
    return f"{MONTHS[dt.month - 1]} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def failed_password_line(dt: datetime, user: str, ip: str, invalid: bool, port: int) -> str:
    tag = "invalid user " if invalid else ""
    return f"{fmt_timestamp(dt)} {HOST} sshd[{random.randint(1000, 9999)}]: Failed password for {tag}{user} from {ip} port {port} ssh2"


def accepted_password_line(dt: datetime, user: str, ip: str, port: int) -> str:
    return f"{fmt_timestamp(dt)} {HOST} sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {port} ssh2"


def invalid_user_line(dt: datetime, user: str, ip: str) -> str:
    return f"{fmt_timestamp(dt)} {HOST} sshd[{random.randint(1000, 9999)}]: Invalid user {user} from {ip}"


def generate_normal_traffic(start: datetime, count: int) -> list:
    """A handful of normal, spread-out logins across the day (mostly successful)."""
    lines = []
    current = start
    for _ in range(count):
        current += timedelta(minutes=random.randint(15, 90))
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        port = random.randint(40000, 60000)
        if random.random() < 0.9:
            lines.append((current, accepted_password_line(current, user, ip, port)))
        else:
            # the occasional real typo/mistake, isolated (not a burst)
            lines.append((current, failed_password_line(current, user, ip, False, port)))
    return lines


def generate_brute_force_attack(start: datetime, attempts: int = 40) -> list:
    """
    A burst of failed logins from a single IP against many usernames in a
    short window, then finally succeeding on one weak account.
    """
    lines = []
    current = start
    used_users = random.sample(
        ATTACKER_USERNAMES, k=min(attempts, len(ATTACKER_USERNAMES))
    )
    # pad out with repeats if attempts > unique usernames available
    while len(used_users) < attempts:
        used_users.append(random.choice(ATTACKER_USERNAMES))

    for user in used_users:
        current += timedelta(seconds=random.uniform(0.8, 3.5))  # rapid-fire
        port = random.randint(40000, 60000)
        lines.append((current, invalid_user_line(current, user, ATTACKER_IP)))
        lines.append((current, failed_password_line(current, user, ATTACKER_IP, True, port)))

    # attacker finally guesses a weak, real account correctly
    current += timedelta(seconds=random.uniform(1, 3))
    port = random.randint(40000, 60000)
    lines.append((current, accepted_password_line(current, "admin", ATTACKER_IP, port)))

    return lines


def main():
    random.seed(42)  # reproducible sample log for the README/demo
    day_start = datetime(2026, 8, 23, 6, 0, 0)

    normal_morning = generate_normal_traffic(day_start, count=8)
    attack_start = day_start + timedelta(hours=3, minutes=12)
    attack = generate_brute_force_attack(attack_start, attempts=40)
    normal_afternoon = generate_normal_traffic(attack_start + timedelta(hours=1), count=6)

    all_lines = normal_morning + attack + normal_afternoon
    all_lines.sort(key=lambda pair: pair[0])

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        for _, line in all_lines:
            f.write(line + "\n")

    print(f"Generated {len(all_lines)} log lines -> {OUTPUT_PATH}")
    print(f"  Normal logins: {len(normal_morning) + len(normal_afternoon)}")
    print(f"  Brute-force attack lines: {len(attack)} (from {ATTACKER_IP})")


if __name__ == "__main__":
    main()
