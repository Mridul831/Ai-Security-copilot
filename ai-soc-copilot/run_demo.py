# run_demo.py
"""
Generate synthetic Linux auth + syslog logs for the SOC copilot demo.
Run:  python run_demo.py
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

USERS = ["root", "mridul", "ubuntu", "www-data", "postgres", "deploy"]
IPS = [
    "192.168.1.42", "10.0.0.15", "203.0.113.77",
    "198.51.100.23", "185.220.101.5", "45.142.212.61",
]
PROCS = ["sshd", "sudo", "systemd", "cron", "kernel", "nginx"]


def _ts(base: datetime, offset: int) -> str:
    return (base + timedelta(seconds=offset)).strftime("%b %d %H:%M:%S")


def gen_auth_log(n_events: int = 200, seed: int = 42) -> list[str]:
    random.seed(seed)
    base = datetime.now() - timedelta(hours=2)
    lines: list[str] = []
    t = 0

    for _ in range(n_events):
        t += random.randint(5, 90)
        host = "Mridul"
        user = random.choice(USERS)
        ip = random.choice(IPS)
        kind = random.choices(
            ["accepted", "failed", "sudo", "session", "invalid"],
            weights=[40, 30, 15, 10, 5],
        )[0]

        if kind == "accepted":
            lines.append(
                f"{_ts(base, t)} {host} sshd[{random.randint(1000,9999)}]: "
                f"Accepted password for {user} from {ip} port {random.randint(30000,65000)} ssh2"
            )
        elif kind == "failed":
            lines.append(
                f"{_ts(base, t)} {host} sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {ip} port {random.randint(30000,65000)} ssh2"
            )
        elif kind == "sudo":
            lines.append(
                f"{_ts(base, t)} {host} sudo: {user} : TTY=pts/0 ; "
                f"PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt-get update"
            )
        elif kind == "session":
            lines.append(
                f"{_ts(base, t)} {host} systemd-logind[{random.randint(500,999)}]: "
                f"New session {random.randint(1,50)} of user {user}."
            )
        else:
            lines.append(
                f"{_ts(base, t)} {host} sshd[{random.randint(1000,9999)}]: "
                f"Invalid user {user} from {ip} port {random.randint(30000,65000)}"
            )

    # Sprinkle in a brute-force burst from one IP (this is what rules will catch)
    attacker = "45.142.212.61"
    for i in range(40):
        t += 3
        lines.append(
            f"{_ts(base, t)} Mridul sshd[{random.randint(1000,9999)}]: "
            f"Failed password for root from {attacker} port {random.randint(30000,65000)} ssh2"
        )

    return lines


def gen_syslog(n_events: int = 150, seed: int = 7) -> list[str]:
    random.seed(seed)
    base = datetime.now() - timedelta(hours=2)
    lines: list[str] = []
    t = 0

    for _ in range(n_events):
        t += random.randint(10, 120)
        proc = random.choice(PROCS)
        pid = random.randint(100, 9999)
        msg = random.choice([
            "Started Daily apt download activities.",
            "Reached target Multi-User System.",
            "Listening on Docker Socket for the API.",
            "error: cannot open /etc/nginx/nginx.conf",
            "Connection reset by peer",
            "Out of memory: Kill process 1234 (python)",
            "pam_unix(cron:session): session opened for user root",
        ])
        lines.append(f"{_ts(base, t)} Mridul {proc}[{pid}]: {msg}")

    return lines


def main() -> None:
    auth_lines = gen_auth_log()
    syslog_lines = gen_syslog()

    auth_path = DATA_DIR / "auth.log"
    syslog_path = DATA_DIR / "syslog.log"

    auth_path.write_text("\n".join(auth_lines) + "\n")
    syslog_path.write_text("\n".join(syslog_lines) + "\n")

    print(f"Wrote {len(auth_lines):>4} lines -> {auth_path}")
    print(f"Wrote {len(syslog_lines):>4} lines -> {syslog_path}")


if __name__ == "__main__":
    main()