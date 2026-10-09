# app/parsers/linux_parser.py
"""
Minimal Linux log parser.
Currently handles:
  - sshd auth events (Accepted / Failed / Invalid)
  - sudo COMMAND lines
  - systemd-logind sessions
  - generic syslog lines (proc[pid]: msg)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional


# "Jul 12 14:33:01"  (no year in classic syslog)
_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")
_HOST_RE = re.compile(r"^(?P<host>\S+)\s+")

_SSHD_RE = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?:"
    r"   (?:(?P<action>Accepted|Failed)\s+(?:password|publickey)\s+for\s+"
    r"      (?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+))"
    r"   |"
    r"   (?:Invalid user (?P<inv_user>\S+) from (?P<inv_ip>\S+) port (?P<inv_port>\d+))"
    r")"
)
_SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+"
    r"PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<runas>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$"
)

_SESSION_RE = re.compile(r"systemd-logind\[\d+\]: New session \d+ of user (?P<user>\S+)\.")

_GENERIC_RE = re.compile(r"(?P<proc>[A-Za-z0-9_\-\.]+)\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$")


@dataclass
class LogEvent:
    ts: str
    host: str
    source: str          # "auth" or "syslog"
    event_type: str      # "ssh_login", "ssh_failed", "sudo", "session", "generic"
    user: Optional[str] = None
    ip: Optional[str] = None
    pid: Optional[int] = None
    raw: str = ""
    extra: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_ts(ts: str) -> str:
    """Return ISO-8601. Classic syslog has no year, so assume current year."""
    year = datetime.now().year
    dt = datetime.strptime(f"{ts} {year}", "%b %d %H:%M:%S %Y")
    return dt.isoformat()


def parse_line(line: str, source: str = "auth") -> Optional[LogEvent]:
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m_ts = _TS_RE.match(line)
    if not m_ts:
        return None
    ts = _parse_ts(m_ts.group("ts"))
    rest = line[m_ts.end():]

    m_host = _HOST_RE.match(rest)
    if not m_host:
        return None
    host = m_host.group("host")
    body = rest[m_host.end():]

    # --- sshd ---
    m = _SSHD_RE.search(body)
    if m:
        if m.group("user"):
            action = m.group("action").lower()
            return LogEvent(
                ts=ts, host=host, source=source,
                event_type="ssh_login" if action == "accepted" else "ssh_failed",
                user=m.group("user"),
                ip=m.group("ip"),
                pid=int(m.group("pid")),
                raw=line,
                extra={"port": int(m.group("port")), "action": action},
            )
        else:
            return LogEvent(
                ts=ts, host=host, source=source,
                event_type="ssh_failed",
                user=m.group("inv_user"),
                ip=m.group("inv_ip"),
                pid=int(m.group("pid")) if m.group("pid") else None,
                raw=line,
                extra={"port": int(m.group("inv_port")), "action": "invalid"},
            )

    # --- sudo ---
    m = _SUDO_RE.search(body)
    if m:
        return LogEvent(
            ts=ts, host=host, source=source, event_type="sudo",
            user=m.group("user"),
            raw=line,
            extra={
                "tty": m.group("tty"),
                "pwd": m.group("pwd"),
                "runas": m.group("runas"),
                "cmd": m.group("cmd"),
            },
        )

    # --- logind session ---
    m = _SESSION_RE.search(body)
    if m:
        return LogEvent(
            ts=ts, host=host, source=source, event_type="session",
            user=m.group("user"), raw=line,
        )

    # --- generic syslog ---
    m = _GENERIC_RE.search(body)
    if m:
        return LogEvent(
            ts=ts, host=host, source=source, event_type="generic",
            pid=int(m.group("pid")), raw=line,
            extra={"proc": m.group("proc"), "msg": m.group("msg")},
        )

    return LogEvent(ts=ts, host=host, source=source, event_type="unknown", raw=line)


def parse_file(path: str | Path, source: str = "auth") -> Iterable[LogEvent]:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_line(line, source=source)
            if ev is not None:
                yield ev


if __name__ == "__main__":
    import json, sys

    p = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/auth.log")
    src = "syslog" if "syslog" in p.name else "auth"

    n = 0
    for ev in parse_file(p, source=src):
        print(json.dumps(ev.to_dict()))
        n += 1
        if n >= 10:
            break
    print(f"... (showed first {n} events)", file=sys.stderr)