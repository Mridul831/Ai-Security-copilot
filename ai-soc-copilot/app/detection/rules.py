# app/detection/rules.py
"""
Rule engine: takes LogEvent objects and produces Alert objects.

Rules implemented:
  R001  SSH Brute Force        - N failed logins from same IP within window
  R002  Successful login after failures - possible compromise
  R003  Sudo to root           - privilege escalation (info-level)
  R004  Off-hours activity     - auth events outside business hours
  R005  Invalid user sweep     - many invalid users from same IP
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Iterable, Optional

from app.parsers.linux_parser import LogEvent


# ----------------------------- Alert model ----------------------------- #

@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str          # "low" | "medium" | "high" | "critical"
    ts: str
    summary: str
    user: Optional[str] = None
    ip: Optional[str] = None
    evidence: list = field(default_factory=list)   # list of raw log lines

    def to_dict(self) -> dict:
        return asdict(self)


# ----------------------------- Config ---------------------------------- #

BRUTE_FORCE_THRESHOLD = 5          # failed logins
BRUTE_FORCE_WINDOW    = timedelta(minutes=2)
INVALID_SWEEP_THRESHOLD = 5
BUSINESS_HOUR_START = 8            # 08:00
BUSINESS_HOUR_END   = 20           # 20:00


# ----------------------------- Helpers --------------------------------- #

def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _is_off_hours(ts: str) -> bool:
    dt = _parse_iso(ts)
    return dt.hour < BUSINESS_HOUR_START or dt.hour >= BUSINESS_HOUR_END


# ----------------------------- Rule engine ----------------------------- #

class RuleEngine:
    def __init__(self) -> None:
        # per-IP rolling window of failed logins
        self._failed_by_ip: dict[str, deque[LogEvent]] = defaultdict(deque)
        # per-IP set of invalid usernames seen (with timestamps)
        self._invalid_by_ip: dict[str, deque[LogEvent]] = defaultdict(deque)

    # -- individual rules ------------------------------------------------ #

    def _r001_brute_force(self, ev: LogEvent) -> Optional[Alert]:
        if ev.event_type != "ssh_failed" or not ev.ip:
            return None

        window = self._failed_by_ip[ev.ip]
        window.append(ev)

        cutoff = _parse_iso(ev.ts) - BRUTE_FORCE_WINDOW
        while window and _parse_iso(window[0].ts) < cutoff:
            window.popleft()

        if len(window) >= BRUTE_FORCE_THRESHOLD:
            return Alert(
                rule_id="R001",
                rule_name="SSH Brute Force",
                severity="high",
                ts=ev.ts,
                summary=(
                    f"{len(window)} failed SSH logins from {ev.ip} "
                    f"within {BRUTE_FORCE_WINDOW.seconds // 60} min"
                ),
                user=ev.user,
                ip=ev.ip,
                evidence=[e.raw for e in list(window)[-10:]],
            )
        return None

    def _r002_success_after_failures(self, ev: LogEvent) -> Optional[Alert]:
        if ev.event_type != "ssh_login" or not ev.ip:
            return None
        window = self._failed_by_ip.get(ev.ip)
        if window and len(window) >= 3:
            return Alert(
                rule_id="R002",
                rule_name="Successful Login After Failures",
                severity="critical",
                ts=ev.ts,
                summary=(
                    f"Successful login for '{ev.user}' from {ev.ip} "
                    f"after {len(window)} failed attempts — possible compromise"
                ),
                user=ev.user,
                ip=ev.ip,
                evidence=[e.raw for e in list(window)[-5:]] + [ev.raw],
            )
        return None

    def _r003_sudo_root(self, ev: LogEvent) -> Optional[Alert]:
        if ev.event_type != "sudo":
            return None
        runas = (ev.extra or {}).get("runas")
        if runas != "root":
            return None
        cmd = (ev.extra or {}).get("cmd", "")
        return Alert(
            rule_id="R003",
            rule_name="Privilege Escalation (sudo -> root)",
            severity="medium",
            ts=ev.ts,
            summary=f"User '{ev.user}' escalated to root: {cmd}",
            user=ev.user,
            evidence=[ev.raw],
        )

    def _r004_off_hours(self, ev: LogEvent) -> Optional[Alert]:
        if ev.event_type not in ("ssh_login", "sudo"):
            return None
        if not _is_off_hours(ev.ts):
            return None
        return Alert(
            rule_id="R004",
            rule_name="Off-Hours Auth Activity",
            severity="low",
            ts=ev.ts,
            summary=(
                f"Off-hours {ev.event_type} for '{ev.user}' at {ev.ts}"
            ),
            user=ev.user,
            ip=ev.ip,
            evidence=[ev.raw],
        )

    def _r005_invalid_sweep(self, ev: LogEvent) -> Optional[Alert]:
        if ev.event_type != "ssh_failed" or not ev.ip:
            return None
        action = (ev.extra or {}).get("action")
        if action != "invalid":
            return None

        window = self._invalid_by_ip[ev.ip]
        window.append(ev)
        cutoff = _parse_iso(ev.ts) - BRUTE_FORCE_WINDOW
        while window and _parse_iso(window[0].ts) < cutoff:
            window.popleft()

        if len(window) >= INVALID_SWEEP_THRESHOLD:
            users = sorted({e.user for e in window if e.user})
            return Alert(
                rule_id="R005",
                rule_name="Invalid User Sweep",
                severity="medium",
                ts=ev.ts,
                summary=(
                    f"Invalid-user sweep from {ev.ip} "
                    f"({len(window)} attempts, users: {', '.join(users[:6])})"
                ),
                ip=ev.ip,
                evidence=[e.raw for e in list(window)[-10:]],
            )
        return None

    # -- public API ------------------------------------------------------ #

    def evaluate(self, ev: LogEvent) -> list[Alert]:
        """Run every rule against one event, return all alerts it triggers."""
        alerts: list[Alert] = []
        for fn in (
            self._r001_brute_force,
            self._r002_success_after_failures,
            self._r003_sudo_root,
            self._r004_off_hours,
            self._r005_invalid_sweep,
        ):
            a = fn(ev)
            if a:
                alerts.append(a)
        return alerts


def run_rules(events: Iterable[LogEvent]) -> list[Alert]:
    """Convenience: feed a stream of events, get all alerts back."""
    engine = RuleEngine()
    out: list[Alert] = []
    for ev in events:
        out.extend(engine.evaluate(ev))
    return out


# ----------------------------- CLI test -------------------------------- #

if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path
    from app.parsers.linux_parser import parse_file

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/auth.log")
    source = "syslog" if "syslog" in path.name else "auth"

    alerts = run_rules(parse_file(path, source=source))

    for a in alerts:
        print(json.dumps(a.to_dict()))
    print(f"\n[{len(alerts)} alerts from {path}]", file=sys.stderr)