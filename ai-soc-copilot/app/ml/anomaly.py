# app/ml/anomaly.py
"""
Unsupervised anomaly detection on parsed Linux log events.

Uses IsolationForest to find events that deviate from the "norm".
This catches unknown-unknowns that rules might miss.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

from app.parsers.linux_parser import LogEvent, parse_file


# ----------------------------- feature engineering --------------------- #

def _events_to_dataframe(events: Iterable[LogEvent]) -> pd.DataFrame:
    """Turn a stream of LogEvents into a numeric feature matrix."""
    rows = []
    for ev in events:
        dt = datetime.fromisoformat(ev.ts)
        rows.append({
            "hour": dt.hour,
            "minute": dt.minute,
            "event_type": ev.event_type,
            "user": ev.user or "unknown",
            "ip": ev.ip or "none",
            "is_failed": 1 if ev.event_type == "ssh_failed" else 0,
            "is_sudo": 1 if ev.event_type == "sudo" else 0,
        })

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # Encode categorical columns
    for col in ("event_type", "user", "ip"):
        le = LabelEncoder()
        df[f"{col}_code"] = le.fit_transform(df[col])

    feature_cols = [
        "hour", "minute", "is_failed", "is_sudo",
        "event_type_code", "user_code", "ip_code",
    ]
    return df[feature_cols]


# ----------------------------- detector -------------------------------- #

def detect_anomalies(
    events: list[LogEvent],
    contamination: float = 0.05,
    random_state: int = 42,
) -> list[dict]:
    """
    Run IsolationForest on the events.

    Returns a list of dicts:
        {
          "event": <original LogEvent dict>,
          "anomaly_score": float,  # lower = more anomalous
          "is_anomaly": bool,      # True if model flagged it
        }
    """
    df = _events_to_dataframe(events)
    if df.empty:
        return []

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    preds = model.fit_predict(df)                # 1 = normal, -1 = anomaly
    scores = model.decision_function(df)         # lower = more anomalous

    results: list[dict] = []
    for ev, pred, score in zip(events, preds, scores):
        results.append({
            "event": ev.to_dict(),
            "anomaly_score": float(score),
            "is_anomaly": bool(pred == -1),
        })

    # Sort so most anomalous float to the top
    results.sort(key=lambda r: r["anomaly_score"])
    return results


# ----------------------------- CLI test -------------------------------- #

if __name__ == "__main__":
    import sys
    from pathlib import Path

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/auth.log")
    source = "syslog" if "syslog" in path.name else "auth"

    events = list(parse_file(path, source=source))
    print(f"Loaded {len(events)} events from {path}", file=sys.stderr)

    results = detect_anomalies(events)
    anomalies = [r for r in results if r["is_anomaly"]]

    print(f"\nFound {len(anomalies)} anomalies (top 5 shown):\n", file=sys.stderr)
    for r in anomalies[:5]:
        ev = r["event"]
        print(json.dumps({
            "score": round(r["anomaly_score"], 3),
            "type": ev["event_type"],
            "user": ev["user"],
            "ip": ev["ip"],
            "ts": ev["ts"],
            "raw": ev["raw"][:100],
        }))