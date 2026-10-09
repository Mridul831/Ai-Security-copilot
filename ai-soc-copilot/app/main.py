# app/main.py
"""
FastAPI backend for the AI SOC Copilot.

Endpoints:
  GET  /                    - welcome message
  GET  /health              - liveness probe
  GET  /alerts              - list all alerts seen so far
  GET  /events              - list all parsed events seen so far
  POST /ingest              - upload a log file (multipart/form-data)
  POST /ingest-path         - ingest a file that already exists on the server
  POST /reset               - clear in-memory state (handy for demos)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Literal

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.parsers.linux_parser import LogEvent, parse_file, parse_line
from app.detection.rules import Alert, run_rules, RuleEngine


# ----------------------------- models ---------------------------------- #

class IngestPathRequest(BaseModel):
    path: str
    source: Literal["auth", "syslog"] = "auth"


class IngestResponse(BaseModel):
    events_parsed: int
    alerts_generated: int
    alerts: List[dict]


# ----------------------------- state ----------------------------------- #

class Store:
    """Tiny in-memory store. Good enough for a demo."""
    def __init__(self) -> None:
        self.events: list[LogEvent] = []
        self.alerts: list[Alert] = []
        self._engine = RuleEngine()

    def reset(self) -> None:
        self.events.clear()
        self.alerts.clear()
        self._engine = RuleEngine()

    def ingest_events(self, events: list[LogEvent]) -> list[Alert]:
        new_alerts: list[Alert] = []
        for ev in events:
            self.events.append(ev)
            for a in self._engine.evaluate(ev):
                self.alerts.append(a)
                new_alerts.append(a)
        return new_alerts


store = Store()


# ----------------------------- app ------------------------------------- #

app = FastAPI(
    title="AI SOC Copilot",
    version="0.1.0",
    description="Parse Linux logs, detect suspicious activity, and (soon) explain it with an LLM.",
)

# Allow Streamlit (localhost:8501) to call us during dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------- routes ---------------------------------- #

@app.get("/")
def read_root() -> dict:
    """Root endpoint to verify the API is running."""
    return {
        "message": "AI SOC Copilot API is running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict:
    """Liveness probe — shows current state counts."""
    return {
        "status": "ok",
        "events": len(store.events),
        "alerts": len(store.alerts),
    }


@app.get("/alerts")
def list_alerts(
    severity: str | None = Query(None, description="Filter by severity, e.g. 'high'"),
    rule_id: str | None = Query(None, description="Filter by rule, e.g. 'R001'"),
    limit: int = Query(200, ge=1, le=5000),
) -> dict:
    items = [a.to_dict() for a in store.alerts]
    if severity:
        items = [a for a in items if a["severity"] == severity]
    if rule_id:
        items = [a for a in items if a["rule_id"] == rule_id]
    return {"count": len(items), "alerts": items[-limit:]}


@app.get("/events")
def list_events(
    event_type: str | None = Query(None, description="e.g. ssh_failed, ssh_login, sudo"),
    limit: int = Query(500, ge=1, le=20000),
) -> dict:
    items = [e.to_dict() for e in store.events]
    if event_type:
        items = [e for e in items if e["event_type"] == event_type]
    return {"count": len(items), "events": items[-limit:]}


@app.post("/ingest", response_model=IngestResponse)
async def ingest_upload(
    file: UploadFile = File(...),
    source: Literal["auth", "syslog"] = "auth",
) -> IngestResponse:
    """Upload a log file directly from the browser."""
    raw = await file.read()
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:  # pragma: no cover
        raise HTTPException(status_code=400, detail=f"cannot decode file: {e}")

    events: list[LogEvent] = []
    for line in text.splitlines():
        ev = parse_line(line, source=source)
        if ev is not None:
            events.append(ev)

    alerts = store.ingest_events(events)
    return IngestResponse(
        events_parsed=len(events),
        alerts_generated=len(alerts),
        alerts=[a.to_dict() for a in alerts],
    )


@app.post("/ingest-path", response_model=IngestResponse)
def ingest_path(req: IngestPathRequest) -> IngestResponse:
    """Ingest a log file already present on the server (e.g. data/auth.log)."""
    p = Path(req.path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"file not found: {p}")
    if not p.is_file():
        raise HTTPException(status_code=400, detail=f"not a file: {p}")

    events = list(parse_file(p, source=req.source))
    alerts = store.ingest_events(events)
    return IngestResponse(
        events_parsed=len(events),
        alerts_generated=len(alerts),
        alerts=[a.to_dict() for a in alerts],
    )


@app.post("/reset")
def reset() -> dict:
    """Clear all events and alerts from memory."""
    store.reset()
    return {"status": "reset"}


# ----------------------------- dev entry ------------------------------- #

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)


    # Add this import at the top of main.py
from app.llm.agent import analyze_alert

# ... existing code ...

# Create a new endpoint (Adjust the data structure based on how you store alerts)
from pydantic import BaseModel

class AlertTriageRequest(BaseModel):
    rule_name: str
    severity: str
    summary: str
    raw_log: str = "Log data not provided"

@app.post("/triage")
def triage_alert(request: AlertTriageRequest):
    """
    Endpoint to send an alert to the LLM for analysis.
    """
    alert_dict = request.dict()
    ai_analysis = analyze_alert(alert_dict)
    return {"analysis": ai_analysis}