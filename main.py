
import os
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

app = FastAPI(title="Incident Response Agent")

DB = os.getenv("DB_PATH", "/tmp/incidents.db")


def now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS incidents(
            run_id TEXT PRIMARY KEY,
            request TEXT NOT NULL,
            result TEXT NOT NULL
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS receipts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            receipt TEXT NOT NULL,
            UNIQUE(run_id, receipt)
        )""")


init_db()


class Incident(BaseModel):
    incidentId: Optional[str] = None
    service: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = "high"
    symptoms: list = Field(default_factory=list)
    evidence: list = Field(default_factory=list)
    diagnostics: dict = Field(default_factory=dict)
    telemetry: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class Receipt(BaseModel):
    action: Optional[str] = None
    status: Optional[str] = None
    outcome: Optional[str] = None
    success: Optional[bool] = None
    details: dict = Field(default_factory=dict)


def analyze(x):
    text = " ".join([
        str(x.summary or ""),
        str(x.description or ""),
        json.dumps(x.symptoms),
        json.dumps(x.evidence),
        json.dumps(x.telemetry)
    ]).lower()

    if any(k in text for k in ["timeout", "latency", "timed out"]):
        cause = "Dependency latency or timeout is the likely cause."
        confidence = 0.78
        evidence = ["Timeout or latency indicators"]
    elif any(k in text for k in ["500", "503", "5xx", "crash"]):
        cause = "Application failure or unhealthy upstream dependency is likely."
        confidence = 0.74
        evidence = ["HTTP error or crash indicators"]
    elif any(k in text for k in ["memory", "oom"]):
        cause = "Memory pressure is the likely cause."
        confidence = 0.76
        evidence = ["Memory or OOM indicators"]
    else:
        cause = "Insufficient telemetry for a definitive root cause."
        confidence = 0.40
        evidence = ["Submitted incident summary and symptoms"]

    return {
        "rootCause": cause,
        "confidence": confidence,
        "selectedEvidence": evidence,
        "diagnosticsRequested": [
            "service health", "recent deployment",
            "error rate", "dependency latency"
        ],
        "proposedActions": [
            {"action": "collect_diagnostics", "approvalRequired": False},
            {"action": "restart_service", "approvalRequired": True},
            {"action": "rollback_deployment", "approvalRequired": True}
        ]
    }


@app.get("/")
def home():
    return {"service": "Incident Response Agent", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/v2/incidents")
def create_incident(
    payload: Incident,
    idempotency_key: Optional[str] = Header(None)
):
    request_data = payload.model_dump()
    key = idempotency_key or payload.incidentId

    if key:
        with connect() as c:
            old = c.execute(
                "SELECT * FROM incidents WHERE run_id=?", (key,)
            ).fetchone()
            if old:
                if old["request"] != json.dumps(request_data, sort_keys=True):
                    raise HTTPException(409, "Idempotency conflict")
                return json.loads(old["result"])

    run_id = str(uuid.uuid4())
    result = {
        "runId": run_id,
        "incidentId": payload.incidentId or run_id,
        "status": "awaiting_receipts",
        "state": "diagnostics_pending",
        "analysis": analyze(payload),
        "actions": [],
        "receipts": [],
        "createdAt": now()
    }

    with connect() as c:
        c.execute(
            "INSERT INTO incidents VALUES(?,?,?)",
            (run_id, json.dumps(request_data, sort_keys=True),
             json.dumps(result))
        )

    return result


@app.post("/v2/incidents/{run_id}/receipts")
def add_receipt(run_id: str, receipt: Receipt):
    with connect() as c:
        row = c.execute(
            "SELECT result FROM incidents WHERE run_id=?", (run_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, "Incident not found")

        result = json.loads(row["result"])
        data = receipt.model_dump()
        encoded = json.dumps(data, sort_keys=True)

        old = c.execute(
            "SELECT 1 FROM receipts WHERE run_id=? AND receipt=?",
            (run_id, encoded)
        ).fetchone()

        if old:
            return result

        action = (data.get("action") or "").lower()
        status = (data.get("status") or data.get("outcome") or "").lower()
        success = data.get("success")
        if success is None:
            success = status in [
                "success", "succeeded", "completed", "ok", "200", "201"
            ]

        if not success:
            result["state"] = "diagnostics_failed"
            result["status"] = "blocked"
            result["blockedReason"] = (
                "Prerequisite failed; dependent actions suppressed."
            )
        elif action in ["collect_diagnostics", "diagnostics"]:
            result["state"] = "awaiting_approval"
            result["status"] = "awaiting_approval"
        elif action in ["approval", "approve"]:
            if data.get("details", {}).get("approved", True):
                result["state"] = "approved"
                result["status"] = "ready_for_action"
            else:
                result["state"] = "rejected"
                result["status"] = "closed"
        elif action in [
            "rollback_deployment", "restart_service", "disable_feature"
        ]:
            if result["state"] != "approved":
                raise HTTPException(403, "Approval required")
            result["state"] = "remediated"
            result["status"] = "resolved"

        result["receipts"].append(data)
        result["actions"].append({
            "action": action,
            "success": bool(success),
            "at": now()
        })

        c.execute(
            "INSERT OR IGNORE INTO receipts(run_id,receipt) VALUES(?,?)",
            (run_id, encoded)
        )
        c.execute(
            "UPDATE incidents SET result=? WHERE run_id=?",
            (json.dumps(result), run_id)
        )

        return result


@app.get("/v2/incidents/{run_id}")
def get_incident(run_id: str):
    with connect() as c:
        row = c.execute(
            "SELECT result FROM incidents WHERE run_id=?", (run_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, "Incident not found")

        return json.loads(row["result"])
