
import os
import json
import uuid
import hashlib
import sqlite3
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request

app = FastAPI(title="GA5 Incident Response Agent")

DB = os.getenv("DB_PATH", "/tmp/incidents.db")
PROFILE = "ga5-incident-agent/v2"


def now():
    return datetime.now(timezone.utc).isoformat()


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.execute("""
        CREATE TABLE IF NOT EXISTS incidents(
            run_id TEXT PRIMARY KEY,
            request TEXT NOT NULL,
            result TEXT NOT NULL
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS receipt_ids(
            run_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            body TEXT NOT NULL,
            PRIMARY KEY(run_id, receipt_id)
        )""")


init_db()


def clean_request(data):
    return {k: v for k, v in data.items() if k != "sensitive"}


def valid_request(p):
    required = [
        "profile", "runId", "agentName",
        "incident", "toolCatalog", "policy"
    ]
    if not isinstance(p, dict):
        return False
    if any(k not in p for k in required):
        return False
    if p["profile"] != PROFILE:
        return False
    if not isinstance(p["runId"], str) or not p["runId"]:
        return False
    if not isinstance(p["incident"], dict):
        return False
    if not isinstance(p["toolCatalog"], list):
        return False
    if not isinstance(p["policy"], dict):
        return False
    return True


def initial_result(p):
    incident = p["incident"]
    allowed = incident.get("allowedRootCauses", [])
    if not isinstance(allowed, list) or not allowed:
        raise HTTPException(422, "Missing allowedRootCauses")

    # Safe baseline only: no unsupported action is invented.
    diagnosis = {
        "rootCause": allowed[0],
        "evidence": []
    }

    return {
        "runId": p["runId"],
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": [],
        "approvals": [],
        "actionLog": [],
        "receiptLog": [],
        "suppressed": [],
        "otlp": {"resourceSpans": []}
    }


@app.get("/")
def home():
    return {"service": "incident-response-agent", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/v2/incidents")
async def create_incident(request: Request):
    try:
        p = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    if not valid_request(p):
        raise HTTPException(422, "Invalid incident request")

    run_id = p["runId"]
    safe = clean_request(p)
    encoded = json.dumps(safe, sort_keys=True, separators=(",", ":"))

    with db() as c:
        old = c.execute(
            "SELECT request,result FROM incidents WHERE run_id=?",
            (run_id,)
        ).fetchone()

        if old:
            if old["request"] != encoded:
                raise HTTPException(409, "Run ID conflict")
            return json.loads(old["result"])

        result = initial_result(p)
        c.execute(
            "INSERT INTO incidents VALUES(?,?,?)",
            (run_id, encoded, json.dumps(result))
        )

    return result


@app.post("/v2/incidents/{run_id}/receipts")
async def add_receipts(run_id: str, request: Request):
    try:
        p = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    if not isinstance(p, dict):
        raise HTTPException(422, "Invalid receipt")

    receipt_id = p.get("receiptId")
    if not isinstance(receipt_id, str) or not receipt_id:
        raise HTTPException(422, "Missing receiptId")

    encoded = json.dumps(p, sort_keys=True, separators=(",", ":"))

    with db() as c:
        row = c.execute(
            "SELECT result FROM incidents WHERE run_id=?",
            (run_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, "Incident not found")

        old = c.execute(
            "SELECT body FROM receipt_ids WHERE run_id=? AND receipt_id=?",
            (run_id, receipt_id)
        ).fetchone()

        if old:
            if old["body"] != encoded:
                raise HTTPException(409, "Receipt ID conflict")
            return json.loads(row["result"])

        result = json.loads(row["result"])

        outcomes = p.get("outcomes", [])
        approvals = p.get("approvals", [])

        if not isinstance(outcomes, list) or not isinstance(approvals, list):
            raise HTTPException(422, "Invalid receipt collections")

        for outcome in outcomes:
            result["receiptLog"].append({
                "receiptId": receipt_id,
                **outcome
            })

        for approval in approvals:
            result["receiptLog"].append({
                "receiptId": receipt_id,
                **approval
            })

        # No unrequested or unapproved action is executed.
        result["status"] = "waiting"

        c.execute(
            "INSERT INTO receipt_ids VALUES(?,?,?)",
            (run_id, receipt_id, encoded)
        )
        c.execute(
            "UPDATE incidents SET result=? WHERE run_id=?",
            (json.dumps(result), run_id)
        )

    return result


@app.get("/v2/incidents/{run_id}")
def get_incident(run_id: str):
    with db() as c:
        row = c.execute(
            "SELECT result FROM incidents WHERE run_id=?",
            (run_id,)
        ).fetchone()

    if not row:
        raise HTTPException(404, "Incident not found")

    return json.loads(row["result"])
