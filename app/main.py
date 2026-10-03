"""HTTP API and dashboard."""
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.config import get_settings
from app.data.stream import alert_stream
from app.db import Alert, Investigation, LadderEvent, SessionLocal, init_db
from app.ladder import engine as ladder
from app.ladder.stats import wilson_lower_bound
from app.pipeline import correct, counts, process_alert, rebuild_memory

settings = get_settings()
STATIC = Path(__file__).parent / "static"
TYPES = ["phishing", "login"]
_write_lock = threading.Lock()


def _guard_write() -> None:
    if settings.readonly:
        raise HTTPException(403, "This demo instance is read-only.")


def _replay(n: int) -> int:
    with _write_lock, SessionLocal() as db:
        start = (db.scalar(select(func.max(Alert.id))) or 0) + 1
        for g in alert_stream(n, TYPES, seed=7 + start, start_idx=start):
            process_alert(db, g)
        db.commit()
    return n


def _live_loop() -> None:
    while True:
        time.sleep(settings.live_replay_interval_sec)
        try:
            _replay(1)
        except Exception as e:  # keep the demo feed alive
            print("live replay error:", e)


def startup() -> None:
    init_db()
    with SessionLocal() as db:
        rebuild_memory(db)
        empty = counts(db)["alerts"] == 0
    if empty and settings.seed_on_start > 0:
        _replay(settings.seed_on_start)
    if settings.live_replay:
        threading.Thread(target=_live_loop, daemon=True).start()


@asynccontextmanager
async def lifespan(_app):
    startup()
    yield


app = FastAPI(title="Proof Ladder", version="0.1.0", description="Evidence-gated autonomy for an agentic SOC triage agent.", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "provider": settings.llm_provider, "memory": settings.memory_backend, "readonly": settings.readonly}


@app.get("/api/summary")
def summary():
    with SessionLocal() as db:
        out = {"provider": settings.llm_provider, "readonly": settings.readonly, **counts(db), "types": []}
        for t in TYPES:
            st = ladder.get_state(db, t)
            m = ladder.compute_metrics(db, t)
            idx = ladder.LEVELS.index(st.level)
            nxt = ladder.LEVELS[idx + 1] if idx < len(ladder.LEVELS) - 1 else None
            checks = None
            if nxt:
                ok, reasons = ladder.meets(m, nxt)
                checks = {"level": nxt, "ok": ok, "blocking": reasons, "criteria": ladder.CRITERIA[nxt]}
            out["types"].append({"alert_type": t, "level": st.level, "recommendation": st.recommendation, "metrics": asdict(m), "next": checks})
        db.commit()
    return out


@app.get("/api/timeline")
def timeline(alert_type: str, bucket: int = Query(25, ge=5, le=500)):
    with SessionLocal() as db:
        rows = db.execute(select(Investigation.outcome, Investigation.used_precedent).where(Investigation.alert_type == alert_type).order_by(Investigation.id)).all()
    outcomes = [r[0] for r in rows]
    points = []
    for end in range(bucket, len(outcomes) + 1, bucket):
        win = outcomes[max(0, end - ladder.WINDOW):end]
        recent = outcomes[end - bucket:end]
        a, d = win.count("agree"), win.count("agree") + win.count("disagree")
        ra, rd = recent.count("agree"), recent.count("agree") + recent.count("disagree")
        points.append({"n": end, "window_lb": round(wilson_lower_bound(a, d), 4), "bucket_agreement": round(ra / rd, 4) if rd else None,
                       "bucket_deferral": round(recent.count("deferred") / len(recent), 4)})
    return {"alert_type": alert_type, "bucket": bucket, "points": points}


@app.get("/api/investigations")
def list_investigations(alert_type: str | None = None, outcome: str | None = None, limit: int = Query(50, le=200), offset: int = 0):
    with SessionLocal() as db:
        q = select(Investigation, Alert).join(Alert).order_by(Investigation.id.desc())
        if alert_type:
            q = q.where(Investigation.alert_type == alert_type)
        if outcome:
            q = q.where(Investigation.outcome == outcome)
        rows = db.execute(q.limit(limit).offset(offset)).all()
        return [{
            "id": i.id, "external_id": a.external_id, "alert_type": i.alert_type, "ai_verdict": i.ai_verdict,
            "human_verdict": a.human_verdict, "outcome": i.outcome, "critical_miss": i.critical_miss,
            "summary": i.summary, "autonomy": i.autonomy_at_time, "action": i.action_status,
            "used_precedent": i.used_precedent, "corrected": i.corrected, "violations": len(i.grading_violations),
            "headline": a.payload.get("subject") or f"{a.payload.get('user')} from {a.payload.get('geo', {}).get('city')}",
        } for i, a in rows]


@app.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: int):
    with SessionLocal() as db:
        i = db.get(Investigation, inv_id)
        if not i:
            raise HTTPException(404, "not found")
        a = i.alert
        return {
            "id": i.id, "external_id": a.external_id, "alert_type": i.alert_type, "payload": a.payload,
            "human_verdict": a.human_verdict, "scenario": a.scenario, "ai_verdict": i.ai_verdict,
            "proposed_verdict": i.proposed_verdict, "summary": i.summary, "findings": i.findings,
            "violations": i.grading_violations, "outcome": i.outcome, "critical_miss": i.critical_miss,
            "autonomy": i.autonomy_at_time, "action": i.action_status, "used_precedent": i.used_precedent,
            "corrected": i.corrected, "provider": i.provider, "cost_usd": i.cost_usd, "latency_ms": i.latency_ms,
            "steps": [{"ref": s.step_ref, "kind": s.kind, "tool": s.tool, "input": s.input, "output": s.output, "ok": s.ok} for s in i.steps],
        }


class CorrectionIn(BaseModel):
    verdict: str = Field(pattern="^(malicious|benign)$")
    note: str = Field("", max_length=500)


@app.post("/api/investigations/{inv_id}/correct")
def post_correction(inv_id: int, body: CorrectionIn):
    _guard_write()
    with _write_lock, SessionLocal() as db:
        try:
            c = correct(db, inv_id, body.verdict, body.note)
        except LookupError:
            raise HTTPException(404, "not found")
        db.commit()
        return {"correction_id": c.id, "signature": c.signature}


@app.get("/api/ladder/{alert_type}/events")
def ladder_events(alert_type: str):
    with SessionLocal() as db:
        rows = db.execute(select(LadderEvent).where(LadderEvent.alert_type == alert_type).order_by(LadderEvent.id.desc()).limit(50)).scalars().all()
        return [{"id": e.id, "event": e.event, "from": e.from_level, "to": e.to_level, "reason": e.reason, "actor": e.actor,
                 "at": e.created_at.isoformat(), "evidence": e.evidence} for e in rows]


@app.post("/api/ladder/{alert_type}/approve")
def ladder_approve(alert_type: str):
    _guard_write()
    with _write_lock, SessionLocal() as db:
        try:
            st = ladder.approve(db, alert_type)
        except ValueError as e:
            db.commit()
            raise HTTPException(409, str(e))
        db.commit()
        return {"alert_type": alert_type, "level": st.level}


@app.get("/api/ladder/{alert_type}/report", response_class=PlainTextResponse)
def ladder_report(alert_type: str):
    """A promotion evidence report a SOC manager can forward to their CISO or auditor."""
    with SessionLocal() as db:
        st = ladder.get_state(db, alert_type)
        m = ladder.compute_metrics(db, alert_type)
        target = st.recommendation or (ladder.LEVELS[min(ladder.LEVELS.index(st.level) + 1, 2)])
        ok, reasons = ladder.meets(m, target) if target in ladder.CRITERIA else (False, ["already at top level"])
        c = ladder.CRITERIA.get(target, {})
        lines = [
            f"# Autonomy evidence report: {alert_type}",
            "",
            f"Current level: {st.level}. Proposed level: {target}. Criteria met: {'yes' if ok else 'no'}.",
            "",
            f"Window: last {m.total} investigations ({m.decided} decided, {m.deferred} deferred to analysts).",
            "",
            "| Measure | Value | Required |",
            "|---|---|---|",
            f"| Agreement with analysts | {m.agreement_rate:.2%} | |",
            f"| Agreement, 95% lower bound | {m.wilson_lb:.2%} | at least {c.get('min_lb', 0):.0%} |",
            f"| Decided alerts | {m.decided} | at least {c.get('min_decided', 0)} |",
            f"| Critical misses (threat called benign) | {m.critical_misses} | at most {c.get('max_critical_misses', 0)} |",
            f"| Deferral rate | {m.deferral_rate:.2%} | at most {c.get('max_deferral_rate', 0):.0%} |",
            f"| False alarms | {m.false_alarms} | |",
            f"| Grading violations | {m.grading_violation_rate:.2%} | |",
            f"| Verdicts using analyst precedent | {m.precedent_rate:.2%} | |",
            f"| Average cost per alert | ${m.avg_cost_usd:.4f} | |",
            "",
        ]
        if reasons:
            lines += ["Blocking items:", *[f"- {r}" for r in reasons], ""]
        lines.append("Demotion is automatic on any critical miss or if the lower bound drops below the requirement minus 2 points.")
        db.commit()
        return "\n".join(lines)


class ReplayIn(BaseModel):
    n: int = Field(100, ge=1, le=500)


@app.post("/api/replay")
def replay(body: ReplayIn):
    _guard_write()
    return {"processed": _replay(body.n)}
