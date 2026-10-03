"""Ingest -> triage -> shadow compare -> ladder update. Also corrections and regression export."""
import json
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agent.tools import Toolbox
from app.agent.triage import triage
from app.data.common import GeneratedAlert
from app.db import Alert, AuditStep, Correction, Intel, Investigation
from app.ladder import engine as ladder
from app.memory.store import get_store

ACTION_BY_LEVEL = {"assisted": "shadow", "ai_led": "drafted", "autonomous": "executed"}


def make_intel_lookup(db: Session):
    cache: dict[tuple[str, str], dict | None] = {}

    def lookup(kind: str, key: str) -> dict | None:
        if (kind, key) not in cache:
            row = db.execute(select(Intel).where(Intel.kind == kind, Intel.key == key).order_by(Intel.id.desc())).scalars().first()
            cache[(kind, key)] = row.attrs if row else None
        return cache[(kind, key)]

    return lookup


def snapshot_lookup(snapshot: list):
    idx = {(k, key): attrs for k, key, attrs in snapshot}
    return lambda kind, key: idx.get((kind, key))


def upsert_intel(db: Session, records: list[tuple[str, str, dict]]) -> None:
    for kind, key, attrs in records:
        row = db.execute(select(Intel).where(Intel.kind == kind, Intel.key == key)).scalars().first()
        if row:
            row.attrs = attrs
        else:
            db.add(Intel(kind=kind, key=key, attrs=attrs))
    db.flush()


def process_alert(db: Session, g: GeneratedAlert) -> Investigation:
    if db.execute(select(Alert).where(Alert.external_id == g.external_id)).scalars().first():
        raise ValueError(f"duplicate alert {g.external_id}")
    upsert_intel(db, g.intel)
    alert = Alert(external_id=g.external_id, alert_type=g.alert_type, payload=g.payload, human_verdict=g.human_verdict,
                  scenario=g.scenario, intel_snapshot=[list(r) for r in g.intel])
    db.add(alert)
    db.flush()

    store = get_store()
    res = triage(g.alert_type, g.payload, make_intel_lookup(db), store.search)

    if res.verdict == "needs_human":
        outcome = "deferred"
    elif res.verdict == g.human_verdict:
        outcome = "agree"
    else:
        outcome = "disagree"
    critical = g.human_verdict == "malicious" and res.verdict == "benign"

    state = ladder.get_state(db, g.alert_type)
    inv = Investigation(
        alert_id=alert.id, alert_type=g.alert_type, provider=res.provider, ai_verdict=res.verdict,
        proposed_verdict=res.proposed_verdict, summary=res.summary, findings=res.findings,
        grading_violations=res.violations, outcome=outcome, critical_miss=critical,
        autonomy_at_time=state.level, action_status="none" if res.verdict == "needs_human" else ACTION_BY_LEVEL[state.level],
        used_precedent=res.used_precedent, steps_used=res.tool_calls, cost_usd=res.cost_usd, latency_ms=res.latency_ms,
    )
    inv.steps = [AuditStep(**s) for s in res.steps]
    db.add(inv)
    db.flush()
    ladder.evaluate(db, g.alert_type, critical_miss_now=critical)
    return inv


def correct(db: Session, investigation_id: int, verdict: str, note: str = "") -> Correction:
    if verdict not in ("malicious", "benign"):
        raise ValueError("corrected verdict must be malicious or benign")
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise LookupError("investigation not found")
    alert = inv.alert
    sig = Toolbox(alert.alert_type, alert.payload, snapshot_lookup(alert.intel_snapshot)).signature()
    c = Correction(investigation_id=inv.id, alert_type=alert.alert_type, signature=sig, corrected_verdict=verdict, note=note[:500])
    db.add(c)
    inv.corrected = True
    db.flush()
    get_store().add(c.id, c.alert_type, sig, verdict, c.note)
    return c


def rebuild_memory(db: Session) -> int:
    store = get_store()
    if hasattr(store, "items"):
        store.clear()
        rows = db.execute(select(Correction).order_by(Correction.id)).scalars().all()
        for c in rows:
            store.add(c.id, c.alert_type, c.signature, c.corrected_verdict, c.note)
        return len(rows)
    return 0


def export_regressions(db: Session, path: Path) -> int:
    """Each analyst correction becomes a permanent test case in the CI eval gate."""
    rows = db.execute(select(Correction).order_by(Correction.id)).scalars().all()
    existing = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                case = json.loads(line)
                existing[case["case_id"]] = case
    for c in rows:
        a = db.get(Investigation, c.investigation_id).alert
        cid = f"{a.external_id}-c{c.id}"
        existing[cid] = {
            "case_id": cid, "alert_type": a.alert_type, "payload": a.payload, "intel": a.intel_snapshot,
            "expected": c.corrected_verdict, "note": c.note, "signature": c.signature,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(v, sort_keys=True) for v in existing.values()) + "\n")
    return len(existing)


def counts(db: Session) -> dict:
    return {
        "alerts": db.scalar(select(func.count(Alert.id))) or 0,
        "corrections": db.scalar(select(func.count(Correction.id))) or 0,
    }
