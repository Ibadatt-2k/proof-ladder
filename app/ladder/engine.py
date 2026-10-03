"""Trust ladder: autonomy is earned per alert type with evidence, and lost automatically.

Levels (mirroring how agentic SOC platforms expose autonomy):
  assisted   : AI investigates and recommends, a human approves every action
  ai_led     : AI drafts the response, a human signs off
  autonomous : AI acts within design-time gates, actions are reversible

Promotions are RECOMMENDED with an evidence report and need a human approval.
Demotions are applied immediately, because failing safe should not wait for a meeting.
"""
from dataclasses import asdict, dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import Investigation, LadderEvent, LadderState, utcnow
from app.ladder.stats import wilson_lower_bound

LEVELS = ["assisted", "ai_led", "autonomous"]
WINDOW = 1000  # most recent investigations considered

# Criteria to hold each level. Demotion uses the same metrics with a small hysteresis margin.
CRITERIA = {
    "ai_led": {"min_decided": 200, "min_lb": 0.95, "max_critical_misses": 0, "max_deferral_rate": 0.20},
    "autonomous": {"min_decided": 500, "min_lb": 0.98, "max_critical_misses": 0, "max_deferral_rate": 0.10},
}
HYSTERESIS = 0.02


@dataclass
class Metrics:
    alert_type: str
    total: int
    decided: int
    agree: int
    disagree: int
    deferred: int
    critical_misses: int
    false_alarms: int
    agreement_rate: float
    wilson_lb: float
    deferral_rate: float
    grading_violation_rate: float
    precedent_rate: float
    avg_cost_usd: float
    p50_latency_ms: float


def compute_metrics(db: Session, alert_type: str, window: int = WINDOW) -> Metrics:
    rows = db.execute(
        select(Investigation).where(Investigation.alert_type == alert_type).order_by(Investigation.id.desc()).limit(window)
    ).scalars().all()
    total = len(rows)
    agree = sum(r.outcome == "agree" for r in rows)
    disagree = sum(r.outcome == "disagree" for r in rows)
    deferred = sum(r.outcome == "deferred" for r in rows)
    decided = agree + disagree
    crit = sum(r.critical_miss for r in rows)
    fa = sum(r.outcome == "disagree" and not r.critical_miss for r in rows)
    lat = sorted(r.latency_ms for r in rows)
    return Metrics(
        alert_type=alert_type, total=total, decided=decided, agree=agree, disagree=disagree, deferred=deferred,
        critical_misses=crit, false_alarms=fa,
        agreement_rate=round(agree / decided, 4) if decided else 0.0,
        wilson_lb=round(wilson_lower_bound(agree, decided), 4),
        deferral_rate=round(deferred / total, 4) if total else 0.0,
        grading_violation_rate=round(sum(bool(r.grading_violations) for r in rows) / total, 4) if total else 0.0,
        precedent_rate=round(sum(r.used_precedent for r in rows) / total, 4) if total else 0.0,
        avg_cost_usd=round(sum(r.cost_usd for r in rows) / total, 6) if total else 0.0,
        p50_latency_ms=lat[len(lat) // 2] if lat else 0.0,
    )


def meets(m: Metrics, level: str, margin: float = 0.0) -> tuple[bool, list[str]]:
    c = CRITERIA[level]
    reasons = []
    if m.decided < c["min_decided"]:
        reasons.append(f"needs {c['min_decided']} decided alerts, has {m.decided}")
    if m.wilson_lb < c["min_lb"] - margin:
        reasons.append(f"agreement lower bound {m.wilson_lb:.3f} below {c['min_lb'] - margin:.3f}")
    if m.critical_misses > c["max_critical_misses"]:
        reasons.append(f"{m.critical_misses} critical miss(es) in window")
    if m.deferral_rate > c["max_deferral_rate"] + margin:
        reasons.append(f"deferral rate {m.deferral_rate:.2%} above {c['max_deferral_rate'] + margin:.0%}")
    return (not reasons), reasons


def get_state(db: Session, alert_type: str) -> LadderState:
    st = db.get(LadderState, alert_type)
    if not st:
        st = LadderState(alert_type=alert_type, level="assisted", recommendation="")
        db.add(st)
        db.flush()
    return st


def evaluate(db: Session, alert_type: str, critical_miss_now: bool = False) -> LadderState:
    st = get_state(db, alert_type)
    m = compute_metrics(db, alert_type)
    idx = LEVELS.index(st.level)
    evidence = asdict(m)

    # Demotion: immediate on a critical miss above assisted, or when the current level's criteria fail.
    if idx > 0:
        ok, reasons = meets(m, st.level, margin=HYSTERESIS)
        if critical_miss_now or not ok:
            new = LEVELS[idx - 1]
            reason = "Critical miss: AI called a real threat benign." if critical_miss_now else "; ".join(reasons)
            db.add(LadderEvent(alert_type=alert_type, event="demote", from_level=st.level, to_level=new, reason=reason, evidence=evidence))
            st.level, st.recommendation, st.updated_at = new, "", utcnow()
            return st

    # Promotion recommendation.
    if idx < len(LEVELS) - 1:
        nxt = LEVELS[idx + 1]
        ok, reasons = meets(m, nxt)
        if ok and st.recommendation != nxt:
            db.add(LadderEvent(alert_type=alert_type, event="recommend", from_level=st.level, to_level=nxt,
                               reason=f"All {nxt} criteria met on the last {m.total} alerts.", evidence=evidence))
            st.recommendation = nxt
        elif not ok and st.recommendation:
            st.recommendation = ""
    return st


def approve(db: Session, alert_type: str, actor: str = "analyst") -> LadderState:
    st = get_state(db, alert_type)
    if not st.recommendation:
        raise ValueError("no promotion is currently recommended")
    m = compute_metrics(db, alert_type)
    ok, reasons = meets(m, st.recommendation)
    if not ok:
        st.recommendation = ""
        raise ValueError("criteria no longer met: " + "; ".join(reasons))
    db.add(LadderEvent(alert_type=alert_type, event="promote", from_level=st.level, to_level=st.recommendation,
                       reason="Approved by human with evidence report.", evidence=asdict(m), actor=actor))
    st.level, st.recommendation, st.updated_at = st.recommendation, "", utcnow()
    return st
