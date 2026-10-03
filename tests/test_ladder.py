from app.db import Alert, Investigation, SessionLocal, init_db
from app.ladder import engine as ladder


def _add(db, n, outcome="agree", critical=False, t="phishing", start=0):
    for i in range(n):
        a = Alert(external_id=f"T-{t}-{start + i}", alert_type=t, payload={}, human_verdict="benign", scenario="test", intel_snapshot=[])
        db.add(a)
        db.flush()
        db.add(Investigation(alert_id=a.id, alert_type=t, provider="test", ai_verdict="benign", proposed_verdict="benign",
                             outcome=outcome, critical_miss=critical, autonomy_at_time="assisted", action_status="shadow"))
    db.flush()


def test_recommend_approve_then_demote_on_critical_miss():
    init_db(drop=True)
    with SessionLocal() as db:
        _add(db, 150)
        assert ladder.evaluate(db, "phishing").recommendation == ""  # not enough data
        _add(db, 150, start=150)
        st = ladder.evaluate(db, "phishing")
        assert st.recommendation == "ai_led"
        st = ladder.approve(db, "phishing")
        assert st.level == "ai_led"
        _add(db, 1, outcome="disagree", critical=True, start=999)
        st = ladder.evaluate(db, "phishing", critical_miss_now=True)
        assert st.level == "assisted"
        events = [e.event for e in db.query(ladder.LadderEvent).filter_by(alert_type="phishing").all()]
        assert events == ["recommend", "promote", "demote"]
