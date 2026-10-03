"""Replay a synthetic SIEM feed through the agent in shadow mode.

  python -m scripts.replay --n 800 --reset
"""
import argparse
from collections import Counter

from sqlalchemy import func, select

from app.data.stream import alert_stream
from app.db import Alert, Investigation, SessionLocal, init_db
from app.ladder.engine import compute_metrics, get_state
from app.memory.store import get_store
from app.pipeline import process_alert, rebuild_memory


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=800)
    ap.add_argument("--types", default="phishing,login")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()

    init_db(drop=args.reset)
    if args.reset:
        get_store().clear()  # keep the vector store in sync with the wiped database (matters for Qdrant)
    types = args.types.split(",")
    with SessionLocal() as db:
        rebuild_memory(db)
        start = (db.scalar(select(func.max(Alert.id))) or 0) + 1
        for g in alert_stream(args.n, types, seed=args.seed + start, start_idx=start):
            process_alert(db, g)
        db.commit()

        for t in types:
            m = compute_metrics(db, t)
            st = get_state(db, t)
            print(f"\n[{t}] level={st.level} recommend={st.recommendation or '-'}")
            print(f"  total={m.total} decided={m.decided} agree={m.agreement_rate:.3f} lb={m.wilson_lb:.3f} "
                  f"deferred={m.deferral_rate:.1%} critical_misses={m.critical_misses} false_alarms={m.false_alarms}")
            rows = db.execute(select(Alert.scenario, Investigation.outcome).join(Investigation).where(Alert.alert_type == t)).all()
            by = Counter((s, o) for s, o in rows)
            for s in sorted({s for s, _ in rows}):
                print(f"    {s:30s} agree={by[(s, 'agree')]:4d} disagree={by[(s, 'disagree')]:3d} deferred={by[(s, 'deferred')]:3d}")
        db.commit()


if __name__ == "__main__":
    main()
