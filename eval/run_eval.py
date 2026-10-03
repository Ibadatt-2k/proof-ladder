"""Offline evaluation gate.

Runs the agent over a fixed holdout of synthetic alerts (no database, no network
when LLM_PROVIDER=offline), with the analyst-corrections memory loaded from the
regression suite, and fails the build if any threshold in eval/thresholds.json
is violated. Writes eval/report.json for the CI artifact.

  python -m eval.run_eval --n 600
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from app.agent.triage import triage
from app.config import get_settings
from app.data.stream import alert_stream
from app.ladder.stats import wilson_lower_bound
from app.memory.store import LocalStore
from app.pipeline import snapshot_lookup

ROOT = Path(__file__).parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--seed", type=int, default=20261002)
    ap.add_argument("--no-memory", action="store_true", help="evaluate without analyst corrections")
    args = ap.parse_args()

    store = LocalStore()
    cases_file = ROOT.parent / "tests" / "regression" / "cases.jsonl"
    if not args.no_memory and cases_file.exists():
        for i, line in enumerate(l for l in cases_file.read_text().splitlines() if l.strip()):
            c = json.loads(line)
            store.add(i + 1, c["alert_type"], c["signature"], c["expected"], c.get("note", ""))

    stats = defaultdict(lambda: defaultdict(int))
    for g in alert_stream(args.n, ["phishing", "login"], seed=args.seed):
        r = triage(g.alert_type, g.payload, snapshot_lookup([list(x) for x in g.intel]), store.search)
        s = stats[g.alert_type]
        s["total"] += 1
        s["cost"] += r.cost_usd
        s["violations"] += bool(r.violations)
        if r.verdict == "needs_human":
            s["deferred"] += 1
        elif r.verdict == g.human_verdict:
            s["agree"] += 1
        else:
            s["disagree"] += 1
            s["critical_misses"] += g.human_verdict == "malicious"
            s[f"miss:{g.scenario}"] += 1

    thresholds = json.loads((ROOT / "thresholds.json").read_text())
    report, failed = {"provider": get_settings().llm_provider, "n": args.n, "memory_cases": len(store.items), "types": {}}, []
    for t, s in stats.items():
        decided = s["agree"] + s["disagree"]
        m = {
            "total": s["total"], "agreement": round(s["agree"] / decided, 4) if decided else 0.0,
            "wilson_lb": round(wilson_lower_bound(s["agree"], decided), 4),
            "deferral_rate": round(s["deferred"] / s["total"], 4), "critical_misses": s["critical_misses"],
            "grading_violation_rate": round(s["violations"] / s["total"], 4), "avg_cost_usd": round(s["cost"] / s["total"], 6),
            "misses_by_scenario": {k[5:]: v for k, v in s.items() if k.startswith("miss:")},
        }
        th = thresholds[t]
        checks = {
            "critical_misses": m["critical_misses"] <= th["max_critical_misses"],
            "agreement": m["agreement"] >= th["min_agreement"],
            "deferral_rate": m["deferral_rate"] <= th["max_deferral_rate"],
            "grading_violation_rate": m["grading_violation_rate"] <= th["max_grading_violation_rate"],
        }
        m["checks"] = checks
        failed += [f"{t}.{k}" for k, ok in checks.items() if not ok]
        report["types"][t] = m

    report["passed"] = not failed
    report["failed_checks"] = failed
    (ROOT / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
