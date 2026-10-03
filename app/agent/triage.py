"""Run one investigation: bounded reasoning, then enforce the evidence-grading contract."""
import time
from dataclasses import dataclass, field

from app.agent.executor import BudgetExceeded, Executor
from app.agent.llm import run_anthropic, run_openai
from app.agent.offline import run_offline
from app.agent.tools import Toolbox
from app.config import Settings, get_settings
from app.schemas import VerdictSubmission


@dataclass
class TriageResult:
    provider: str
    proposed_verdict: str
    verdict: str
    summary: str
    findings: list[dict]
    violations: list[str]
    steps: list[dict]
    used_precedent: bool
    tool_calls: int
    cost_usd: float
    latency_ms: float
    signature: str = ""
    recommended_action: str = ""
    extra: dict = field(default_factory=dict)


def enforce_grading(sub: VerdictSubmission, ex: Executor) -> tuple[str, list[dict], list[str], bool]:
    """Apply the Confirmed / Inferred / Gap rules. Returns (verdict, findings, violations, used_precedent)."""
    violations: list[str] = []
    out: list[dict] = []
    used_precedent = False
    for f in sub.findings:
        d = f.model_dump()
        if d["grade"] == "confirmed":
            valid = [r for r in d["evidence_refs"] if (st := ex.step(r)) and st["kind"] == "tool_call" and st["ok"]]
            if not valid:
                violations.append(f"Confirmed without valid tool evidence, downgraded to inferred: {d['claim'][:80]}")
                d["grade"] = "inferred"
                d["reasoning"] = d.get("reasoning") or "(model claimed confirmation without citing tool output)"
            d["evidence_refs"] = valid or d["evidence_refs"]
        if d["grade"] == "inferred" and not d.get("reasoning"):
            violations.append(f"Inferred finding without reasoning: {d['claim'][:80]}")
            d["reasoning"] = "(none given)"
        for r in d["evidence_refs"]:
            st = ex.step(r)
            if st and st["tool"] == "search_past_corrections" and st["output"].get("matches") and d["weight"] != "neutral":
                used_precedent = True
        out.append(d)

    verdict = sub.verdict
    if verdict in ("malicious", "benign"):
        support = f"supports_{verdict}"
        opposite = "supports_benign" if verdict == "malicious" else "supports_malicious"
        has_confirmed_support = any(d["grade"] == "confirmed" and d["weight"] == support for d in out)
        if not has_confirmed_support and not used_precedent:
            violations.append(f"{verdict} verdict had no confirmed supporting evidence; deferred to a human.")
            verdict = "needs_human"
        elif verdict == "benign" and not used_precedent and any(d["grade"] == "confirmed" and d["weight"] == opposite for d in out):
            violations.append("Benign verdict contradicts confirmed malicious evidence; deferred to a human.")
            verdict = "needs_human"
    return verdict, out, violations, used_precedent


def triage(alert_type: str, payload: dict, intel, memory_search=None, settings: Settings | None = None) -> TriageResult:
    s = settings or get_settings()
    tb = Toolbox(alert_type, payload, intel, memory_search)
    ex = Executor(tb, s.llm_max_steps if s.llm_provider != "offline" else 20, s.llm_max_cost_usd)
    t0 = time.perf_counter()
    violations: list[str] = []
    try:
        if s.llm_provider == "anthropic":
            sub = run_anthropic(alert_type, payload, ex, s)
        elif s.llm_provider == "openai":
            sub = run_openai(alert_type, payload, ex, s)
        else:
            sub = run_offline(alert_type, payload, ex, s.memory_match_threshold)
    except BudgetExceeded as e:
        violations.append(f"Budget exceeded: {e}")
        sub = VerdictSubmission(verdict="needs_human", summary="Investigation stopped at its budget; deferring to an analyst.", findings=[])
    except Exception as e:  # provider failure must fail safe, never fail open
        violations.append(f"Provider error: {type(e).__name__}: {str(e)[:200]}")
        sub = VerdictSubmission(verdict="needs_human", summary="Reasoning provider failed; deferring to an analyst.", findings=[])

    verdict, findings, grade_viol, used_precedent = enforce_grading(sub, ex)
    violations += grade_viol
    ex.note("verdict", {"proposed": sub.verdict, "final": verdict, "summary": sub.summary, "violations": violations})
    return TriageResult(
        provider=s.llm_provider, proposed_verdict=sub.verdict, verdict=verdict, summary=sub.summary,
        findings=findings, violations=violations, steps=ex.steps, used_precedent=used_precedent,
        tool_calls=ex.tool_calls, cost_usd=round(ex.cost_usd, 6), latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        signature=tb.signature(), recommended_action=sub.recommended_action,
    )
