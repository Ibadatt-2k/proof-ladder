"""Bounded tool executor: enforces step and cost limits and records the audit trail."""
from app.agent.tools import Toolbox, call_tool


class BudgetExceeded(Exception):
    pass


class Executor:
    def __init__(self, toolbox: Toolbox, max_steps: int, max_cost_usd: float):
        self.tb = toolbox
        self.max_steps = max_steps
        self.max_cost = max_cost_usd
        self.steps: list[dict] = []
        self.tool_calls = 0
        self.cost_usd = 0.0

    def _record(self, kind: str, tool: str, inp: dict, out: dict, ok: bool) -> str:
        ref = f"s{len(self.steps) + 1}"
        self.steps.append({"seq": len(self.steps) + 1, "step_ref": ref, "kind": kind, "tool": tool, "input": inp, "output": out, "ok": ok})
        return ref

    def call(self, name: str, args: dict | None = None) -> tuple[str, dict]:
        args = args or {}
        if self.tool_calls >= self.max_steps:
            raise BudgetExceeded(f"step limit {self.max_steps} reached")
        if self.cost_usd > self.max_cost:
            raise BudgetExceeded(f"cost limit ${self.max_cost} reached")
        self.tool_calls += 1
        try:
            out = call_tool(self.tb, name, args)
            return self._record("tool_call", name, args, out, True), out
        except Exception as e:  # tool errors are evidence too
            return self._record("tool_call", name, args, {"error": str(e)}, False), {"error": str(e)}

    def note(self, kind: str, data: dict) -> str:
        return self._record(kind, "", {}, data, True)

    def add_cost(self, usd: float) -> None:
        self.cost_usd += usd

    def step(self, ref: str) -> dict | None:
        return next((s for s in self.steps if s["step_ref"] == ref), None)
