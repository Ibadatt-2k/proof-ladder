"""LLM reasoning providers: one bounded tool-use loop, two wire formats.

anthropic : Anthropic Messages API (tool use)
openai    : any OpenAI-compatible chat completions endpoint (OpenAI, Gemini's
            OpenAI-compatible endpoint, Ollama, vLLM)
"""
import json

import httpx

from app.agent.executor import BudgetExceeded, Executor
from app.agent.tools import TOOL_SPECS, json_schema_for
from app.config import Settings
from app.schemas import VerdictSubmission

SYSTEM_PROMPT = """You are a tier-2 SOC analyst investigating one {alert_type} alert.
Use the tools to gather evidence. Every tool result comes back with a step_ref such as "s3".
When done, call submit_verdict exactly once.

Grading rules (enforced by software after you submit; violations are logged):
- confirmed: the claim is directly shown by tool output. You MUST list the step_refs.
- inferred: circumstantial; you MUST explain the reasoning.
- gap: you looked and found nothing. Say so instead of guessing.
- A malicious or benign verdict needs at least one confirmed finding supporting it,
  otherwise it is converted to needs_human. If evidence is not decisive, choose needs_human.
- If search_past_corrections returns a match, weigh the analyst precedent heavily and cite it.
Budget: at most {max_steps} tool calls."""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "benign", "needs_human"]},
        "summary": {"type": "string"},
        "recommended_action": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"},
                    "grade": {"type": "string", "enum": ["confirmed", "inferred", "gap"]},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "reasoning": {"type": "string"},
                    "weight": {"type": "string", "enum": ["supports_malicious", "supports_benign", "neutral"]},
                },
                "required": ["claim", "grade", "evidence_refs", "weight"],
            },
        },
    },
    "required": ["verdict", "summary", "findings"],
}


def _user_msg(alert_type: str, payload: dict) -> str:
    return f"Alert type: {alert_type}\nAlert payload:\n{json.dumps(payload, indent=2)}"


def _tool_result(ex: Executor, name: str, args: dict) -> str:
    ref, out = ex.call(name, args)
    return json.dumps({"step_ref": ref, "output": out})


def _price(s: Settings, tin: int, tout: int) -> float:
    return tin * s.llm_price_in_per_mtok / 1e6 + tout * s.llm_price_out_per_mtok / 1e6


def run_anthropic(alert_type: str, payload: dict, ex: Executor, s: Settings) -> VerdictSubmission:
    tools = [{"name": t["name"], "description": t["description"], "input_schema": json_schema_for(t)} for t in TOOL_SPECS[alert_type]]
    tools.append({"name": "submit_verdict", "description": "Submit the final graded verdict.", "input_schema": VERDICT_SCHEMA})
    messages = [{"role": "user", "content": _user_msg(alert_type, payload)}]
    url = (s.llm_base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
    headers = {"x-api-key": s.llm_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    with httpx.Client(timeout=60) as client:
        for _ in range(s.llm_max_steps + 2):
            r = client.post(url, headers=headers, json={
                "model": s.llm_model, "max_tokens": 2000, "tools": tools, "messages": messages,
                "system": SYSTEM_PROMPT.format(alert_type=alert_type, max_steps=s.llm_max_steps),
            })
            r.raise_for_status()
            data = r.json()
            u = data.get("usage", {})
            ex.add_cost(_price(s, u.get("input_tokens", 0), u.get("output_tokens", 0)))
            messages.append({"role": "assistant", "content": data["content"]})
            results = []
            for block in data["content"]:
                if block["type"] == "text" and block["text"].strip():
                    ex.note("reasoning", {"text": block["text"]})
                if block["type"] != "tool_use":
                    continue
                if block["name"] == "submit_verdict":
                    return VerdictSubmission.model_validate(block["input"])
                results.append({"type": "tool_result", "tool_use_id": block["id"], "content": _tool_result(ex, block["name"], block["input"] or {})})
            if not results:
                messages.append({"role": "user", "content": "Call submit_verdict now."})
            else:
                messages.append({"role": "user", "content": results})
    raise BudgetExceeded("model did not submit a verdict within budget")


def run_openai(alert_type: str, payload: dict, ex: Executor, s: Settings) -> VerdictSubmission:
    tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": json_schema_for(t)}} for t in TOOL_SPECS[alert_type]]
    tools.append({"type": "function", "function": {"name": "submit_verdict", "description": "Submit the final graded verdict.", "parameters": VERDICT_SCHEMA}})
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT.format(alert_type=alert_type, max_steps=s.llm_max_steps)},
        {"role": "user", "content": _user_msg(alert_type, payload)},
    ]
    url = (s.llm_base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {s.llm_api_key}"} if s.llm_api_key else {}
    with httpx.Client(timeout=120) as client:
        for _ in range(s.llm_max_steps + 2):
            r = client.post(url, headers=headers, json={"model": s.llm_model, "messages": messages, "tools": tools, "tool_choice": "auto"})
            r.raise_for_status()
            data = r.json()
            u = data.get("usage", {}) or {}
            ex.add_cost(_price(s, u.get("prompt_tokens", 0), u.get("completion_tokens", 0)))
            msg = data["choices"][0]["message"]
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
            if msg.get("content"):
                ex.note("reasoning", {"text": msg["content"]})
            calls = msg.get("tool_calls") or []
            if not calls:
                messages.append({"role": "user", "content": "Call submit_verdict now."})
                continue
            for c in calls:
                name = c["function"]["name"]
                args = json.loads(c["function"].get("arguments") or "{}")
                if name == "submit_verdict":
                    return VerdictSubmission.model_validate(args)
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": _tool_result(ex, name, args)})
    raise BudgetExceeded("model did not submit a verdict within budget")
