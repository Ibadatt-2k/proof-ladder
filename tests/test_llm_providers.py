"""Exercise both LLM wire formats against a mocked API, including the grading contract."""
import json

import httpx
import pytest

from app.agent import llm
from app.agent.triage import triage
from app.config import Settings
from tests.test_tools import LOGIN


def _patch(monkeypatch, handler):
    real = httpx.Client
    monkeypatch.setattr(llm.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))


VERDICT = {"verdict": "malicious", "summary": "Impossible travel.", "findings": [
    {"claim": "Impossible travel Vancouver to Frankfurt", "grade": "confirmed", "evidence_refs": ["s1"], "weight": "supports_malicious"},
    {"claim": "Made-up fact", "grade": "confirmed", "evidence_refs": [], "weight": "supports_malicious"},
]}


def test_openai_compatible_loop(monkeypatch):
    calls = []

    def handler(req):
        body = json.loads(req.content)
        calls.append(body)
        if len(calls) == 1:
            msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "geo_velocity", "arguments": "{}"}}]}
        else:
            assert body["messages"][-1]["role"] == "tool"
            msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c2", "type": "function", "function": {"name": "submit_verdict", "arguments": json.dumps(VERDICT)}}]}
        return httpx.Response(200, json={"choices": [{"message": msg}], "usage": {"prompt_tokens": 1000, "completion_tokens": 200}})

    _patch(monkeypatch, handler)
    s = Settings(llm_provider="openai", llm_model="test", llm_api_key="k", llm_price_in_per_mtok=1, llm_price_out_per_mtok=5)
    res = triage("login", LOGIN, lambda k, key: None, None, s)
    assert res.verdict == "malicious"
    assert res.findings[1]["grade"] == "inferred"  # unsupported "confirmed" was downgraded
    assert res.cost_usd == pytest.approx(2 * (1000 * 1 + 200 * 5) / 1e6)


def test_anthropic_loop(monkeypatch):
    n = {"i": 0}

    def handler(req):
        n["i"] += 1
        if n["i"] == 1:
            content = [{"type": "text", "text": "Checking travel."}, {"type": "tool_use", "id": "t1", "name": "geo_velocity", "input": {}}]
        else:
            # s1 is the model's text (reasoning), so the tool output it must cite is s2.
            v = json.loads(json.dumps(VERDICT).replace('"s1"', '"s2"'))
            content = [{"type": "tool_use", "id": "t2", "name": "submit_verdict", "input": v}]
        return httpx.Response(200, json={"content": content, "stop_reason": "tool_use", "usage": {"input_tokens": 10, "output_tokens": 10}})

    _patch(monkeypatch, handler)
    res = triage("login", LOGIN, lambda k, key: None, None, Settings(llm_provider="anthropic", llm_model="test", llm_api_key="k"))
    assert res.verdict == "malicious"
    assert any(s["kind"] == "reasoning" for s in res.steps)


def test_provider_failure_fails_safe(monkeypatch):
    _patch(monkeypatch, lambda req: httpx.Response(500, json={"error": "boom"}))
    res = triage("login", LOGIN, lambda k, key: None, None, Settings(llm_provider="openai", llm_model="test"))
    assert res.verdict == "needs_human"
    assert any("Provider error" in v for v in res.violations)


def test_out_of_scope_tool_is_refused(monkeypatch):
    n = {"i": 0}

    def handler(req):
        n["i"] += 1
        name, args = ("inspect_attachments", "{}") if n["i"] == 1 else ("submit_verdict", json.dumps({**VERDICT, "findings": VERDICT["findings"][:1]}))
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "tool_calls": [{"id": f"c{n['i']}", "type": "function", "function": {"name": name, "arguments": args}}]}}]})

    _patch(monkeypatch, handler)
    res = triage("login", LOGIN, lambda k, key: None, None, Settings(llm_provider="openai", llm_model="test"))
    assert res.steps[0]["ok"] is False and "outside the allowed scope" in res.steps[0]["output"]["error"]
    assert res.verdict == "needs_human"  # its only "confirmed" evidence pointed at a failed step
