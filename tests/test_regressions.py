"""Every analyst correction is a permanent test: a fixed mistake must stay fixed.

CI runs this on every change to prompts, tools, providers or rules.
"""
import json
from pathlib import Path

import pytest

from app.agent.triage import triage
from app.config import Settings
from app.memory.store import LocalStore
from app.pipeline import snapshot_lookup

CASES_FILE = Path(__file__).parent / "regression" / "cases.jsonl"
CASES = [json.loads(line) for line in CASES_FILE.read_text().splitlines() if line.strip()] if CASES_FILE.exists() else []


@pytest.fixture(scope="module")
def memory():
    store = LocalStore()
    for i, c in enumerate(CASES, 1):
        store.add(i, c["alert_type"], c["signature"], c["expected"], c.get("note", ""))
    return store


@pytest.mark.parametrize("case", CASES, ids=[c["case_id"] for c in CASES])
def test_corrected_mistake_stays_fixed(case, memory):
    res = triage(case["alert_type"], case["payload"], snapshot_lookup(case["intel"]), memory.search, Settings(llm_provider="offline"))
    assert res.verdict == case["expected"], f"{case['case_id']}: got {res.verdict}, analyst said {case['expected']} ({case.get('note')})"


def test_precedent_does_not_overgeneralize(memory):
    """An attacker egressing through the same VPN on a NEW device must not inherit the benign precedent."""
    vpn = next((c for c in CASES if "corporate_vpn" in c["signature"]), None)
    if not vpn:
        pytest.skip("no VPN correction in suite")
    payload = {**vpn["payload"], "device_id": "dev-attacker1", "mfa_result": "push_fatigue_pass"}
    res = triage("login", payload, snapshot_lookup(vpn["intel"]), memory.search, Settings(llm_provider="offline"))
    assert not res.used_precedent
    assert res.verdict == "malicious"
