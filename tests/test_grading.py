from app.agent.executor import Executor
from app.agent.tools import Toolbox
from app.agent.triage import enforce_grading
from app.schemas import Finding, VerdictSubmission
from tests.test_tools import LOGIN


def _ex():
    ex = Executor(Toolbox("login", LOGIN, lambda k, key: None), 10, 1.0)
    ex.call("geo_velocity")  # s1
    return ex


def test_confirmed_without_evidence_is_downgraded_and_defers():
    sub = VerdictSubmission(verdict="malicious", summary="x", findings=[
        Finding(claim="Bad IP", grade="confirmed", evidence_refs=["s99"], weight="supports_malicious")])
    verdict, findings, viol, _ = enforce_grading(sub, _ex())
    assert findings[0]["grade"] == "inferred"
    assert verdict == "needs_human"
    assert len(viol) == 2


def test_confirmed_with_real_evidence_stands():
    sub = VerdictSubmission(verdict="malicious", summary="x", findings=[
        Finding(claim="Impossible travel", grade="confirmed", evidence_refs=["s1"], weight="supports_malicious")])
    verdict, _, viol, _ = enforce_grading(sub, _ex())
    assert verdict == "malicious" and viol == []


def test_benign_against_confirmed_malicious_defers():
    sub = VerdictSubmission(verdict="benign", summary="x", findings=[
        Finding(claim="Impossible travel", grade="confirmed", evidence_refs=["s1"], weight="supports_malicious"),
        Finding(claim="Looks fine", grade="confirmed", evidence_refs=["s1"], weight="supports_benign")])
    verdict, _, _, _ = enforce_grading(sub, _ex())
    assert verdict == "needs_human"
