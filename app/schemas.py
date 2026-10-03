"""The verdict contract every reasoning provider must satisfy."""
from typing import Literal

from pydantic import BaseModel, Field

Grade = Literal["confirmed", "inferred", "gap"]
Verdict = Literal["malicious", "benign", "needs_human"]


class Finding(BaseModel):
    claim: str = Field(..., description="One factual statement about the alert.")
    grade: Grade = Field(..., description="confirmed = tool output cited; inferred = reasoning shown; gap = looked, found nothing.")
    evidence_refs: list[str] = Field(default_factory=list, description="Audit step refs (e.g. 's2') whose tool output supports the claim.")
    reasoning: str = Field("", description="Required for inferred findings.")
    weight: Literal["supports_malicious", "supports_benign", "neutral"] = "neutral"


class VerdictSubmission(BaseModel):
    verdict: Verdict
    summary: str
    findings: list[Finding]
    recommended_action: str = ""
