"""Pydantic response/request schemas."""
from pydantic import BaseModel


class ScanCreate(BaseModel):
    repo_url: str
    branch: str = "HEAD"


class VerificationOut(BaseModel):
    id: str
    status: str
    rescan_clean: bool
    tests_passed: bool | None
    test_log: str
    notes: str


class PatchOut(BaseModel):
    id: str
    diff: str
    summary: str
    applied: bool
    verifications: list[VerificationOut] = []


class FindingOut(BaseModel):
    id: str
    rule_id: str
    title: str
    cwe: str
    severity: str
    confidence: str
    file_path: str
    line_no: int
    snippet: str
    explanation: str
    risk_score: float
    risk_rationale: str
    reproduced: bool
    repro_log: str
    validated: bool
    false_positive: bool
    patches: list[PatchOut] = []


class EvidenceOut(BaseModel):
    id: str
    stage: str
    actor: str
    message: str
    ref_id: str


class ScanOut(BaseModel):
    id: str
    repo_url: str
    branch: str
    status: str
    error: str
    findings: list[FindingOut] = []
    evidence: list[EvidenceOut] = []
