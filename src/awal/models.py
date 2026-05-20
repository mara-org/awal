from __future__ import annotations

from dataclasses import asdict, dataclass


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_WEIGHT = {
    "low": 3,
    "medium": 8,
    "high": 20,
    "critical": 35,
}


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    severity: str
    category: str
    excerpt: str
    why_it_matters: str
    suggested_review: str
    rule_id: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    status: str
    risk_score: int
    target: str
    summary: dict[str, object]
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "target": self.target,
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
        }
