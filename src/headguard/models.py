"""Core data structures shared by the scanner, the checks and the reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    OK = "ok"            # header present and well configured
    WARN = "warn"        # present, but its value weakens the protection
    MISSING = "missing"  # protection absent
    INFO = "info"        # informational only, never affects the score


@dataclass
class Finding:
    """The outcome of one check against the response headers."""

    header: str
    status: Status
    score: int
    max_score: int
    message: str
    value: str | None = None
    recommendation: str | None = None

    def to_dict(self) -> dict:
        return {
            "header": self.header,
            "status": self.status.value,
            "value": self.value,
            "score": self.score,
            "max_score": self.max_score,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanContext:
    """What a check is allowed to look at.

    ``headers`` uses lowercase keys — HTTP header names are case-insensitive,
    so the scanner normalizes them once instead of every check doing it.
    """

    headers: dict[str, str]
    is_https: bool


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return sum(finding.score for finding in self.findings)

    @property
    def max_score(self) -> int:
        return sum(finding.max_score for finding in self.findings)

    @property
    def grade(self) -> str:
        from .grading import grade_for

        return grade_for(self.score, self.max_score)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "score": self.score,
            "max_score": self.max_score,
            "grade": self.grade,
            "findings": [finding.to_dict() for finding in self.findings],
        }
