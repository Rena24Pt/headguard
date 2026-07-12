"""Map a raw score onto a letter grade."""

from __future__ import annotations

_THRESHOLDS: list[tuple[int, str]] = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (25, "E"),
    (0, "F"),
]

# Worst to best, used to compare grades for --min-grade.
GRADE_ORDER = ["F", "E", "D", "C", "B", "A", "A+"]

GRADE_STYLES = {
    "A+": "bold green",
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "D": "orange_red1",
    "E": "red",
    "F": "bold red",
}


def grade_for(score: int, max_score: int) -> str:
    percent = 100 * score / max_score if max_score else 0
    for threshold, grade in _THRESHOLDS:
        if percent >= threshold:
            return grade
    return "F"


def meets(grade: str, minimum: str) -> bool:
    return GRADE_ORDER.index(grade) >= GRADE_ORDER.index(minimum)
