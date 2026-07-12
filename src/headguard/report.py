"""Human-friendly terminal report and JSON serialization."""

from __future__ import annotations

import json

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .grading import GRADE_STYLES
from .models import ScanResult, Status

_STATUS_STYLES = {
    Status.OK: ("OK", "green"),
    Status.WARN: ("WARN", "yellow"),
    Status.MISSING: ("MISSING", "red"),
    Status.INFO: ("INFO", "cyan"),
}

_MAX_VALUE_LEN = 100


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    grade_style = GRADE_STYLES.get(result.grade, "white")

    console.print(
        Panel(
            f"[bold]{escape(result.final_url)}[/bold]\n"
            f"Grade: [{grade_style}]{result.grade}[/{grade_style}]   "
            f"Score: {result.score}/{result.max_score}   "
            f"HTTP {result.status_code}",
            title="headguard",
            expand=False,
        )
    )

    table = Table(pad_edge=False)
    table.add_column("Header", style="bold", no_wrap=True)
    table.add_column("Result", no_wrap=True)
    table.add_column("Details", overflow="fold")

    for finding in result.findings:
        label, color = _STATUS_STYLES[finding.status]
        details = escape(finding.message)
        if finding.value:
            shown = finding.value
            if len(shown) > _MAX_VALUE_LEN:
                shown = shown[:_MAX_VALUE_LEN] + "..."
            details += f"\n[dim]{escape(shown)}[/dim]"
        table.add_row(finding.header, f"[{color}]{label}[/{color}]", details)

    console.print(table)

    recommendations = [f for f in result.findings if f.recommendation]
    if recommendations:
        console.print("\n[bold]Recommendations[/bold]")
        for index, finding in enumerate(recommendations, 1):
            console.print(f"  {index}. [bold]{finding.header}[/bold]: {escape(finding.recommendation)}")


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
