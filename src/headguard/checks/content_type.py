"""X-Content-Type-Options.

Stops browsers from guessing (sniffing) a response's content type.
Without it, a file a user uploaded as an "image" or a JSON API response
can be reinterpreted as HTML or script and executed in your origin.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "X-Content-Type-Options"
MAX_SCORE = 10


def check(ctx: ScanContext) -> list[Finding]:
    value = ctx.headers.get("x-content-type-options")

    if value is None:
        return [
            Finding(
                HEADER, Status.MISSING, 0, MAX_SCORE,
                "Header not present.",
                recommendation=(
                    "Add 'X-Content-Type-Options: nosniff' so browsers never reinterpret "
                    "responses as a different content type (e.g. an uploaded 'image' "
                    "executing as HTML)."
                ),
            )
        ]

    if value.strip().lower() == "nosniff":
        return [Finding(HEADER, Status.OK, MAX_SCORE, MAX_SCORE, "Set to nosniff.", value=value)]

    return [
        Finding(
            HEADER, Status.WARN, 3, MAX_SCORE,
            "Value is not 'nosniff'; browsers ignore anything else.",
            value=value,
            recommendation="The only valid value is 'nosniff'.",
        )
    ]
