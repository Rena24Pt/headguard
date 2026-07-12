"""Referrer-Policy.

Controls how much of the current URL is sent in the Referer header when
the user navigates away or the page loads third-party resources. Full
URLs can leak private paths, search queries and even tokens to other
sites and analytics providers.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "Referrer-Policy"
MAX_SCORE = 10

STRONG = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
WEAK = {"origin", "origin-when-cross-origin", "no-referrer-when-downgrade"}
LEAKY = {"unsafe-url"}


def check(ctx: ScanContext) -> list[Finding]:
    value = ctx.headers.get("referrer-policy")

    if value is None:
        return [
            Finding(
                HEADER, Status.MISSING, 0, MAX_SCORE,
                "Header not present; browsers fall back to their default policy.",
                recommendation=(
                    "Add 'Referrer-Policy: strict-origin-when-cross-origin'. Modern browsers "
                    "already default to it, but setting it explicitly protects users of older "
                    "browsers and documents your intent."
                ),
            )
        ]

    # The header may carry a comma-separated fallback list; per spec, the
    # last policy the browser recognizes wins.
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = next((t for t in reversed(tokens) if t in STRONG | WEAK | LEAKY), None)

    if effective in STRONG:
        return [Finding(HEADER, Status.OK, MAX_SCORE, MAX_SCORE, f"Set to {effective}.", value=value)]

    if effective in LEAKY:
        return [
            Finding(
                HEADER, Status.WARN, 0, MAX_SCORE,
                "unsafe-url sends the full URL (path and query included) with every request, "
                "even to plain-HTTP destinations.",
                value=value,
                recommendation="Use 'strict-origin-when-cross-origin' or stricter.",
            )
        ]

    if effective in WEAK:
        return [
            Finding(
                HEADER, Status.WARN, 5, MAX_SCORE,
                f"'{effective}' can leak the full URL or origin to third parties in some cases.",
                value=value,
                recommendation="Prefer 'strict-origin-when-cross-origin', 'same-origin' or 'no-referrer'.",
            )
        ]

    return [
        Finding(
            HEADER, Status.WARN, 3, MAX_SCORE,
            "No recognized policy token; browsers fall back to their default.",
            value=value,
            recommendation="Use a valid policy such as 'strict-origin-when-cross-origin'.",
        )
    ]
