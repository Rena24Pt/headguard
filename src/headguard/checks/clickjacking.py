"""Clickjacking protection: CSP frame-ancestors and X-Frame-Options.

If any site can embed your pages in an invisible iframe, it can trick
users into clicking your buttons while they think they are clicking
something else (clickjacking / UI redressing). The modern control is the
CSP ``frame-ancestors`` directive; ``X-Frame-Options`` is its legacy
equivalent and still worth sending for older browsers.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status
from .csp import parse_policy

HEADER = "X-Frame-Options"
MAX_SCORE = 10


def check(ctx: ScanContext) -> list[Finding]:
    csp_value = ctx.headers.get("content-security-policy")
    if csp_value and "frame-ancestors" in parse_policy(csp_value):
        return [
            Finding(
                "CSP frame-ancestors", Status.OK, MAX_SCORE, MAX_SCORE,
                "Framing is restricted via the CSP frame-ancestors directive "
                "(supersedes X-Frame-Options in modern browsers).",
            )
        ]

    value = ctx.headers.get("x-frame-options")
    if value is None:
        return [
            Finding(
                HEADER, Status.MISSING, 0, MAX_SCORE,
                "Header not present and no CSP frame-ancestors directive found.",
                recommendation=(
                    "Add 'X-Frame-Options: DENY' (or CSP \"frame-ancestors 'none'\") so other "
                    "sites cannot embed your pages in an iframe and trick users into "
                    "clicking on them (clickjacking)."
                ),
            )
        ]

    normalized = value.strip().upper()
    if normalized in ("DENY", "SAMEORIGIN"):
        return [Finding(HEADER, Status.OK, MAX_SCORE, MAX_SCORE, f"Set to {normalized}.", value=value)]

    if normalized.startswith("ALLOW-FROM"):
        return [
            Finding(
                HEADER, Status.WARN, 3, MAX_SCORE,
                "ALLOW-FROM is deprecated and ignored by modern browsers, leaving the page frameable.",
                value=value,
                recommendation="Use CSP 'frame-ancestors' to allow specific origins instead.",
            )
        ]

    return [
        Finding(
            HEADER, Status.WARN, 3, MAX_SCORE,
            "Unrecognized value; browsers may ignore it.",
            value=value,
            recommendation="Use DENY or SAMEORIGIN.",
        )
    ]
