"""Permissions-Policy (formerly Feature-Policy).

Switches off powerful browser features — camera, microphone, geolocation,
payment, USB... — that the site does not use. This limits what an attacker
can do even after finding an XSS, and blocks third-party iframes from
using those features silently.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "Permissions-Policy"
MAX_SCORE = 10


def check(ctx: ScanContext) -> list[Finding]:
    value = ctx.headers.get("permissions-policy")

    if value is None:
        return [
            Finding(
                HEADER, Status.MISSING, 0, MAX_SCORE,
                "Header not present.",
                recommendation=(
                    "Add e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()' "
                    "to switch off powerful browser features the site does not use — it limits "
                    "the blast radius of any script that ends up running on your pages."
                ),
            )
        ]

    directive_count = len([p for p in value.split(",") if p.strip()])
    return [
        Finding(
            HEADER, Status.OK, MAX_SCORE, MAX_SCORE,
            f"Present, restricting {directive_count} feature{'s' if directive_count != 1 else ''}.",
            value=value,
        )
    ]
