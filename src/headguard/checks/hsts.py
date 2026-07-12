"""Strict-Transport-Security (HSTS).

Tells browsers to only ever contact the site over HTTPS. Without it, a
network attacker can hold a user on plain HTTP after their first request
(SSL stripping) and read or rewrite everything they send.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "Strict-Transport-Security"
MAX_SCORE = 20

# Browsers require at least ~6 months before accepting a site on the preload list.
SIX_MONTHS = 15_552_000


def check(ctx: ScanContext) -> list[Finding]:
    value = ctx.headers.get("strict-transport-security")

    if value is None:
        recommendation = (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'. "
            "Without HSTS, a network attacker can keep users on plain HTTP "
            "(SSL stripping) and intercept all their traffic."
        )
        if not ctx.is_https:
            recommendation = "Serve the site over HTTPS first, then " + recommendation
        return [
            Finding(
                HEADER, Status.MISSING, 0, MAX_SCORE,
                "Header not present.",
                recommendation=recommendation,
            )
        ]

    directives = [d.strip().lower() for d in value.split(";") if d.strip()]
    max_age: int | None = None
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1].strip('"'))
            except ValueError:
                max_age = None
            break

    if max_age is None:
        return [
            Finding(
                HEADER, Status.WARN, 0, MAX_SCORE,
                "No valid max-age directive; browsers ignore the header entirely.",
                value=value,
                recommendation="Set 'max-age=31536000' (one year).",
            )
        ]

    if max_age == 0:
        return [
            Finding(
                HEADER, Status.WARN, 0, MAX_SCORE,
                "max-age=0 tells browsers to forget the site's HSTS state, disabling the protection.",
                value=value,
                recommendation="Set 'max-age=31536000' (one year) unless you are deliberately rolling HSTS back.",
            )
        ]

    if max_age < SIX_MONTHS:
        return [
            Finding(
                HEADER, Status.WARN, 10, MAX_SCORE,
                f"max-age is only {max_age} seconds (less than 6 months), so the protection expires quickly.",
                value=value,
                recommendation="Raise max-age to at least 15552000 (6 months); one year is the common choice.",
            )
        ]

    extras = [d for d in ("includesubdomains", "preload") if d in directives]
    message = f"Enforced for {max_age} seconds"
    if extras:
        message += " with " + " and ".join(extras)
    message += "."
    return [Finding(HEADER, Status.OK, MAX_SCORE, MAX_SCORE, message, value=value)]
