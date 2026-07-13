"""Set-Cookie attribute analysis.

A session cookie is a bearer token: whoever holds it *is* the user.
Three attributes decide how easily it can be stolen or abused:

- ``Secure``   — never sent over plain HTTP, so it cannot be sniffed
  off the network.
- ``HttpOnly`` — invisible to JavaScript, so an XSS cannot exfiltrate it.
- ``SameSite`` — withheld on cross-site requests, which blocks CSRF
  (``Lax`` or ``Strict``; ``None`` re-enables cross-site sending).

A response that sets no cookies has nothing to protect, so this check
only contributes to the score when cookies are present.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "Set-Cookie"
MAX_SCORE = 10


def _parse(raw: str) -> tuple[str, dict[str, str]]:
    """Split one Set-Cookie line into (cookie name, {attribute: value})."""
    parts = raw.split(";")
    name = parts[0].split("=", 1)[0].strip()
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip()
    return name, attributes


def check(ctx: ScanContext) -> list[Finding]:
    if not ctx.cookies:
        return [Finding(HEADER, Status.INFO, 0, 0, "No cookies set on this response.")]

    problems: list[str] = []
    hardened = 0
    for raw in ctx.cookies:
        name, attributes = _parse(raw)
        missing: list[str] = []
        if "secure" not in attributes:
            missing.append("Secure")
        if "httponly" not in attributes:
            missing.append("HttpOnly")
        if "samesite" not in attributes:
            missing.append("SameSite")
        elif attributes["samesite"].lower() == "none":
            missing.append("SameSite=Lax/Strict (None explicitly re-enables cross-site sending)")

        if missing:
            problems.append(f"'{name}' lacks {', '.join(missing)}")
        else:
            hardened += 1

    total = len(ctx.cookies)
    plural = "s" if total != 1 else ""

    # Findings never echo cookie values: Set-Cookie lines contain live
    # session tokens, and reports end up in logs and CI output.
    if not problems:
        return [
            Finding(
                HEADER, Status.OK, MAX_SCORE, MAX_SCORE,
                f"All {total} cookie{plural} set Secure, HttpOnly and SameSite.",
            )
        ]

    score = round(MAX_SCORE * hardened / total)
    return [
        Finding(
            HEADER, Status.WARN, score, MAX_SCORE,
            f"{total - hardened} of {total} cookie{plural} lack hardening attributes: "
            + "; ".join(problems) + ".",
            recommendation=(
                "Add 'Secure' (never sent over plain HTTP), 'HttpOnly' (JavaScript cannot "
                "read it, so XSS cannot steal the session) and 'SameSite=Lax' or 'Strict' "
                "(withheld on cross-site requests, blocking CSRF). Use SameSite=None only "
                "for cookies that genuinely must travel cross-site, and always pair it "
                "with Secure."
            ),
        )
    ]
