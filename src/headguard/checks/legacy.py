"""Deprecated security headers that should be removed, not added.

These findings never affect the score (max_score = 0); they exist to
teach that some once-recommended headers are now useless or harmful.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

_LEGACY = {
    "x-xss-protection": (
        "X-XSS-Protection",
        "The browser XSS auditor this header controlled was removed from modern browsers, "
        "and in old ones '1; mode=block' could be abused for cross-site leaks. "
        "Remove the header or set it to '0'.",
    ),
    "expect-ct": (
        "Expect-CT",
        "Certificate Transparency has been enforced by default since 2021; the header is "
        "deprecated and can be removed.",
    ),
    "public-key-pins": (
        "Public-Key-Pins",
        "HPKP was abandoned by browsers because a misconfiguration could lock users out of "
        "a domain for months. Remove it.",
    ),
}


def check(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    for lower_name, (display_name, advice) in _LEGACY.items():
        value = ctx.headers.get(lower_name)
        if value is None:
            continue
        # 'X-XSS-Protection: 0' is the one recommended form: it explicitly
        # disables the legacy auditor.
        if lower_name == "x-xss-protection" and value.strip() == "0":
            continue
        findings.append(
            Finding(
                display_name, Status.WARN, 0, 0,
                "Deprecated header present.",
                value=value,
                recommendation=advice,
            )
        )
    return findings
