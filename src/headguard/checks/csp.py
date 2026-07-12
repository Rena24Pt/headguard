"""Content-Security-Policy (CSP).

Restricts where the page may load scripts, styles, frames and other
resources from. A solid CSP is the strongest browser-side containment
for cross-site scripting (XSS): even if an attacker injects markup,
the browser refuses to run code from origins the policy does not allow.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "Content-Security-Policy"
MAX_SCORE = 25


def parse_policy(value: str) -> dict[str, list[str]]:
    """Split a serialized CSP into {directive: [source, ...]}."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check(ctx: ScanContext) -> list[Finding]:
    enforced = ctx.headers.get("content-security-policy")
    report_only = ctx.headers.get("content-security-policy-report-only")

    if enforced is None and report_only is None:
        return [
            Finding(
                HEADER, Status.MISSING, 0, MAX_SCORE,
                "Header not present.",
                recommendation=(
                    "Add a CSP to contain XSS. Even a starter policy such as "
                    "\"default-src 'self'; frame-ancestors 'self'\" limits where "
                    "scripts, styles and frames can come from."
                ),
            )
        ]

    if enforced is None:
        return [
            Finding(
                HEADER, Status.WARN, 5, MAX_SCORE,
                "Only a Report-Only policy is set; violations are reported but nothing is blocked.",
                value=report_only,
                recommendation=(
                    "Report-Only is the right way to test a policy — once the violation "
                    "reports look clean, ship it as the enforcing Content-Security-Policy header."
                ),
            )
        ]

    policy = parse_policy(enforced)
    script_sources = policy.get("script-src", policy.get("default-src", []))
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script_sources
    )

    issues: list[str] = []
    if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
        issues.append(
            "'unsafe-inline' lets injected inline scripts run, which defeats CSP's main "
            "XSS protection — replace it with nonces or hashes"
        )
    if "'unsafe-eval'" in script_sources:
        issues.append(
            "'unsafe-eval' allows eval()-style code execution — remove it or isolate the code that needs it"
        )
    if any(s in ("*", "http:", "https:") for s in script_sources):
        issues.append(
            "a wildcard script source allows scripts from any origin — pin the exact origins you use"
        )
    if "default-src" not in policy:
        issues.append(
            "no default-src fallback, so any resource type not listed explicitly is "
            "unrestricted — add default-src 'self'"
        )

    if issues:
        score = max(MAX_SCORE - 5 * len(issues), 10)
        return [
            Finding(
                HEADER, Status.WARN, score, MAX_SCORE,
                f"Policy present but weakened ({len(issues)} issue{'s' if len(issues) > 1 else ''} found).",
                value=enforced,
                recommendation="; ".join(issues) + ".",
            )
        ]

    return [
        Finding(
            HEADER, Status.OK, MAX_SCORE, MAX_SCORE,
            "Policy present with no common weaknesses detected.",
            value=enforced,
        )
    ]
