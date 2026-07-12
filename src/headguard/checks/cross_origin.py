"""Cross-origin isolation: COOP and CORP.

Cross-Origin-Opener-Policy detaches your window from windows opened by
other origins, and Cross-Origin-Resource-Policy stops other origins from
loading your resources into their pages. Together they defend against
cross-window attacks (XS-Leaks, tabnabbing) and Spectre-style
cross-origin memory reads.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

COOP_HEADER = "Cross-Origin-Opener-Policy"
CORP_HEADER = "Cross-Origin-Resource-Policy"
COOP_MAX = 5
CORP_MAX = 5


def check(ctx: ScanContext) -> list[Finding]:
    return [_check_coop(ctx), _check_corp(ctx)]


def _check_coop(ctx: ScanContext) -> Finding:
    value = ctx.headers.get("cross-origin-opener-policy")

    if value is None:
        return Finding(
            COOP_HEADER, Status.MISSING, 0, COOP_MAX,
            "Header not present.",
            recommendation=(
                "Add 'Cross-Origin-Opener-Policy: same-origin' so windows opened from other "
                "origins cannot keep a handle to yours (mitigates XS-Leaks and tabnabbing)."
            ),
        )

    normalized = value.strip().lower()
    if normalized == "same-origin":
        return Finding(COOP_HEADER, Status.OK, COOP_MAX, COOP_MAX, "Set to same-origin.", value=value)

    if normalized == "same-origin-allow-popups":
        return Finding(
            COOP_HEADER, Status.WARN, 3, COOP_MAX,
            "same-origin-allow-popups is weaker than same-origin, but sometimes required "
            "for OAuth or payment popups.",
            value=value,
            recommendation="Use 'same-origin' if the site does not rely on cross-origin popups.",
        )

    return Finding(
        COOP_HEADER, Status.WARN, 0, COOP_MAX,
        "Value does not isolate the browsing context.",
        value=value,
        recommendation="Use 'Cross-Origin-Opener-Policy: same-origin'.",
    )


def _check_corp(ctx: ScanContext) -> Finding:
    value = ctx.headers.get("cross-origin-resource-policy")

    if value is None:
        return Finding(
            CORP_HEADER, Status.MISSING, 0, CORP_MAX,
            "Header not present.",
            recommendation=(
                "Add 'Cross-Origin-Resource-Policy: same-origin' so other origins cannot "
                "embed your resources in their pages (helps against Spectre-style "
                "cross-origin reads)."
            ),
        )

    normalized = value.strip().lower()
    if normalized in ("same-origin", "same-site"):
        return Finding(CORP_HEADER, Status.OK, CORP_MAX, CORP_MAX, f"Set to {normalized}.", value=value)

    if normalized == "cross-origin":
        return Finding(
            CORP_HEADER, Status.WARN, 2, CORP_MAX,
            "cross-origin explicitly allows any origin to embed these resources — fine for "
            "a public CDN, weak for everything else.",
            value=value,
            recommendation="Use 'same-origin' unless the resources are meant to be embedded elsewhere.",
        )

    return Finding(
        CORP_HEADER, Status.WARN, 0, CORP_MAX,
        "Unrecognized value.",
        value=value,
        recommendation="Use one of: same-origin, same-site, cross-origin.",
    )
