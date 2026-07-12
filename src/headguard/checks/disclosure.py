"""Information disclosure via response headers.

Headers such as ``Server: nginx/1.18.0`` or ``X-Powered-By: PHP/8.1.2``
tell attackers exactly which software and version you run, letting them
match your stack against known CVEs in seconds. Hiding versions is not a
real defense on its own, but there is no reason to advertise them.
"""

from __future__ import annotations

from ..models import Finding, ScanContext, Status

HEADER = "Information disclosure"
MAX_SCORE = 5

_VERBOSE_HEADERS = {
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
    "x-generator": "X-Generator",
}


def check(ctx: ScanContext) -> list[Finding]:
    leaks: list[str] = []

    server = ctx.headers.get("server")
    if server and any(char.isdigit() for char in server):
        leaks.append(f"Server: {server}")

    for lower_name, display_name in _VERBOSE_HEADERS.items():
        value = ctx.headers.get(lower_name)
        if value:
            leaks.append(f"{display_name}: {value}")

    if not leaks:
        return [
            Finding(
                HEADER, Status.OK, MAX_SCORE, MAX_SCORE,
                "No software version information exposed in response headers.",
            )
        ]

    score = 2 if len(leaks) == 1 else 0
    return [
        Finding(
            HEADER, Status.WARN, score, MAX_SCORE,
            "Response headers reveal server software: " + "; ".join(leaks) + ".",
            recommendation=(
                "Remove these headers or strip the version numbers "
                "(e.g. 'server_tokens off' in nginx, 'ServerTokens Prod' in Apache, "
                "'expose_php = Off' in PHP)."
            ),
        )
    ]
