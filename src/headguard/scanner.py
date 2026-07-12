"""Fetch a URL and run every header check against the response."""

from __future__ import annotations

import httpx

from . import __version__
from .checks import ALL_CHECKS
from .models import Finding, ScanContext, ScanResult, Status

USER_AGENT = f"headguard/{__version__} (security headers scanner)"


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = True,
    transport: httpx.BaseTransport | None = None,
) -> ScanResult:
    """Request ``url`` (following redirects) and analyze the final response.

    ``transport`` exists so tests can inject an ``httpx.MockTransport``
    instead of hitting the network.
    """
    if "://" not in url:
        url = "https://" + url

    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        verify=verify,
        headers={"User-Agent": USER_AGENT},
        transport=transport,
    ) as client:
        response = client.get(url)

    headers = {name.lower(): value for name, value in response.headers.items()}
    is_https = response.url.scheme == "https"
    ctx = ScanContext(headers=headers, is_https=is_https)

    findings: list[Finding] = []
    if not is_https:
        findings.append(
            Finding(
                "HTTPS", Status.WARN, 0, 0,
                "Final response was served over plain HTTP.",
                recommendation=(
                    "Serve the site over HTTPS; without it, every protection below can be "
                    "stripped by anyone on the network path."
                ),
            )
        )
    elif url.startswith("http://"):
        findings.append(
            Finding("HTTPS", Status.INFO, 0, 0, "HTTP request was redirected to HTTPS.")
        )

    for check in ALL_CHECKS:
        findings.extend(check(ctx))

    return ScanResult(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
    )
