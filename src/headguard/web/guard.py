"""Server-Side Request Forgery (SSRF) protection for the web API.

The CLI fetches whatever URL its own user types — that user only reaches
what they could already reach. The web API is different: it fetches URLs
on behalf of *remote strangers*, from wherever the server is deployed.
Without a guard, anyone could make the server probe its own network:
``http://127.0.0.1:6379`` (local services), ``http://192.168.1.1``
(internal hosts) or ``http://169.254.169.254/`` (cloud metadata endpoints
that hand out credentials).

Known limitation: the hostname is resolved here and then again by the
HTTP client, so a DNS server switching answers between the two lookups
(DNS rebinding) could slip through. The robust fix — pinning the
connection to the vetted IP — is out of scope for this project.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    """The URL points somewhere the scanner must not be asked to reach."""


def assert_public_http_url(url: str) -> None:
    """Raise UnsafeTargetError unless ``url`` is http(s) to a public address."""
    parsed = urlparse(url if "://" in url else "https://" + url)

    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError(f"only http and https URLs are allowed, not {parsed.scheme}://")

    host = parsed.hostname
    if not host:
        raise UnsafeTargetError("URL has no hostname")

    try:
        resolved = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise UnsafeTargetError(f"could not resolve {host}") from None

    for entry in resolved:
        address = ipaddress.ip_address(entry[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise UnsafeTargetError(
                f"{host} resolves to {address}, which is not a public address"
            )
