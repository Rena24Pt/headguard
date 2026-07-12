import httpx

from headguard.scanner import scan

HARDENED_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _transport(headers: dict[str, str]) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, headers=headers))


def test_hardened_site_gets_a_plus():
    result = scan("https://example.test", transport=_transport(HARDENED_HEADERS))
    assert result.score == result.max_score
    assert result.grade == "A+"


def test_bare_site_fails():
    result = scan("https://example.test", transport=_transport({}))
    assert result.grade == "F"


def test_scheme_defaults_to_https():
    result = scan("example.test", transport=_transport({}))
    assert result.final_url.startswith("https://")


def test_json_round_trip():
    result = scan("https://example.test", transport=_transport(HARDENED_HEADERS))
    data = result.to_dict()
    assert data["grade"] == "A+"
    assert len(data["findings"]) == len(result.findings)
