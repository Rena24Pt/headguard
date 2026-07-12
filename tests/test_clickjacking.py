from headguard.checks import clickjacking
from headguard.models import Status


def test_frame_ancestors_supersedes_xfo(make_ctx):
    (finding,) = clickjacking.check(
        make_ctx({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
    )
    assert finding.status is Status.OK
    assert finding.score == clickjacking.MAX_SCORE
    assert finding.header == "CSP frame-ancestors"


def test_deny_is_ok(make_ctx):
    (finding,) = clickjacking.check(make_ctx({"X-Frame-Options": "DENY"}))
    assert finding.status is Status.OK
    assert finding.score == clickjacking.MAX_SCORE


def test_sameorigin_is_ok_case_insensitive(make_ctx):
    (finding,) = clickjacking.check(make_ctx({"X-Frame-Options": "sameorigin"}))
    assert finding.status is Status.OK


def test_allow_from_is_deprecated(make_ctx):
    (finding,) = clickjacking.check(make_ctx({"X-Frame-Options": "ALLOW-FROM https://a.example"}))
    assert finding.status is Status.WARN
    assert finding.score < clickjacking.MAX_SCORE


def test_nothing_set_is_missing(make_ctx):
    (finding,) = clickjacking.check(make_ctx())
    assert finding.status is Status.MISSING
    assert finding.score == 0
