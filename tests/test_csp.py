from headguard.checks import csp
from headguard.models import Status


def test_missing_policy(make_ctx):
    (finding,) = csp.check(make_ctx())
    assert finding.status is Status.MISSING
    assert finding.score == 0


def test_report_only_gets_minimal_credit(make_ctx):
    (finding,) = csp.check(
        make_ctx({"Content-Security-Policy-Report-Only": "default-src 'self'"})
    )
    assert finding.status is Status.WARN
    assert 0 < finding.score < csp.MAX_SCORE


def test_unsafe_inline_is_flagged(make_ctx):
    (finding,) = csp.check(
        make_ctx({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"})
    )
    assert finding.status is Status.WARN
    assert "nonce" in finding.recommendation


def test_unsafe_inline_with_nonce_is_not_flagged(make_ctx):
    # With a nonce present, modern browsers ignore 'unsafe-inline', so it is
    # a legitimate backwards-compatibility fallback rather than a weakness.
    (finding,) = csp.check(
        make_ctx(
            {"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123' 'unsafe-inline'"}
        )
    )
    assert finding.status is Status.OK
    assert finding.score == csp.MAX_SCORE


def test_wildcard_script_source_is_flagged(make_ctx):
    (finding,) = csp.check(make_ctx({"Content-Security-Policy": "default-src *"}))
    assert finding.status is Status.WARN
    assert finding.score < csp.MAX_SCORE


def test_missing_default_src_is_flagged(make_ctx):
    (finding,) = csp.check(make_ctx({"Content-Security-Policy": "script-src 'self'"}))
    assert finding.status is Status.WARN
    assert "default-src" in finding.recommendation


def test_strict_policy_gets_full_score(make_ctx):
    (finding,) = csp.check(
        make_ctx({"Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'"})
    )
    assert finding.status is Status.OK
    assert finding.score == csp.MAX_SCORE


def test_parse_policy():
    policy = csp.parse_policy("default-src 'self'; script-src 'self' cdn.example.com")
    assert policy["default-src"] == ["'self'"]
    assert policy["script-src"] == ["'self'", "cdn.example.com"]
