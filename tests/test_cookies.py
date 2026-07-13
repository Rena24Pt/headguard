from headguard.checks import cookies
from headguard.models import Status


def test_no_cookies_is_informational(make_ctx):
    (finding,) = cookies.check(make_ctx())
    assert finding.status is Status.INFO
    # A site without cookies has nothing to protect, so it is not penalized.
    assert finding.max_score == 0


def test_hardened_cookie_gets_full_score(make_ctx):
    (finding,) = cookies.check(
        make_ctx(cookies=["session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"])
    )
    assert finding.status is Status.OK
    assert finding.score == cookies.MAX_SCORE


def test_missing_attributes_are_listed(make_ctx):
    (finding,) = cookies.check(make_ctx(cookies=["session=abc; Path=/"]))
    assert finding.status is Status.WARN
    assert finding.score == 0
    for attribute in ("Secure", "HttpOnly", "SameSite"):
        assert attribute in finding.message


def test_samesite_none_is_flagged(make_ctx):
    (finding,) = cookies.check(make_ctx(cookies=["tracker=1; Secure; HttpOnly; SameSite=None"]))
    assert finding.status is Status.WARN


def test_attributes_are_case_insensitive(make_ctx):
    (finding,) = cookies.check(
        make_ctx(cookies=["session=abc; secure; HTTPONLY; samesite=strict"])
    )
    assert finding.status is Status.OK


def test_score_is_proportional_to_hardened_cookies(make_ctx):
    (finding,) = cookies.check(
        make_ctx(cookies=["good=1; Secure; HttpOnly; SameSite=Strict", "bad=2"])
    )
    assert finding.status is Status.WARN
    assert 0 < finding.score < cookies.MAX_SCORE


def test_cookie_values_are_never_echoed(make_ctx):
    (finding,) = cookies.check(make_ctx(cookies=["session=SUPERSECRET; Path=/"]))
    assert "SUPERSECRET" not in finding.message
    assert finding.value is None
