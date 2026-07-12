from headguard.checks import hsts
from headguard.models import Status


def test_missing_header_scores_zero(make_ctx):
    (finding,) = hsts.check(make_ctx())
    assert finding.status is Status.MISSING
    assert finding.score == 0
    assert "SSL stripping" in finding.recommendation


def test_short_max_age_gets_partial_credit(make_ctx):
    (finding,) = hsts.check(make_ctx({"Strict-Transport-Security": "max-age=86400"}))
    assert finding.status is Status.WARN
    assert 0 < finding.score < hsts.MAX_SCORE


def test_zero_max_age_disables_protection(make_ctx):
    (finding,) = hsts.check(make_ctx({"Strict-Transport-Security": "max-age=0"}))
    assert finding.status is Status.WARN
    assert finding.score == 0


def test_invalid_max_age_scores_zero(make_ctx):
    (finding,) = hsts.check(make_ctx({"Strict-Transport-Security": "max-age=banana"}))
    assert finding.status is Status.WARN
    assert finding.score == 0


def test_solid_policy_gets_full_score(make_ctx):
    (finding,) = hsts.check(
        make_ctx({"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"})
    )
    assert finding.status is Status.OK
    assert finding.score == hsts.MAX_SCORE
    assert "includesubdomains" in finding.message
    assert "preload" in finding.message
