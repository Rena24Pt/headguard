"""Registry of all header checks, in the order they appear in the report."""

from . import (
    clickjacking,
    content_type,
    cookies,
    cross_origin,
    csp,
    disclosure,
    hsts,
    legacy,
    permissions,
    referrer,
)

ALL_CHECKS = [
    hsts.check,
    csp.check,
    clickjacking.check,
    content_type.check,
    referrer.check,
    permissions.check,
    cross_origin.check,
    cookies.check,
    disclosure.check,
    legacy.check,
]
