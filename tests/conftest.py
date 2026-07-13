import pytest

from headguard.models import ScanContext


@pytest.fixture
def make_ctx():
    """Build a ScanContext from a plain header dict (any key casing)."""

    def _make(
        headers: dict[str, str] | None = None,
        https: bool = True,
        cookies: list[str] | None = None,
    ) -> ScanContext:
        normalized = {k.lower(): v for k, v in (headers or {}).items()}
        return ScanContext(headers=normalized, is_https=https, cookies=list(cookies or []))

    return _make
