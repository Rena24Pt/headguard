import pytest
from fastapi.testclient import TestClient

from headguard.models import ScanResult
from headguard.web.app import SECURITY_HEADERS, app
from headguard.web.guard import UnsafeTargetError, assert_public_http_url

client = TestClient(app)


# --- SSRF guard ---------------------------------------------------------
# IP literals are used so these tests never depend on DNS.

def test_guard_allows_public_address():
    assert_public_http_url("http://1.1.1.1")


def test_guard_rejects_loopback():
    with pytest.raises(UnsafeTargetError):
        assert_public_http_url("http://127.0.0.1/admin")


def test_guard_rejects_private_ranges():
    for address in ("http://10.0.0.1", "http://172.16.0.1", "http://192.168.1.1"):
        with pytest.raises(UnsafeTargetError):
            assert_public_http_url(address)


def test_guard_rejects_cloud_metadata_endpoint():
    with pytest.raises(UnsafeTargetError):
        assert_public_http_url("http://169.254.169.254/latest/meta-data/")


def test_guard_rejects_localhost_hostname():
    with pytest.raises(UnsafeTargetError):
        assert_public_http_url("http://localhost:6379")


def test_guard_rejects_non_http_schemes():
    with pytest.raises(UnsafeTargetError):
        assert_public_http_url("ftp://example.com")
    with pytest.raises(UnsafeTargetError):
        assert_public_http_url("file:///etc/passwd")


# --- API ----------------------------------------------------------------

def test_index_serves_page_with_its_own_security_headers():
    response = client.get("/")
    assert response.status_code == 200
    for name in SECURITY_HEADERS:
        assert name in response.headers, f"app does not send {name}"


def test_api_scan_rejects_private_target_with_400():
    response = client.get("/api/scan", params={"url": "http://192.168.1.1"})
    assert response.status_code == 400
    assert "public" in response.json()["detail"]


def test_api_scan_returns_scanner_output(monkeypatch):
    fake = ScanResult(url="https://x.test", final_url="https://x.test", status_code=200)
    monkeypatch.setattr("headguard.web.app.scan", lambda url, timeout: fake)

    # 1.1.1.1 passes the SSRF guard without needing DNS.
    response = client.get("/api/scan", params={"url": "http://1.1.1.1"})
    assert response.status_code == 200
    data = response.json()
    assert data["final_url"] == "https://x.test"
    assert "grade" in data
