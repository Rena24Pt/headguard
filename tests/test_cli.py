import json

import httpx
import pytest

from headguard import cli
from headguard.models import Finding, ScanResult, Status


def _result(url: str, score: int = 100) -> ScanResult:
    return ScanResult(
        url=url,
        final_url=url,
        status_code=200,
        findings=[Finding("X", Status.OK, score, 100, "test finding")],
    )


def test_single_url_json_is_an_object(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda url, timeout, verify: _result(url))
    assert cli.main(["https://a.test", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] == "A+"


def test_batch_json_is_an_array(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda url, timeout, verify: _result(url))
    assert cli.main(["https://a.test", "https://b.test", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert [entry["url"] for entry in data] == ["https://a.test", "https://b.test"]


def test_batch_renders_comparison_table(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda url, timeout, verify: _result(url))
    assert cli.main(["https://a.test", "https://b.test"]) == 0
    out = capsys.readouterr().out
    assert "a.test" in out and "b.test" in out


def test_min_grade_fails_on_worst_result(monkeypatch):
    results = {"a.test": _result("a.test", 100), "b.test": _result("b.test", 40)}
    monkeypatch.setattr(cli, "scan", lambda url, timeout, verify: results[url])
    assert cli.main(["a.test", "b.test", "--min-grade", "B"]) == 1
    assert cli.main(["a.test", "--min-grade", "B"]) == 0


def test_network_error_exits_2(monkeypatch, capsys):
    def boom(url, timeout, verify):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(cli, "scan", boom)
    assert cli.main(["https://a.test"]) == 2
    assert "connection refused" in capsys.readouterr().err


def test_batch_partial_failure_still_reports_and_exits_2(monkeypatch, capsys):
    def flaky(url, timeout, verify):
        if url == "bad.test":
            raise httpx.ConnectError("no route to host")
        return _result(url)

    monkeypatch.setattr(cli, "scan", flaky)
    assert cli.main(["good.test", "bad.test"]) == 2
    out = capsys.readouterr().out
    assert "good.test" in out
    assert "no route to host" in out
