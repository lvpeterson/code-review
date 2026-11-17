"""Acceptance fixes (misc): static weak hashes, test-project demotion, key-name secret literals, and the
degraded-only fail-open catch false positive. Helper and degraded runs give the same answers."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project

FX = Path(__file__).parent / "fixtures" / "aspnetcore" / "misc_3d"
HASH = "src/Misc3d/Crypto/Hashing.cs"
SECRETS = "src/Misc3d/Auth/Secrets.cs"
TEST_CTL = "tests/Misc3d.Tests/FakeProxyController.cs"
PROXY = "src/Misc3d/Services/Proxy.cs"


@pytest.fixture(autouse=True)
def _fresh():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


@pytest.fixture(params=["helper", "degraded"])
def findings(request, monkeypatch, roslyn_helper):
    degraded = request.param == "degraded"
    if degraded:
        monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
        monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    res = [r for r in enumerator.enumerate_target(FX, allow_degraded=degraded) if r.language == "dotnet"]
    assert res and all(bool(r.degraded) == degraded for r in res)
    return [f for r in res for f in r.findings]


def _of(findings, rule, file):
    return sorted((f.line, f.severity, f.confidence) for f in findings if f.check_id == rule and f.file == file)


def test_d4_static_weak_hash_calls_fire(findings):
    got = _of(findings, "DNL-CRY-001", HASH)
    # MD5.HashData, SHA1.HashData, MD5.HashDataAsync, SHA1.HashDataAsync, HMACMD5.HashData; SHA256 stays quiet
    assert [g[0] for g in got] == [10, 15, 20, 25, 30]
    assert all(g[1] == "medium" for g in got)


def test_n4_key_name_and_sentence_literals_skipped(findings):
    got = _of(findings, "DNL-SEC-003", SECRETS)
    assert [g[0] for g in got] == [10]           # only the real-looking signing secret
    assert got[0][1] == "high" and got[0][2] is None


def test_n4_test_project_findings_demoted(findings):
    sec = _of(findings, "DNL-SEC-003", TEST_CTL)
    assert sec == [(10, "medium", "REVIEW")]
    ssrf = _of(findings, "DNL-SSRF-001", TEST_CTL)
    assert ssrf == [(15, "medium", "REVIEW")]
    # the same flow in the product project is unchanged
    assert _of(findings, "DNL-SSRF-001", PROXY) == [(14, "high", None)]


def test_n7_no_fail_open_catch_for_modelstate_and_service_calls(findings):
    # An unqualified call must not resolve to a same-named method of an unrelated type.
    assert [f for f in findings if f.check_id == "DNL-ERR-001"] == []
