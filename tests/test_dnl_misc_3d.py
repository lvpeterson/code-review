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


def test_n4_key_name_literals_skipped_weak_looking_ones_demoted(findings):
    got = {g[0]: g[1:] for g in _of(findings, "DNL-SEC-003", SECRETS)}
    # accessToken / user_token / __RequestVerificationToken / id_token (lines 7-10): skipped
    assert not {7, 8, 9, 10} & set(got)
    assert got[11] == ("high", None)             # real-looking secret unchanged
    # name-shaped literals on a secret-like variable, or too long, or without a key word: never dropped
    for line in (16, 17, 18, 19, 20, 21, 22, 24, 25, 27, 28, 29, 30, 31, 32, 36):
        assert got[line] == ("low", "REVIEW"), line


def test_hmacsha1_hashdata_is_not_flagged(findings):
    assert 40 not in [g[0] for g in _of(findings, "DNL-CRY-001", HASH)]


def test_n4_test_project_findings_demoted(findings):
    sec = _of(findings, "DNL-SEC-003", TEST_CTL)
    assert sec == [(10, "medium", "REVIEW")]
    ssrf = _of(findings, "DNL-SSRF-001", TEST_CTL)
    assert ssrf == [(15, "medium", "REVIEW")]
    # the same flow in the product project is unchanged
    assert _of(findings, "DNL-SSRF-001", PROXY) == [(14, "high", None)]


FALLBACK = "src/Misc3d/Services/GateFallback.cs"
GATES = {"src/Misc3d/Services/GateNested.cs", "src/Misc3d/Services/GateStaticUsing.cs",
         "src/Misc3d/Services/GateExtension.cs", "src/Misc3d/Services/GateGeneric.cs"}


def test_n7_scoped_resolution_keeps_real_gates(findings):
    # nested class -> outer method, `using static` helper, extension method via this., generic base,
    # plus the solution-wide fallback (REVIEW)
    errs = [f for f in findings if f.check_id == "DNL-ERR-001"]
    assert {f.file for f in errs} == GATES | {FALLBACK}
    assert all(f.confidence is None for f in errs if f.file in GATES)
    assert [f.confidence for f in errs if f.file == FALLBACK] == ["REVIEW"]


def test_n7_no_fail_open_catch_for_modelstate_and_service_calls(findings):
    # An unqualified call must not resolve to a same-named method of an unrelated type.
    assert not [f for f in findings if f.check_id == "DNL-ERR-001" and "Checkout" in f.file]


def test_n7_truth_evaluation_is_scoped_to_the_owner(roslyn_helper, monkeypatch):
    """`_Truth` resolves `Lookup()` inside TruthHost; an unrelated TruthDecoy.Lookup must not make the
    answer ambiguous (core, no symbols)."""
    from checks.dnl import rules_errors
    from checks.dnl.ir import walk
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    model = project.prepare(FX, True).view("dotnet")
    auth = rules_errors._Auth(model)
    host = next(t for t in model.types() if t.name == "TruthHost")
    pick = next(m for m in host.methods if m.name == "Pick")
    call = next(n for n in walk(pick.body) if n.get("k") == "call")
    assert rules_errors._Truth(auth, host, pick.body, owner=host).of(call) == "true"
