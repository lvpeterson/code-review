"""Crypto and hardcoded-credential rules in code (DNL-CRY-001..008, DNL-SEC-003)."""
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_crypto
from core.registry import get_analyzer
import languages.dotnet_legacy.analyzers  # noqa: F401  (registration)

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def refs(model):
    return routes.discover_mvc_webapi(model) + routes.discover_webforms(model) + routes.discover_wcf(model)


@pytest.fixture(scope="module")
def findings(model, refs):
    return rules_crypto.check(model, refs)


def hits(findings, rule, file_endswith=None, where=None):
    """Findings of a rule, optionally in one file and one `Type.Method` (description says `in Type.Method`)."""
    out = [f for f in findings if f.check_id == rule]
    if file_endswith:
        out = [f for f in out if f.file.endswith(file_endswith)]
    if where:
        out = [f for f in out if f"in {where}" in f.description]
    return out


def where_of(f):
    """`Type.Method` from the trailing `(in Type.Method).` of a description."""
    return f.description.rsplit("(in ", 1)[1].rstrip(").")


def test_cry001_weak_hash_password_context(findings):
    h = hits(findings, "DNL-CRY-001", "Hashing.cs", "WeakHashes.HashPassword")
    assert len(h) == 1 and h[0].severity == "high"
    e = hits(findings, "DNL-CRY-001", "Hashing.cs", "WeakHashes.Etag")
    assert len(e) == 1 and e[0].severity == "medium"
    legacy = hits(findings, "DNL-CRY-001", "Hashing.cs", "WeakHashes.LegacyStore")
    assert len(legacy) == 1 and legacy[0].severity == "high"
    assert not hits(findings, "DNL-CRY-001", "Hashing.cs", "WeakHashes.LegacyFine")
    assert not hits(findings, "DNL-CRY-001", "Hashing.cs", "WeakHashes.StrongHash")
    assert len(hits(findings, "DNL-CRY-001", "Hashing.cs")) == 5   # + the two on one line


def test_cry001_two_primitives_on_one_line_are_both_reported(findings):
    two = hits(findings, "DNL-CRY-001", "Hashing.cs", "WeakHashes.TwoOnOneLine")
    assert len(two) == 2 and len({f.line for f in two}) == 1


def test_cry001_new_through_using_alias(findings):
    assert len(hits(findings, "DNL-CRY-001", "Alias.cs", "AliasHashes.AliasNew")) == 1


def test_cry001_through_using_alias(findings):
    assert len(hits(findings, "DNL-CRY-001", "Alias.cs", "AliasHashes.AliasSha")) == 1
    assert len(hits(findings, "DNL-CRY-001", "Alias.cs", "AliasHashes.AliasFactory")) == 1


def test_vb_md5_password_high(findings):
    h = hits(findings, "DNL-CRY-001", "Crypto.vb", "VbHashes.HashPassword")
    assert len(h) == 1 and h[0].severity == "high"
    assert not hits(findings, "DNL-CRY-001", "Crypto.vb", "VbHashes.StrongHash")


def test_cry002_weak_cipher(findings):
    got = hits(findings, "DNL-CRY-002", "Ciphers.cs")
    assert {where_of(f) for f in got} >= {"Ciphers.OldDes", "Ciphers.OldTripleDes"}
    assert len(got) == 2 and all(f.severity == "high" for f in got)


def test_cry003_ecb(findings):
    assert len(hits(findings, "DNL-CRY-003", "Ciphers.cs", "Ciphers.EcbAes")) == 1
    assert not hits(findings, "DNL-CRY-003", "Ciphers.cs", "Ciphers.CbcAes")
    assert not hits(findings, "DNL-CRY-003", "Ciphers.cs", "StatefulSafe")
    # VB identifiers are case-insensitive (`CIPHERMODE.ecb`)
    assert len(hits(findings, "DNL-CRY-003", "Crypto.vb")) == 1


def test_cry004_constant_key_iv(findings):
    const_iv = hits(findings, "DNL-CRY-004", "Ciphers.cs", "Ciphers.ConstantIv")
    assert len(const_iv) == 2 and len({f.line for f in const_iv}) == 2   # .Key and .IV lines
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "Ciphers.ConstantKeyArg")) == 1
    assert not hits(findings, "DNL-CRY-004", "Ciphers.cs", "Ciphers.RandomIv")
    assert not hits(findings, "DNL-CRY-004", "Ciphers.cs", "Ciphers.NotACipher")   # not a cipher object
    assert all(f.severity == "high" for f in hits(findings, "DNL-CRY-004"))


def test_cry004_filled_buffer_is_not_constant(findings):
    for m in ("FilledIv", "CopiedIv", "FromParam"):
        assert not hits(findings, "DNL-CRY-004", "Ciphers.cs", f"KeyForms.{m}"), m
    # unfilled zero buffers are constant, directly or through a local
    for m in ("ZeroIv", "ZeroIvLocal"):
        assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", f"KeyForms.{m})")) == 1, m


def test_cry004_reassigned_strings_and_array_fill(findings):
    for m in ("SaltedString", "ReassignedString", "ArrayFillRandom"):
        assert not hits(findings, "DNL-CRY-004", "Ciphers.cs", f"KeyForms.{m})"), m
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "KeyForms.ArrayFillZero)")) == 1   # constant fill value


def test_cry004_appended_constant_stays_constant(findings):
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "KeyForms.AppendedConst)")) == 1


def test_cry004_local_in_another_method_does_not_clear_field(findings):
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "ShadowFields.UseField")) == 1


def test_cry004_field_buffers_filled_elsewhere(findings):
    assert not hits(findings, "DNL-CRY-004", "Ciphers.cs", "FieldBuffers.UseFilled")
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "FieldBuffers.UseZero")) == 1


def test_cry004_const_strings_and_mixed_elements(findings):
    for m in ("ConstString", "StaticString", "LocalString", "MixedIv"):
        assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", f"KeyForms.{m})")) == 1, m


def test_cry004_property_initializers(findings):
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "PropInit.Engine")) == 1
    assert len(hits(findings, "DNL-CRY-004", "Ciphers.cs", "PropInit.Use")) == 1


def test_crypto_state_across_methods(findings):
    # the cipher is a field; ECB is set in the constructor, a constant IV from a static field in another method
    assert len(hits(findings, "DNL-CRY-003", "Ciphers.cs", "StatefulCipher")) == 1
    iv = hits(findings, "DNL-CRY-004", "Ciphers.cs", "StatefulCipher")
    assert len(iv) == 2          # _aes.IV = FixedIv ; Engine.IV = GetBytes("literal"); Engine.Key = key is fine
    assert not hits(findings, "DNL-CRY-004", "Ciphers.cs", "StatefulSafe")
    assert not hits(findings, "DNL-CRY-003", "Ciphers.cs", "StatefulSafe")


def test_cry005_random_secrets(findings):
    got = hits(findings, "DNL-CRY-005", "Tokens.cs")
    names = {where_of(f) for f in got}
    assert names == {"Tokens.ResetToken", "Tokens.MakeCode", "Tokens.Fill"}
    assert all(f.severity == "medium" and f.confidence == "REVIEW" for f in got)
    assert not hits(findings, "DNL-CRY-005", "Tokens.cs", "Tokens.Shuffle")
    assert not hits(findings, "DNL-CRY-005", "Tokens.cs", "Tokens.SecureToken")


def test_cry006_certificate_validation(findings):
    for m in ("AcceptAnything", "AcceptBlock", "AcceptMethodGroup", "AcceptCast", "AcceptPolicy"):
        h = hits(findings, "DNL-CRY-006", "Tls.cs", f"TlsSetup.{m}")
        assert len(h) == 1, m
        assert h[0].severity == "high" and h[0].owasp["api2023"].startswith("API10:2023")
    for m in ("CheckChain", "CheckMethodGroup", "CheckPolicy"):
        assert not hits(findings, "DNL-CRY-006", "Tls.cs", f"TlsSetup.{m}"), m
    assert len(hits(findings, "DNL-CRY-006", "Crypto.vb", "VbHashes.VbTrust")) == 1
    assert len(hits(findings, "DNL-CRY-006", "Crypto.vb", "VbHashes.VbMethodGroup")) == 1    # AddressOf a method returning True
    assert not hits(findings, "DNL-CRY-006", "Crypto.vb", "VbHashes.VbCheckGroup")


def test_cry007_old_protocols(findings):
    assert len(hits(findings, "DNL-CRY-007", "Tls.cs", "TlsSetup.OldProtocols")) == 1
    assert len(hits(findings, "DNL-CRY-007", "Tls.cs", "TlsSetup.OldSsl")) == 1
    assert not hits(findings, "DNL-CRY-007", "Tls.cs", "TlsSetup.ModernProtocol")
    assert not hits(findings, "DNL-CRY-007", "Tls.cs", "TlsSetup.DropSsl")      # clearing Ssl3 is a hardening step


def test_cry008_kdf(findings):
    for m in ("Default", "Few", "Old"):
        assert len(hits(findings, "DNL-CRY-008", "Kdf.cs", f"Kdf.{m}")) == 1, m
    for m in ("Many", "ManyViaConst"):
        assert not hits(findings, "DNL-CRY-008", "Kdf.cs", f"Kdf.{m}"), m


def test_sec003_hardcoded_credentials(findings):
    sec = hits(findings, "DNL-SEC-003", "Secrets.cs")
    by_line = {f.line: f for f in sec}
    src = (FX / "taint_app" / "TaintCs" / "Crypto" / "Secrets.cs").read_text().splitlines()
    flagged = {src[ln - 1].strip() for ln in by_line}
    assert any("ApiToken" in s for s in flagged)
    assert any("AdminPassword" in s for s in flagged)
    assert any("hunter2hunter2" in s for s in flagged)
    assert any("Ld4pSecret" in s for s in flagged)
    assert any("Db!Secret99" in s for s in flagged)
    assert any("clientSecret = " in s for s in flagged)
    assert any("N4medSecret" in s for s in flagged)
    assert any('adminPassword = "admin"' in s for s in flagged)     # the literal is a substring of the name only
    assert any("DbPassword" in s for s in flagged)                  # auto-property initializer
    assert all(f.severity == "high" for f in sec)
    assert any('secret = "secret"' in s for s in flagged)       # equal to the whole name still fires
    assert any('Token = "token"' in s for s in flagged)
    assert len(sec) == 11
    assert len(hits(findings, "DNL-SEC-003", "Crypto.vb", "VbHashes.VbSecret")) == 1
    assert len(hits(findings, "DNL-SEC-003", "Crypto.vb", "VbHashes.VbPassword")) == 1


def test_sec003_ignores_placeholders_and_setting_keys(findings):
    src = (FX / "taint_app" / "TaintCs" / "Crypto" / "Secrets.cs").read_text().splitlines()
    flagged = {src[f.line - 1].strip() for f in hits(findings, "DNL-SEC-003", "Secrets.cs")}
    for quiet in ("PasswordResetUrl", "PasswordKey", "SecretName", "ApiKeyHeader", "PasswordPrefix", "Clear-Text-Format", '"tmp"', '"xxxx"', 'password = ""',
                  "AppSettings", "Integrated Security", "{password}"):
        assert not any(quiet in s for s in flagged), quiet


def test_route_attached_inside_handler_only(findings):
    f = hits(findings, "DNL-CRY-001", "CryptoController.cs")
    assert len(f) == 1 and f[0].severity == "high"
    assert f[0].route is not None and f[0].route.handler_name == "CryptoController.Digest"
    assert all(x.route is None for x in findings if not x.file.endswith("CryptoController.cs"))


def test_owasp_tags(findings):
    f = hits(findings, "DNL-CRY-001", "Hashing.cs")[0]
    assert f.owasp["2025"].startswith("A04:2025") and f.owasp["2021"].startswith("A02:2021") and "api2023" not in f.owasp
    assert hits(findings, "DNL-SEC-003")[0].owasp["2025"].startswith("A07:2025")


def test_route_less_findings_land_in_exactly_one_analyzer(roslyn_helper):
    project._CACHE.clear()
    seen = []
    for fw in ("mvc", "webapi", "webforms", "wcf", "config"):
        a = get_analyzer("dotnet_legacy", fw)(FX / "taint_app")
        seen += [f for f in a.analyze().findings if f.check_id == "DNL-CRY-001" and f.file.endswith("Hashing.cs")]
    assert len(seen) == 5   # Hashing.cs only
    project._CACHE.clear()
