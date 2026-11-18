"""DNL-SEC-001 / DNL-SEC-002 on appsettings*.json and launchSettings.json: a secret is reported in the
file that holds it (raw entries, not merged), with the Development / launch rule one severity lower."""
from cfgutil import make_app, mode, prepare_model, run_check  # noqa: F401

from checks.dnl import rules_pipeline

LEGACY_CSPROJ = """<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>
</Project>
"""
REAL = "Server=db;Database=a;User Id=app;Password=Zx9!kLm3pQ"


def _sec(tmp_path, files, mode):
    found = run_check(make_app(tmp_path, files), degraded=(mode == "degraded"))
    return [f for f in found if f.check_id in ("DNL-SEC-001", "DNL-SEC-002")]


def _shape(findings):
    return {(f.check_id, f.severity, f.confidence, f.route, f.file, f.line) for f in findings}


def _cs(value, key="Default"):
    return '{\n  "ConnectionStrings": {\n    "%s": "%s"\n  }\n}\n' % (key, value)


def test_connection_string_password_high_at_key_line(tmp_path, mode):
    got = _sec(tmp_path, {"appsettings.json": _cs(REAL)}, mode)
    assert _shape(got) == {("DNL-SEC-001", "high", None, None, "appsettings.json", 3)}
    assert "Zx9" not in got[0].description


def test_integrated_security_and_placeholders_are_clean(tmp_path, mode):
    for i, v in enumerate(["Server=db;Integrated Security=true", "Server=db;Password=$(DbPassword)",
                           "Server=db;Password=#{Pw}#",
                           "Server=db;Password=${DB_PW}", "Server=db;Password=%DB_PW%",
                           "Server=db;Password=<set me>", "Server=db;Password=;", "",
                           "@Microsoft.KeyVault(SecretUri=https://v.example.test/secrets/c)",
                           "vault:db/conn", "keyvault:conn", "secret://db/conn"]):
        assert _sec(tmp_path / str(i), {"appsettings.json": _cs(v)}, mode) == [], v


def test_changeme_style_stays_real(tmp_path, mode):
    got = _sec(tmp_path, {"appsettings.json": _cs("Server=db;Password=changeme")}, mode)
    assert {f.check_id for f in got} == {"DNL-SEC-001"}


def test_key_ending_connectionstring_is_checked(tmp_path, mode):
    text = '{\n  "Data": {\n    "MainConnectionString": "%s"\n  }\n}\n' % REAL
    assert _shape(_sec(tmp_path, {"appsettings.json": text}, mode)) == {
        ("DNL-SEC-001", "high", None, None, "appsettings.json", 3)}


def test_jwt_key_is_sec002_medium(tmp_path, mode):
    text = '{\n  "Jwt": {\n    "Key": "k8s9d7f6g5h4j3k2"\n  }\n}\n'
    assert _shape(_sec(tmp_path, {"appsettings.json": text}, mode)) == {
        ("DNL-SEC-002", "medium", None, None, "appsettings.json", 3)}


def test_other_secret_names(tmp_path, mode):
    text = ('{"Auth": {"ClientSecret": "abc123def456", "ApiKey": "k-1", "SigningKey": "s1gn1ngk3y",'
            ' "Token": "t0k3nvalue"}, "Hosts": {"Password": "p4ssw0rdreal"}}')
    got = _sec(tmp_path, {"appsettings.json": text}, mode)
    assert len(got) == 5 and {f.check_id for f in got} == {"DNL-SEC-002"}


def test_keyvault_reference_and_empty_values_are_clean(tmp_path, mode):
    text = ('{"Jwt": {"Key": "@Microsoft.KeyVault(SecretUri=https://v.example.test/secrets/k)"},'
            ' "A": {"Password": "", "Secret": null, "ApiKey": "${API_KEY}", "Token": "<set me>",'
            ' "ClientSecret": "vault:x", "SigningKey": "keyvault:y", "PrivateKey": "secret://z",'
            ' "Pwd": 12345, "Flag": {"Token": true}}}')
    assert _sec(tmp_path, {"appsettings.json": text}, mode) == []


def test_setting_name_keys_are_skipped(tmp_path, mode):
    text = ('{"Logging": {"TokenExpiration": "00:10:00"}, "Identity": {"PasswordMinLength": "12",'
            ' "PasswordResetUrl": "https://example.test/reset"}}')
    assert _sec(tmp_path, {"appsettings.json": text}, mode) == []


def test_connection_strings_key_is_not_double_reported(tmp_path, mode):
    got = _sec(tmp_path, {"appsettings.json": _cs(REAL, key="PasswordDb")}, mode)
    assert {f.check_id for f in got} == {"DNL-SEC-001"}


def test_development_file_placeholder_ignored_real_one_lower(tmp_path, mode):
    dev = {"appsettings.Development.json": _cs("Server=db;Password=password")}
    assert _sec(tmp_path / "a", dev, mode) == []
    dev = {"appsettings.Development.json": _cs(REAL)}
    assert _shape(_sec(tmp_path / "b", dev, mode)) == {
        ("DNL-SEC-001", "medium", None, None, "appsettings.Development.json", 3)}


def test_development_file_weak_values_ignored(tmp_path, mode):
    text = ('{"A": {"Key": "short", "Secret": "changeme", "Token": "xxxxxxxxxxxx", "ApiKey": "example",'
            ' "Password": "localdevpassword", "ClientSecret": "secret"}}')
    got = _sec(tmp_path, {"appsettings.Development.json": text}, mode)
    assert [(f.check_id, f.severity) for f in got] == [("DNL-SEC-002", "low")]


def test_development_secret_is_low(tmp_path, mode):
    text = '{\n  "Jwt": {\n    "Key": "k8s9d7f6g5h4j3k2"\n  }\n}\n'
    assert _shape(_sec(tmp_path, {"appsettings.Development.json": text}, mode)) == {
        ("DNL-SEC-002", "low", None, None, "appsettings.Development.json", 3)}


def test_production_staging_and_base_full_severity(tmp_path, mode):
    files = {"appsettings.Production.json": _cs(REAL), "appsettings.Staging.json": _cs(REAL),
             "appsettings.json": _cs(REAL)}
    got = _sec(tmp_path, files, mode)
    assert sorted(f.file for f in got) == ["appsettings.Production.json", "appsettings.Staging.json",
                                           "appsettings.json"]
    assert {f.severity for f in got} == {"high"}


def test_raw_entries_not_merged(tmp_path, mode):
    """A base secret overridden in Production is still committed in the base file."""
    files = {"appsettings.json": _cs(REAL), "appsettings.Production.json": _cs("Server=db;Password=$(Pw)")}
    got = _sec(tmp_path, files, mode)
    assert _shape(got) == {("DNL-SEC-001", "high", None, None, "appsettings.json", 3)}


def test_launch_settings_secret_is_low(tmp_path, mode):
    ls = ('{\n "profiles": {\n  "p": {\n   "environmentVariables": {\n    "Db__Password": "Zx9!kLm3pQ"\n'
          '   }\n  }\n }\n}\n')
    got = _sec(tmp_path, {"Properties/launchSettings.json": ls}, mode)
    assert _shape(got) == {("DNL-SEC-002", "low", None, None, "Properties/launchSettings.json", 5)}
    ls = ls.replace("Zx9!kLm3pQ", "password")
    assert _sec(tmp_path / "x", {"Properties/launchSettings.json": ls}, mode) == []


def test_launch_settings_connection_string_is_medium(tmp_path, mode):
    ls = '{"profiles": {"p": {"environmentVariables": {"ConnectionStrings__Default": "%s"}}}}' % REAL
    got = _sec(tmp_path, {"Properties/launchSettings.json": ls}, mode)
    assert [(f.check_id, f.severity) for f in got] == [("DNL-SEC-001", "medium")]


def test_commented_out_secret_is_ignored(tmp_path, mode):
    text = '{\n  // "Jwt": {"Key": "k8s9d7f6g5h4j3k2"},\n  /* "Password": "p4ssw0rdreal", */\n  "A": 1\n}\n'
    assert _sec(tmp_path, {"appsettings.json": text}, mode) == []


def test_malformed_file_adds_note_and_no_crash(tmp_path, mode):
    root = make_app(tmp_path, {"appsettings.json": '{"Jwt": {"Key": ,}}',
                               "appsettings.Production.json": _cs(REAL)})
    model, refs = prepare_model(root, degraded=(mode == "degraded"))
    found = rules_pipeline.check(model, refs)
    assert any("appsettings.json" in n and "could not be read" in n for n in model.notes)
    assert not any("failed" in n for n in model.notes)
    assert {(f.check_id, f.file) for f in found if f.check_id == "DNL-SEC-001"} == {
        ("DNL-SEC-001", "appsettings.Production.json")}


def test_file_in_legacy_project_directory_is_not_read(tmp_path, mode):
    files = {"appsettings.json": '{"A": 1}', "Old/Old.csproj": LEGACY_CSPROJ,
             "Old/appsettings.json": _cs(REAL)}
    got = [f for f in _sec(tmp_path, files, mode) if f.file.startswith("Old/")]
    assert got == []


def test_nested_app_directory_reports_repo_relative_path(tmp_path, mode):
    files = {"Api/Api.csproj": make_app(tmp_path / "scratch", {}).joinpath("App.csproj").read_text(),
             "Api/appsettings.json": _cs(REAL)}
    got = _sec(tmp_path / "w", files, mode)
    assert [(f.check_id, f.file, f.line) for f in got] == [("DNL-SEC-001", "Api/appsettings.json", 3)]


def _conn(tmp_path, value, mode):
    return _sec(tmp_path, {"appsettings.json": '{"ConnectionStrings": {"Default": %s}}' % __import__("json").dumps(value)}, mode)


def test_quoted_and_braced_passwords_are_reported(tmp_path, mode):
    for i, v in enumerate(['Server=a;Password="Zx9;kLm3pQ"', "Server=a;Password='Zx9;kLm3pQ'",
                           "Server=a;Password={Zx9;kLm3pQ}", 'Server=a;Password="Zx9""kLm3pQ";Port=1',
                           "Server=a;Password = Zx9kLm3pQ", "Server=a;PASSWORD=Zx9kLm3pQ",
                           "Server=a; pwd =Zx9kLm3pQ", "Server=a;DBPassword=Zx9kLm3pQ"]):
        got = _conn(tmp_path / str(i), v, mode)
        assert {f.check_id for f in got} == {"DNL-SEC-001"}, v


def test_quoted_placeholders_and_empty_are_clean(tmp_path, mode):
    for i, v in enumerate(['Server=a;Password=""', 'Server=a;Password="${DbPassword}"', "Server=a;Password='$(Pw)'",
                           "Server=a;Password=${DbPassword}", "Server=a;Password=$(Pw)", "Server=a;Password=#{Pw}#",
                           "Server=a;Password=@Microsoft.KeyVault(SecretUri=https://v.example.test/secrets/k)",
                           "Server=a;Password=secret://kv/db"]):
        assert _conn(tmp_path / str(i), v, mode) == [], v


def test_reference_prefix_with_secret_tail_is_reported(tmp_path, mode):
    for i, v in enumerate(["Server=a;Pwd=vault:Real123x", "Server=a;Pwd=keyvault:Real123x",
                           "Server=a;Password=@Microsoft.KeyVault(x)Real123x"]):
        assert {f.check_id for f in _conn(tmp_path / str(i), v, mode)} == {"DNL-SEC-001"}, v


def test_placeholder_with_literal_text_is_reported(tmp_path, mode):
    for i, v in enumerate(["Server=a;Password=${A}real${B}", "Server=a;Password=$(A)real$(B)",
                           "Server=a;Password=%A%real%B%", "Server=a;Password=pre#{A}#", "Server=a;Password=<a>real<b>"]):
        assert {f.check_id for f in _conn(tmp_path / str(i), v, mode)} == {"DNL-SEC-001"}, v
    text = '{"Jwt": {"Key": "${A}real${B}"}}'
    assert {f.check_id for f in _sec(tmp_path / "k", {"appsettings.json": text}, mode)} == {"DNL-SEC-002"}
    text = '{"Jwt": {"Key": "${JwtKey}"}, "A": {"Secret": "$(S)", "Token": "#{T}#", "ApiKey": "%K%"}}'
    assert _sec(tmp_path / "j", {"appsettings.json": text}, mode) == []


# -- final fix wave ---------------------------------------------------------------------------------------


def test_braced_and_double_underscore_connection_passwords_are_review(tmp_path, mode):
    for i, v in enumerate(["Server=db;Password={Summer2024}", "Server=db;Password={{Summer2024}}",
                           "Server=db;Password=__Summer2024__", 'Server=db;Password="{Summer2024}"']):
        got = _conn(tmp_path / str(i), v, mode)
        assert [(f.check_id, f.severity, f.confidence) for f in got] == [("DNL-SEC-001", "high", "REVIEW")], v


def test_whole_value_braced_placeholder_on_other_key_stays_clean(tmp_path, mode):
    text = '{"Jwt": {"Key": "{JwtKey}"}, "A": {"Secret": "__S__", "ApiKey": "{{K}}"}}'
    assert _sec(tmp_path, {"appsettings.json": text}, mode) == []


def test_other_placeholders_inside_connection_password_stay_ignored(tmp_path, mode):
    for i, v in enumerate(["Server=a;Password=${Pw}", "Server=a;Password=$(Pw)", "Server=a;Password=#{Pw}#",
                           "Server=a;Password=%PW%"]):
        assert _conn(tmp_path / str(i), v, mode) == [], v


def test_password_in_any_string_value_is_checked(tmp_path, mode):
    text = '{\n  "Redis": {\n    "Configuration": "cache.example.test:6380,password=Zx9kLm3pQ7,ssl=True"\n  }\n}\n'
    got = _sec(tmp_path / "a", {"appsettings.json": text}, mode)
    assert _shape(got) == {("DNL-SEC-001", "high", None, None, "appsettings.json", 3)}
    assert "Zx9kLm3pQ7" not in got[0].description
    text = '{"Redis": {"Configuration": "cache.example.test:6380,password=${REDIS_PW},ssl=True"}}'
    assert _sec(tmp_path / "b", {"appsettings.json": text}, mode) == []
    # the key-name exclusions still hold: a setting-shaped key is not a password holder
    text = '{"Auth": {"PasswordResetUrl": "https://x.example.test/r?a=1;password=Zx9kLm3pQ7"}}'
    assert _sec(tmp_path / "c", {"appsettings.json": text}, mode) == []


def test_bare_key_under_encryption_sections_is_secret(tmp_path, mode):
    for i, sect in enumerate(("Encryption", "DataCrypto", "AesSettings", "Hmac", "FieldEncryptor")):
        text = '{\n  "%s": {\n    "Key": "k8s9d7f6g5h4j3k2"\n  }\n}\n' % sect
        got = _sec(tmp_path / str(i), {"appsettings.json": text}, mode)
        assert _shape(got) == {("DNL-SEC-002", "medium", None, None, "appsettings.json", 3)}, sect
    text = '{"Logging": {"Key": "k8s9d7f6g5h4j3k2"}, "Paes": {"Key": "k8s9d7f6g5h4j3k2"}}'
    assert _sec(tmp_path / "n", {"appsettings.json": text}, mode) == []


def test_placeholder_followed_by_literal_after_comma_is_reported(tmp_path, mode):
    for i, v in enumerate(["Server=a;Password=${A},realsecret1", "Server=a;Password={Summer2024},ssl=True"]):
        assert {f.check_id for f in _conn(tmp_path / str(i), v, mode)} == {"DNL-SEC-001"}, v
