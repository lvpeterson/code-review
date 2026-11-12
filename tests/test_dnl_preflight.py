"""Helper discovery / build / probe / preflight for the dotnet_legacy analyzer.
Everything here is monkeypatched; no real helper or SDK is needed."""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import main
from checks.dnl import helper
from enumerator import enumerate_target

FIXTURES = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture
def mvc_fixture():
    return FIXTURES / "mvc5_app"


def test_missing_helper_raises_with_install_text(monkeypatch, mvc_fixture):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    with pytest.raises(helper.PreflightError) as e:
        helper.preflight(mvc_fixture, allow_degraded=False)
    msg = str(e.value)
    assert msg.startswith("error: .NET Framework code detected")
    assert re.search(r"Found 2 \.vb / \d+ \.cs files in \.NET Framework projects", msg)
    assert "--allow-degraded" in msg


def test_install_text_per_os():
    assert "apt install dotnet-sdk-8.0" in helper.install_instructions("linux")
    assert "dnf install dotnet-sdk-8.0" in helper.install_instructions("linux")
    assert "./dotnet-install.sh --channel 8.0" in helper.install_instructions("linux")
    assert "winget install Microsoft.DotNet.SDK.8" in helper.install_instructions("win32")
    for plat in ("linux", "win32"):
        t = helper.install_instructions(plat)
        assert "CODE_REVIEW_ROSLYN_IR" in t and "PublishSingleFile=true" in t


def test_allow_degraded_returns_none(monkeypatch, mvc_fixture):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    assert helper.preflight(mvc_fixture, allow_degraded=True) is None


def test_sdk_present_builds_then_probes(monkeypatch, mvc_fixture, tmp_path):
    built = tmp_path / "roslyn-ir"
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: True)
    monkeypatch.setattr(helper, "build_helper", lambda *a: built)
    monkeypatch.setattr(helper, "probe", lambda b: None)
    assert helper.preflight(mvc_fixture, allow_degraded=False) == built


def test_found_helper_is_probed_not_built(monkeypatch, mvc_fixture, tmp_path):
    found = tmp_path / "roslyn-ir"
    probed = []
    monkeypatch.setattr(helper, "find_helper", lambda *a: found)
    monkeypatch.setattr(helper, "build_helper", lambda *a: pytest.fail("built"))
    monkeypatch.setattr(helper, "probe", probed.append)
    assert helper.preflight(mvc_fixture, allow_degraded=False) == found
    assert probed == [found]


def test_broken_helper_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "not json", ""))
    with pytest.raises(helper.PreflightError):
        helper.probe(tmp_path / "roslyn-ir")


def test_probe_nonzero_and_schema_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "boom"))
    with pytest.raises(helper.PreflightError, match="boom"):
        helper.probe(tmp_path / "roslyn-ir")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 0, '{"ok": true, "schema": 99}', ""))
    with pytest.raises(helper.PreflightError, match="outdated"):
        helper.probe(tmp_path / "roslyn-ir")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 0, '{"ok": true, "schema": 1}', ""))
    helper.probe(tmp_path / "roslyn-ir")


def test_parse_projects_single_process(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **k):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, '{"path":"a.cs","types":[]}\n' * 1200, "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    out = helper.parse_projects(tmp_path / "roslyn-ir", tmp_path,
                                [{"name": "p", "language": "cs",
                                  "files": [str(tmp_path / f"{i}.cs") for i in range(1200)], "references": []}])
    assert len(calls) == 1 and len(out) == 1200


def test_parse_projects_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "bad request"))
    with pytest.raises(helper.PreflightError, match="bad request"):
        helper.parse_projects(tmp_path / "roslyn-ir", tmp_path, [])


def test_find_helper_env_then_repo_local_then_path(monkeypatch, tmp_path):
    name = "roslyn-ir.exe" if sys.platform == "win32" else "roslyn-ir"
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    monkeypatch.delenv(helper.HELPER_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", lambda n: None)
    assert helper.find_helper(tmp_path) is None

    on_path = tmp_path / "pathbin" / name
    on_path.parent.mkdir()
    on_path.write_text("x")
    monkeypatch.setattr(helper.shutil, "which", lambda n: str(on_path))
    assert helper.find_helper(tmp_path) == on_path

    local = tmp_path / "tools" / "roslyn-ir" / "bin" / name
    local.parent.mkdir(parents=True)
    local.write_text("x")
    assert helper.find_helper(tmp_path) == local

    env = tmp_path / "envbin"
    env.write_text("x")
    monkeypatch.setenv(helper.HELPER_ENV, str(env))
    assert helper.find_helper(tmp_path) == env


def test_stale_repo_binary_rebuilt_only_with_sdk(monkeypatch, tmp_path):
    name = "roslyn-ir.exe" if sys.platform == "win32" else "roslyn-ir"
    monkeypatch.delenv(helper.HELPER_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", lambda n: None)
    local = tmp_path / "tools" / "roslyn-ir" / "bin" / name
    local.parent.mkdir(parents=True)
    local.write_text("x")
    src = tmp_path / "tools" / "roslyn-ir" / "src"
    (src / "obj").mkdir(parents=True)
    (src / "Program.cs").write_text("//")
    (src / "obj" / "junk.cs").write_text("//")
    old = time.time() - 1000
    os.utime(local, (old, old))
    monkeypatch.setattr(helper, "sdk_available", lambda: True)
    assert helper.find_helper(tmp_path) is None
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    assert helper.find_helper(tmp_path) == local


def test_cli_exits_2_on_preflight(monkeypatch, mvc_fixture, capsys):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    monkeypatch.setattr(sys, "argv", ["main.py", str(mvc_fixture)])
    assert main.main() == 2 and "Roslyn helper is not available" in capsys.readouterr().err


def test_non_dotnet_target_never_preflights(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n")
    monkeypatch.setattr(helper, "preflight", lambda *a, **k: pytest.fail("preflight ran"))
    enumerate_target(tmp_path)


def test_allow_degraded_flag_reaches_preflight(monkeypatch, mvc_fixture):
    seen = []
    monkeypatch.setattr(helper, "preflight", lambda t, d: seen.append(d))
    enumerate_target(mvc_fixture, allow_degraded=True)
    assert seen == [True]


def test_allow_degraded_covers_build_failure(monkeypatch, mvc_fixture, capsys):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: True)

    def boom(*a):
        raise helper.PreflightError("error: building the Roslyn helper failed.")
    monkeypatch.setattr(helper, "build_helper", boom)
    assert helper.preflight(mvc_fixture, allow_degraded=True) is None
    assert "warning: error: building" in capsys.readouterr().err
    with pytest.raises(helper.PreflightError):
        helper.preflight(mvc_fixture, allow_degraded=False)


def test_allow_degraded_covers_probe_failure(monkeypatch, mvc_fixture, tmp_path, capsys):
    monkeypatch.setattr(helper, "find_helper", lambda *a: tmp_path / "roslyn-ir")

    def boom(b):
        raise helper.PreflightError("error: Roslyn helper is broken")
    monkeypatch.setattr(helper, "probe", boom)
    assert helper.preflight(mvc_fixture, allow_degraded=True) is None
    assert "warning: error: Roslyn helper is broken" in capsys.readouterr().err
    with pytest.raises(helper.PreflightError):
        helper.preflight(mvc_fixture, allow_degraded=False)


def test_staleness_compares_against_dll(monkeypatch, tmp_path):
    name = "roslyn-ir.exe" if sys.platform == "win32" else "roslyn-ir"
    monkeypatch.delenv(helper.HELPER_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", lambda n: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: True)
    bindir = tmp_path / "tools" / "roslyn-ir" / "bin"
    bindir.mkdir(parents=True)
    src = tmp_path / "tools" / "roslyn-ir" / "src"
    src.mkdir()
    (src / "Program.cs").write_text("//")
    now = time.time()
    os.utime(src / "Program.cs", (now - 500, now - 500))
    (bindir / name).write_text("x")
    (bindir / "roslyn-ir.dll").write_text("x")
    os.utime(bindir / name, (now - 1000, now - 1000))  # stale apphost
    os.utime(bindir / "roslyn-ir.dll", (now, now))     # fresh dll
    assert helper.find_helper(tmp_path) == bindir / name


def test_build_and_parse_errors_become_preflight_errors(monkeypatch, tmp_path):
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(helper.PreflightError):
        helper.build_helper(tmp_path)
    with pytest.raises(helper.PreflightError):
        helper.parse_projects(tmp_path / "roslyn-ir", tmp_path, [])
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, b"{bad\n", b""))
    with pytest.raises(helper.PreflightError, match="invalid output"):
        helper.parse_projects(tmp_path / "roslyn-ir", tmp_path, [])


def test_env_var_not_a_file_warns(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv(helper.HELPER_ENV, str(tmp_path / "nope"))
    monkeypatch.setattr(helper.shutil, "which", lambda n: None)
    assert helper.find_helper(tmp_path) is None
    assert helper.HELPER_ENV in capsys.readouterr().err


def test_allow_degraded_without_helper_warns_on_stderr(monkeypatch, mvc_fixture, capsys):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    assert helper.preflight(mvc_fixture, allow_degraded=True) is None
    assert "DEGRADED" in capsys.readouterr().err


def test_degraded_visible_on_console_and_at_exit(monkeypatch, mvc_fixture, capsys):
    from checks.dnl import project
    project._CACHE.clear()
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    monkeypatch.setattr(sys, "argv", ["main.py", str(mvc_fixture), "--allow-degraded"])
    assert main.main() == 0
    cap = capsys.readouterr()
    assert f"DEGRADED: {helper.DEGRADED_REASON}" in cap.out
    assert cap.err.rstrip().splitlines()[-1].startswith("DEGRADED")
    project._CACHE.clear()


def test_which_hit_inside_cwd_is_ignored(monkeypatch, tmp_path):
    # Windows searches the cwd first: a planted roslyn-ir / dotnet there must not run.
    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "roslyn-ir.exe").write_text("x")
    (planted / "dotnet.exe").write_text("x")
    monkeypatch.chdir(planted)
    monkeypatch.delenv(helper.HELPER_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", lambda n: str(planted / (n + ".exe")))
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: ran.append(a) or subprocess.CompletedProcess(a, 0, "8.0.100 [x]", ""))
    assert helper.find_helper(tmp_path / "repo") is None
    assert helper.sdk_available() is False
    with pytest.raises(helper.PreflightError):
        helper.build_helper(tmp_path / "repo")
    assert ran == []


def test_which_hit_outside_cwd_is_used(monkeypatch, tmp_path):
    other = tmp_path / "onpath"
    other.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv(helper.HELPER_ENV, raising=False)
    monkeypatch.setattr(helper.shutil, "which", lambda n: str(other / n))
    assert helper.find_helper(tmp_path / "repo") == other / "roslyn-ir"
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: seen.append(cmd) or subprocess.CompletedProcess(cmd, 0, "8.0.100 [x]\n", ""))
    assert helper.sdk_available() is True
    assert seen[0][0] == str(other / "dotnet")


def test_which_hit_in_ancestor_of_cwd_is_kept(monkeypatch, tmp_path):
    # Running from a parent of the SDK dir (e.g. the drive root) must not discard it.
    sdk = tmp_path / "Program Files" / "dotnet"
    sdk.mkdir(parents=True)
    (sdk / "dotnet.exe").write_text("x")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(helper.shutil, "which", lambda n: str(sdk / "dotnet.exe"))
    assert helper._which("dotnet") == str(sdk / "dotnet.exe")


def test_which_hit_directly_in_cwd_is_dropped(monkeypatch, tmp_path):
    (tmp_path / "dotnet.exe").write_text("x")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(helper.shutil, "which", lambda n: str(tmp_path / "dotnet.exe"))
    assert helper._which("dotnet") is None
