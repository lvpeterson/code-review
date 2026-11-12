"""Discovery, build-on-first-use and invocation of the roslyn-ir helper.

The legacy .NET analyzer needs full-context C#/VB parsing, which only the
Roslyn helper (tools/roslyn-ir) provides. `preflight` finds or builds it and
proves it works before any analysis starts, so a broken setup fails fast
with install steps (CLI exit 2) instead of silently producing thin results.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from checks.dnl.files import iter_dnl_files

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_VERSION = 1
HELPER_ENV = "CODE_REVIEW_ROSLYN_IR"

DEGRADED_REASON = (
    "Roslyn helper not available (--allow-degraded): C#/VB code analysis was "
    "skipped; only project and web.config checks ran."
)


class PreflightError(Exception):
    """The message is the full user-facing text."""


def _binary_name(platform: str = sys.platform) -> str:
    return "roslyn-ir.exe" if platform == "win32" else "roslyn-ir"


def _src_newer_than(src_dir: Path, binary: Path) -> bool:
    """True if any helper source file is newer than the binary (bin/obj skipped)."""
    # The apphost stub is only rewritten by publish when it changes; the code
    # lives in roslyn-ir.dll, so that is the real build timestamp.
    dll = binary.with_name("roslyn-ir.dll")
    built = (dll if dll.is_file() else binary).stat().st_mtime
    for dirpath, dirnames, filenames in os.walk(src_dir):
        dirnames[:] = [d for d in dirnames if d.lower() not in ("bin", "obj")]
        for name in filenames:
            if (Path(dirpath) / name).stat().st_mtime > built:
                return True
    return False


def find_helper(repo_root: Path = REPO_ROOT) -> Path | None:
    """Order: $CODE_REVIEW_ROSLYN_IR, repo-local publish dir, PATH. A repo-local
    binary older than its sources counts as missing when the SDK can rebuild it."""
    env = os.environ.get(HELPER_ENV)
    if env and Path(env).is_file():
        return Path(env)
    if env:
        print(f"warning: {HELPER_ENV}={env} is not a file; ignoring it", file=sys.stderr)

    src = repo_root / "tools" / "roslyn-ir" / "src"
    local = repo_root / "tools" / "roslyn-ir" / "bin" / _binary_name()
    if local.is_file():
        stale = src.is_dir() and _src_newer_than(src, local)
        if not (stale and sdk_available()):
            return local

    on_path = _which("roslyn-ir")
    return Path(on_path) if on_path else None


def _which(name: str) -> str | None:
    """shutil.which, minus hits directly in the current directory. Windows searches the
    cwd before PATH, so a scanned repo could plant a roslyn-ir / dotnet that we
    would then execute. The repo's own tools/roslyn-ir/bin is the one exception."""
    found = shutil.which(name)
    if not found:
        return None
    p = Path(found)
    if not p.is_absolute():
        return None  # a bare / relative hit can only have come from the cwd
    try:
        resolved, cwd = p.resolve(), Path.cwd().resolve()
        # Only a binary sitting directly in the cwd is the planted-binary risk; a hit
        # deeper below (or cwd being an ancestor such as the drive root) is a real install.
        in_cwd = os.path.normcase(str(resolved.parent)) == os.path.normcase(str(cwd))
        if in_cwd and not resolved.is_relative_to((REPO_ROOT / "tools" / "roslyn-ir" / "bin").resolve()):
            return None
    except OSError:
        return None
    return found


def sdk_available() -> bool:
    """True if `dotnet --list-sdks` lists a major version >= 8."""
    dotnet = _which("dotnet")
    if dotnet is None:
        return False
    try:
        proc = subprocess.run([dotnet, "--list-sdks"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    return any(int(m.group(1)) >= 8 for m in re.finditer(r"^(\d+)\.", proc.stdout, re.M))


def build_helper(repo_root: Path = REPO_ROOT) -> Path:
    """Publish the helper into tools/roslyn-ir/bin and return the binary."""
    print("[dotnet_legacy] building Roslyn helper (first run)...", flush=True)
    csproj = repo_root / "tools" / "roslyn-ir" / "src" / "RoslynIr.csproj"
    out = repo_root / "tools" / "roslyn-ir" / "bin"
    dotnet = _which("dotnet")
    if dotnet is None:
        raise PreflightError("error: building the Roslyn helper failed (dotnet not found on PATH).")
    try:
        proc = subprocess.run(
            [dotnet, "publish", str(csproj), "-c", "Release", "-o", str(out), "--nologo"],
            capture_output=True, text=True, timeout=900,
        )
    except (OSError, subprocess.SubprocessError) as ex:
        raise PreflightError(f"error: building the Roslyn helper failed ({ex}).") from ex
    binary = out / _binary_name()
    if proc.returncode != 0 or not binary.is_file():
        raise PreflightError(
            "error: building the Roslyn helper failed.\n"
            + (proc.stdout + proc.stderr).strip()[-2000:]
            + "\nFix the build, or see tools/roslyn-ir/README.md."
        )
    return binary


def probe(binary: Path) -> None:
    """Run `roslyn-ir probe`; PreflightError if broken or a different schema."""
    rebuild = "Rebuild it: dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -o tools/roslyn-ir/bin"
    try:
        proc = subprocess.run([str(binary), "probe"], capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as ex:
        raise PreflightError(f"error: Roslyn helper at {binary} is broken ({ex}). {rebuild}") from ex
    if proc.returncode != 0:
        raise PreflightError(
            f"error: Roslyn helper at {binary} is broken (probe exited {proc.returncode}): "
            f"{proc.stderr.strip()}\n{rebuild}"
        )
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        data = None
    if not isinstance(data, dict) or not data.get("ok"):
        raise PreflightError(f"error: Roslyn helper at {binary} is broken (probe gave no valid result). {rebuild}")
    if data.get("schema") != SCHEMA_VERSION:
        raise PreflightError(
            f"error: Roslyn helper at {binary} is outdated (schema {data.get('schema')}, "
            f"expected {SCHEMA_VERSION}). {rebuild}"
        )


def detection_summary(target: Path) -> str:
    vb = sum(1 for _ in iter_dnl_files(target, (".vb",)))
    cs = sum(1 for _ in iter_dnl_files(target, (".cs",)))
    return f"Found {vb} .vb / {cs} .cs files in .NET Framework projects"


def install_instructions(platform: str = sys.platform) -> str:
    if platform == "win32":
        sdk = "Install the .NET 8 SDK:\n  winget install Microsoft.DotNet.SDK.8"
    else:
        sdk = (
            "Install the .NET 8 SDK:\n"
            "  Debian/Ubuntu: sudo apt install dotnet-sdk-8.0\n"
            "  Fedora/RHEL:   sudo dnf install dotnet-sdk-8.0\n"
            "  Any distro:    ./dotnet-install.sh --channel 8.0   (script from https://dot.net/v1/dotnet-install.sh)"
        )
    return (
        f"{sdk}\n"
        "Or, with no install on this machine: on a machine that has the SDK run\n"
        "  dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true\n"
        "then copy the binary (and its refs/ folder) to tools/roslyn-ir/bin/ or point\n"
        f"{HELPER_ENV} at it.\n"
        "Then re-run this command. To proceed without C#/VB code analysis, pass --allow-degraded."
    )


def preflight(target: Path, allow_degraded: bool) -> Path | None:
    """Return a probed helper binary, building it if the SDK is present.
    None only when unavailable and allow_degraded; otherwise PreflightError."""
    try:
        binary = find_helper()
        if binary is None and sdk_available():
            binary = build_helper()
        if binary is not None:
            probe(binary)
            return binary
    except PreflightError as ex:
        # A failed build or broken helper is as unavailable as a missing one.
        if not allow_degraded:
            raise
        print(f"warning: {ex}", file=sys.stderr)
        print(f"DEGRADED: {DEGRADED_REASON}", file=sys.stderr)
        return None
    if allow_degraded:
        print(f"DEGRADED: {DEGRADED_REASON}", file=sys.stderr)
        return None
    raise PreflightError(
        "error: .NET Framework code detected but the Roslyn helper is not available.\n"
        f"{detection_summary(target)}.\n"
        "The helper is needed for full-context C#/VB analysis (types, data flow, symbol resolution).\n"
        f"{install_instructions()}"
    )


def parse_projects(binary: Path, root: Path, projects: list[dict], timeout: int = 1800) -> list[dict]:
    """Run `roslyn-ir parse` once for all projects; return decoded JSON Lines."""
    request = {"root": str(root), "projects": projects}
    fd, req_path = tempfile.mkstemp(suffix=".json", prefix="roslyn-ir-req-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(request, fh)
        proc = subprocess.run([str(binary), "parse", "--input", req_path],
                              capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as ex:
        raise PreflightError(f"error: Roslyn helper parse could not run or timed out ({ex}).") from ex
    finally:
        try:
            os.unlink(req_path)
        except OSError:
            pass
    out, err = proc.stdout, proc.stderr
    stdout = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
    stderr = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
    if proc.returncode != 0:
        raise PreflightError(f"error: Roslyn helper parse failed (exit {proc.returncode}): {stderr.strip()}")
    try:
        return [json.loads(line) for line in stdout.splitlines() if line.strip()]
    except ValueError as ex:
        raise PreflightError(f"error: Roslyn helper produced invalid output ({ex}).") from ex
