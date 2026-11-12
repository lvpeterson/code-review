"""Shared pytest fixtures.

`roslyn_helper` builds the tools/roslyn-ir .NET helper once per session
(controller ruling R1) and hands tests the published binary path. Tests
that need it are skipped -- not failed -- on machines without the .NET SDK.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ROSLYN_PROJECT = REPO_ROOT / "tools" / "roslyn-ir" / "src" / "RoslynIr.csproj"
ROSLYN_BIN_DIR = REPO_ROOT / "tools" / "roslyn-ir" / "bin"


@pytest.fixture(scope="session")
def roslyn_helper() -> str:
    if shutil.which("dotnet") is None:
        pytest.skip("dotnet SDK not on PATH; roslyn-ir helper cannot be built")
    # Publish into the gitignored tools/roslyn-ir/bin; a failed build is a
    # real failure (the helper source is part of the repo), not a skip.
    subprocess.run(
        ["dotnet", "publish", str(ROSLYN_PROJECT), "-c", "Release",
         "-o", str(ROSLYN_BIN_DIR), "--nologo"],
        check=True, cwd=REPO_ROOT,
    )
    name = "roslyn-ir.exe" if os.name == "nt" else "roslyn-ir"
    binary = ROSLYN_BIN_DIR / name
    assert binary.exists(), f"publish did not produce {binary}"
    return str(binary)
