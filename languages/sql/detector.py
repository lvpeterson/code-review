"""Language + dialect detection for SQL targets. Which files count (including
.txt files whose contents look like SQL) is decided by
checks.plsql.iter_plsql_files.

"Framework" here means SQL dialect -- the only thing that changes which
rules apply. Only Oracle PL/SQL has an analyzer so far, so a repo of plain
T-SQL/Postgres .sql files is detected as "sql" but gets no deep-dive (the
enumerator prints "no known framework matched") rather than being run
through Oracle-only rules that would silently miss its dynamic SQL.
"""
from __future__ import annotations

import re
from pathlib import Path

from checks.plsql import iter_plsql_files
from core.fsutil import read_text_safe

# Extensions that are Oracle-specific on their own (package spec/body,
# standalone function/procedure/trigger/type files), no content check needed.
_ORACLE_ONLY_EXTENSIONS = {".pls", ".pkb", ".pks", ".pck", ".fnc", ".prc", ".trg", ".typ"}

_PLSQL_MARKERS = re.compile(
    r"(?i)\b(?:EXECUTE\s+IMMEDIATE|AUTHID\s+(?:DEFINER|CURRENT_USER)"
    r"|CREATE\s+(?:OR\s+REPLACE\s+)?PACKAGE|DBMS_\w+\s*\.|UTL_\w+\s*\."
    r"|PRAGMA\s+AUTONOMOUS_TRANSACTION|RAISE_APPLICATION_ERROR)"
)


def detect_language(target_path: Path) -> bool:
    return any(True for _ in iter_plsql_files(target_path))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return ["plsql"] if any file is Oracle by extension or contains an
    Oracle-only construct; otherwise []."""
    for path in iter_plsql_files(target_path):
        if path.suffix.lower() in _ORACLE_ONLY_EXTENSIONS:
            return ["plsql"]
        if _PLSQL_MARKERS.search(read_text_safe(path)):
            return ["plsql"]
    return []
