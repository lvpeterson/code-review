"""Marked pattern scan of VB sources for degraded mode (no Roslyn helper).

Without the helper there is no VB parser, so this is a small set of high-signal
line patterns, every finding `confidence="REVIEW"`: a regex cannot tell whether
a concatenated value is attacker-controlled, so a human decides. It reuses the
rule ids of the matching IR rules, so the OWASP mapping stays the same. It runs
only on .vb files and only in degraded mode (the analyzers call it then).

Comment lines (`'`, `REM`) and trailing comments never match; `_` line
continuations are joined so a statement split over lines is scanned whole.
Identifiers are case-insensitive (VB), so every pattern is.
"""
from __future__ import annotations

import re

from checks.dnl.files import read_source
from checks.dnl.findings import dnl_finding
from core.models import Finding

_NOTE = " VB is scanned with patterns only (no Roslyn helper): verify by hand."

_STR = re.compile(r'"(?:[^"]|"")*"')
_SQL_VERB = re.compile(r'^\s*(?:select|insert|update|delete|exec(?:ute)?)\b', re.I)
_CMD_CTOR = re.compile(r"\b(?:new\s+)?(?:sql|oledb|odbc|oracle|mysql|npgsql)?(?:command|dataadapter)\s*\(|\.commandtext\s*=", re.I)
# A string literal is masked to x01 (never an identifier character) before concatenation is looked for.
_LIT = "\x01"
_CONCAT = re.compile(rf"{_LIT}\s*[&+]\s*[A-Za-z_(\[]|[A-Za-z_)\]]\s*[&+]\s*{_LIT}|\${_LIT}")
_RESP_WRITE = re.compile(r"\bResponse\s*\.\s*Write\b", re.I)
_REQUEST = re.compile(r"\bRequest\s*(?:\.\s*(?:QueryString|Form|Params|Item|Cookies|Headers)\b|\()", re.I)
_ENCODED = re.compile(r"\b(?:Server\s*\.\s*Html(?:Attribute)?Encode|HttpUtility\s*\.\s*Html(?:Attribute)?Encode|"
                      r"AntiXss\w*\s*\.\s*\w+|Encoder\s*\.\s*Html\w*)\s*\(", re.I)
_DESER_TYPES = r"(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|SoapFormatter|NetDataContractSerializer)"
_DESER_DIRECT = re.compile(rf"\bNew\s+(?:[\w.]+\.)?{_DESER_TYPES}\b[^\r\n]*?\.\s*Deserialize\s*\(", re.I)
_DECL_MODS = r"(?:(?:Dim|Private|Public|Protected|Friend|Shared|ReadOnly|Shadows|Static)\s+)+"
_DESER_DECL = re.compile(
    rf"\b{_DECL_MODS}(\w+)\b[^\r\n=]*?(?:\bAs\s+(?:New\s+)?(?:[\w.]+\.)?{_DESER_TYPES}\b|=\s*New\s+(?:[\w.]+\.)?{_DESER_TYPES}\b)|"
    rf"\b{_DECL_MODS}(\w+)\s*=\s*New\s+(?:[\w.]+\.)?{_DESER_TYPES}\b", re.I)
_WEAK_HASH = re.compile(r"\b(?:MD5\s*\.\s*Create|MD5CryptoServiceProvider|MD5Cng|SHA1\s*\.\s*Create|SHA1Managed|"
                        r"SHA1CryptoServiceProvider|SHA1Cng)\b", re.I)
_WEAK_HASH_FACTORY = re.compile(r"\bHashAlgorithm\s*\.\s*Create\s*\(\s*\"(?:MD5|SHA1|SHA-1)\"", re.I)
_WEAK_CIPHER = re.compile(r"\b(?:DESCryptoServiceProvider|TripleDESCryptoServiceProvider|TripleDESCng|RC2CryptoServiceProvider|"
                          r"DES\s*\.\s*Create|TripleDES\s*\.\s*Create|RC2\s*\.\s*Create)\b", re.I)
_PWD = re.compile(r"(?:password|pwd)\s*=\s*([^;\"]+)", re.I)
_PLACEHOLDER = re.compile(r"^\s*(?:\{.*\}|\$\(.*\)|#\{.*\}|<.*>|%.*%|\*+|x+)\s*$", re.I)
_CERT = re.compile(r"\bServerCertificateValidationCallback\s*(?:\+?=)\s*(.*)", re.I)
_ADDRESS_OF = re.compile(r"\bAddressOf\s+([\w.]+)", re.I)
_RETURN = re.compile(r"^\s*Return\b(.*)$", re.I)


def _strip_comment(line: str) -> str:
    """The code part of a physical line: everything from an unquoted `'` is dropped."""
    in_str = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_str = not in_str
        elif ch == "'" and not in_str:
            return line[:i]
    return line


def _is_rem(line: str) -> bool:
    return bool(re.match(r"\s*REM(?:\s|$)", line, re.I))


def logical_lines(text: str) -> list[tuple[int, str]]:
    """[(first physical line number, statement text)] with comments removed and
    `_` continuations joined."""
    out: list[tuple[int, str]] = []
    cur: list[str] = []
    start = 0
    for n, raw in enumerate(text.splitlines(), 1):
        code = "" if _is_rem(raw) else _strip_comment(raw).rstrip()
        if not cur:
            start = n
        if re.search(r"(?:^|\s)_$", code):
            cur.append(code[:-1])
            continue
        cur.append(code)
        stmt = " ".join(c.strip() for c in cur).strip()
        cur = []
        if stmt:
            out.append((start, stmt))
    if cur:
        stmt = " ".join(c.strip() for c in cur).strip()
        if stmt:
            out.append((start, stmt))
    return out


def _masked(stmt: str) -> str:
    """Statement with every string literal replaced by _LIT (`$"..."` by `$` + _LIT)."""
    return _STR.sub(_LIT, stmt)


def _sql_concat(stmt: str) -> bool:
    lits = [m[1:-1] for m in _STR.findall(stmt)]
    masked = _masked(stmt)
    if not _CONCAT.search(masked):
        return False
    if _CMD_CTOR.search(masked):
        return True
    return any(_SQL_VERB.match(lit) for lit in lits) and (
        "=" in masked or re.search(r"\bformat\s*\(", stmt, re.I) is not None)


def _format_sql(stmt: str) -> bool:
    """String.Format("SELECT ... {0}", x): a SQL-verb literal with placeholders."""
    m = re.search(r"\bString\s*\.\s*Format\s*\(\s*(\"(?:[^\"]|\"\")*\")", stmt, re.I)
    return bool(m) and bool(_SQL_VERB.match(m.group(1)[1:-1])) and "{" in m.group(1)


def _always_true_function(lines: list[tuple[int, str]], idx: int) -> bool:
    """True when the `Function ... ` block starting at lines[idx] returns only `True`."""
    returns: list[str] = []
    for _, stmt in lines[idx + 1: idx + 40]:
        if re.match(r"End\s+(?:Function|Sub)\b", stmt, re.I):
            break
        m = _RETURN.match(stmt)
        if m:
            returns.append(m.group(1).strip().lower())
    return bool(returns) and all(r == "true" for r in returns)


def _scan_text(rel: str, text: str) -> list[Finding]:
    lines = logical_lines(text)
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, severity: str, title: str, desc: str, line: int) -> None:
        if (rule, line) in seen:
            return
        seen.add((rule, line))
        out.append(dnl_finding(rule, severity, f"{title} (VB pattern)", desc + _NOTE, rel, line, confidence="REVIEW"))

    formatters = {(m.group(1) or m.group(2)).lower() for _, s in lines for m in [_DESER_DECL.search(s)] if m}
    funcs = {}
    for i, (_, s) in enumerate(lines):
        m = re.match(r"(?:\w+\s+)*Function\s+(\w+)\b", s, re.I)
        if m:
            funcs[m.group(1).lower()] = i

    sql_vars: set[str] = set()
    for i, (ln, stmt) in enumerate(lines):
        # A variable seeded with a SQL literal, then grown with `&=` / `+=` / `x = x & y`.
        seed = re.match(r"(?:Dim\s+)?(\w+)\s*(?:As\s+String\s*)?=\s*(\"(?:[^\"]|\"\")*\")", stmt, re.I)
        if seed and _SQL_VERB.match(seed.group(2)[1:-1]):
            sql_vars.add(seed.group(1).lower())
        grow = re.match(r"(\w+)\s*(?:&=|\+=|=\s*\1\s*[&+])\s*(.+)$", stmt, re.I)
        grown = bool(grow) and grow.group(1).lower() in sql_vars and _masked(grow.group(2)).strip() != _LIT
        # Code patterns look at the statement with literal contents blanked, so a string that merely
        # mentions `MD5.Create()` is not code.
        bare = _STR.sub('""', stmt)
        direct = bool(_CMD_CTOR.search(bare)) and bool(_REQUEST.search(bare))
        if _sql_concat(stmt) or _format_sql(stmt) or grown or direct:
            add("DNL-INJ-001", "high", "SQL built by string concatenation",
                "A SQL statement is assembled with `&` / `+` / String.Format around a non-literal value, or a command "
                "is built from a Request value; check whether the value is attacker-controlled.", ln)
        if _RESP_WRITE.search(bare) and _REQUEST.search(bare) and not _ENCODED.search(bare):
            add("DNL-XSS-001", "high", "Request value written to the response",
                "Response.Write receives a Request value with no HTML encoding.", ln)
        deser = bool(_DESER_DIRECT.search(bare))
        if not deser:
            for v in formatters:
                if re.search(rf"\b{re.escape(v)}\s*\.\s*Deserialize\s*\(", bare, re.I):
                    deser = True
        if deser:
            add("DNL-DESER-001", "medium", "Unsafe formatter deserializes data",
                "BinaryFormatter / LosFormatter / similar rebuilds arbitrary objects from its input.", ln)
        if _WEAK_HASH.search(bare) or _WEAK_HASH_FACTORY.search(stmt):
            add("DNL-CRY-001", "medium", "Weak hash algorithm (MD5 / SHA1)",
                "MD5 or SHA1 is created here; weak for passwords and integrity.", ln)
        if _WEAK_CIPHER.search(bare):
            add("DNL-CRY-002", "high", "Weak symmetric cipher (DES / 3DES / RC2)",
                "A DES, TripleDES or RC2 provider is created here.", ln)
        for lit in _STR.findall(stmt):
            m = _PWD.search(lit[1:-1])
            if m and m.group(1).strip() and not _PLACEHOLDER.match(m.group(1)):
                add("DNL-SEC-003", "high", "Hardcoded password in a connection string",
                    "A string literal carries `Password=` / `Pwd=` with a value.", ln)
                break
        m = _CERT.search(bare)
        if m:
            rhs = m.group(1)
            hit = bool(re.search(r"\bTrue\b", rhs, re.I)) and re.search(r"\bFunction\b|\bSub\b", rhs, re.I) is not None
            if not hit and re.search(r"\bFunction\s*\([^)]*\)\s*$", rhs, re.I):
                hit = _always_true_function(lines, i)
            if not hit:
                a = _ADDRESS_OF.search(rhs)
                hit = bool(a) and a.group(1).split(".")[-1].lower() in funcs and _always_true_function(
                    lines, funcs[a.group(1).split(".")[-1].lower()])
            if hit:
                add("DNL-CRY-006", "high", "TLS certificate validation disabled",
                    "ServerCertificateValidationCallback is set to a callback that returns True.", ln)
    return out


def scan(model) -> list[Finding]:
    """REVIEW findings for the VB files of a degraded model (model.vb_files)."""
    out: list[Finding] = []
    for rel in getattr(model, "vb_files", []):
        try:
            text = read_source(model.root / rel)
        except OSError as ex:
            model.notes.append(f"{rel}: unreadable ({ex})")
            continue
        out += _scan_text(rel, text)
    return out
