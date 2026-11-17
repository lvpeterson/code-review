"""Secrets committed in appsettings*.json and Properties/launchSettings.json (DNL-SEC-001, DNL-SEC-002,
the ids the web.config rules already use). Every raw entry of every file is read where it is written:
a base-file secret that Production overrides is still committed. Placeholders and Key Vault style
references are not secrets. Development files and launch profiles are local by design, so they count
only when the value looks real, one severity lower.
"""
from __future__ import annotations

import re

from checks.dnl.auth_core import SECRET_KEY, is_setting_key
from checks.dnl.cfgctx import Ctx

# A placeholder is ONE token that is the entire value, with no literal text around it (`${A}real${B}`
# is a real value): `$(X)`, `${X}`, `{X}`, `{{X}}`, `#{X}#`, `%X%`, `<...>`, `***`, `xxx`, `__X__`.
_TOKEN = re.compile(r"(?i)^(\$\([^()\s]+\)|\$\{[^{}\s]+\}|\{[a-z_]\w*\}|\{\{[^{}]+\}\}|\#\{[^{}]+\}\#?"
                    r"|%[^%\s]+%|<[^<>]+>|\*+|x+|__\w+__)$")
# Key Vault / user-secrets style references: the value lives elsewhere. Only a COMPLETE reference counts;
# a bare `vault:` / `keyvault:` prefix is a reference only as a whole setting value, or (inside a
# connection string, where `vault:Real123x` could be a password) when a `/` path follows.
_KV_FULL = re.compile(r"(?i)^@microsoft\.keyvault\([^()]+\)$")
_BARE_REF = re.compile(r"(?i)^(vault:|keyvault:)[\w./\-]+$")
_BARE_REF_PATH = re.compile(r"(?i)^(vault:|keyvault:)[\w.\-]*/[\w./\-]*$")
_SECRET_URI = re.compile(r"(?i)^secret://[\w./\-]+$")
# `Password=` / `Pwd=` part of an ADO.NET connection string; a prefix such as `DB` is accepted (an
# app-defined keyword), the value is read by _conn_value.
_PW_KEYWORD = re.compile(r"(?i)(?:^|[;\s])\w*(?:password|pwd)\s*=\s*")
# Words a developer leaves in a local file; `changeme` is only ignored under the Development rule.
_WEAK = {"password", "pass", "passwd", "pwd", "secret", "test", "testing", "dev", "development", "local",
         "localhost", "example", "sample", "demo", "changeme", "change-me", "change_me", "admin", "root",
         "default", "token", "apikey", "key", "todo", "tbd", "none", "null", "xxxx", "your-secret-here"}
_WEAK_PATTERN = re.compile(r"(?i)^(change[-_ ]?me.*|your[-_ ].*|replace[-_ ]?me.*|todo.*|insert.*|put.*here)$")
# Key names that hold a secret without containing a secret word (`Jwt:Key` is handled separately).
_KEY_SECRET = re.compile(r"(?i)(signing|secret|encryption|symmetric|master|access|shared|private)key$")
_JWT_PATH = re.compile(r"(?i)jwt|signing|bearer|token")


def _placeholder(v: str, whole: bool = True) -> bool:
    """True for an empty value, a lone placeholder token or a complete reference. `whole` is False for the
    password part of a connection string, where only path-shaped bare references count."""
    v = v.strip()
    if not v or _TOKEN.match(v) or _KV_FULL.match(v) or _SECRET_URI.match(v):
        return True
    return bool((_BARE_REF if whole else _BARE_REF_PATH).match(v))


def _looks_real(v: str) -> bool:
    """The Development rule: at least 8 characters, not a weak word, not one repeated character."""
    v = v.strip()
    return (len(v) >= 8 and v.lower() not in _WEAK and not _WEAK_PATTERN.match(v)
            and len(set(v.lower())) > 1)


def _lower(sev: str) -> str:
    return {"high": "medium", "medium": "low"}.get(sev, sev)


def _segments(key: str) -> list[str]:
    """Colon segments without trailing array indexes (`Secrets:0` is named by `Secrets`)."""
    segs = key.split(":")
    while len(segs) > 1 and segs[-1].isdigit():
        segs.pop()
    return segs


def _is_conn_key(segs: list[str]) -> bool:
    return segs[0].lower() == "connectionstrings" and len(segs) > 1 or segs[-1].lower().endswith("connectionstring")


def _is_secret_key(segs: list[str]) -> bool:
    last = segs[-1]
    if SECRET_KEY.search(last) and not is_setting_key(last):
        return True
    if _KEY_SECRET.search(last):
        return True
    # `Jwt:Key`, `Authentication:Bearer:Key`: a bare `Key` under a token / signing section.
    return last.lower() == "key" and any(_JWT_PATH.search(s) for s in segs[:-1])


def _conn_value(text: str, i: int) -> str:
    """The value starting at text[i]: `"..."` / `'...'` (a doubled quote is a literal quote) read to the closing
    quote, `{...}` kept with its braces, else up to the next `;`."""
    if i < len(text) and text[i] in "\"'":
        q, out, j = text[i], [], i + 1
        while j < len(text):
            if text[j] == q:
                if text[j + 1:j + 2] == q:
                    out.append(q)
                    j += 2
                    continue
                break
            out.append(text[j])
            j += 1
        return "".join(out)
    if i < len(text) and text[i] == "{":
        j = i + 1
        while j < len(text):
            if text[j] == "}":
                if text[j + 1:j + 2] == "}":
                    j += 2
                    continue
                return text[i:j + 1]
            j += 1
        return text[i:]
    j = text.find(";", i)
    return text[i:] if j < 0 else text[i:j]


def _conn_password(value: str) -> str | None:
    """The first real password value of a connection string, or None when it has none (Integrated
    Security, a placeholder, an empty value). The shared CONN_PW cannot read a quoted value that holds a
    `;`, so the parts are read here."""
    for m in _PW_KEYWORD.finditer(value):
        pw = _conn_value(value, m.end()).strip()
        if pw and not _placeholder(pw, whole=False):
            return pw
    return None


def check(ctx: Ctx) -> None:
    if ctx.settings is None:
        return
    seen: set = set()
    for f in ctx.settings.files:
        for e in f.entries:
            if not isinstance(e.value, str) or not e.value.strip() or _placeholder(e.value):
                continue
            segs = _segments(e.key)
            local = e.env is not None and e.env.lower() in ("development", "launch")
            where = "the launch profile" if e.env == "launch" else e.file
            if _is_conn_key(segs):
                pw = _conn_password(e.value)
                if pw is None or (local and not _looks_real(pw)):
                    continue
                cid, sev, title = "DNL-SEC-001", "high", "Password in connection string"
                desc = (f"Setting \"{e.key}\" in {where} embeds a database password; move it to user secrets, "
                        "environment variables or a key vault and keep only a reference in the file.")
            elif _is_secret_key(segs):
                if local and not _looks_real(e.value):
                    continue
                cid, sev, title = "DNL-SEC-002", "medium", "Secret in application settings"
                desc = (f"Setting \"{e.key}\" in {where} holds a hard-coded secret value; move it to user "
                        "secrets, environment variables or a key vault.")
            else:
                continue
            if local:
                sev = _lower(sev)
                desc += " The file is for local development, so the severity is lowered; make sure it is not deployed."
            key = (cid, e.file, e.line, e.key)
            if key not in seen:
                seen.add(key)
                ctx.add(cid, sev, title, desc, e.file, e.line)
