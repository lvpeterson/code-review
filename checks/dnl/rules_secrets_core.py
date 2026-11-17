"""Secrets committed in appsettings*.json and Properties/launchSettings.json (DNL-SEC-001, DNL-SEC-002,
the ids the web.config rules already use). Every raw entry of every file is read where it is written:
a base-file secret that Production overrides is still committed. Placeholders and Key Vault style
references are not secrets. Development files and launch profiles are local by design, so they count
only when the value looks real, one severity lower.
"""
from __future__ import annotations

import re

from checks.dnl.auth_core import CONN_PW, PLACEHOLDER, SECRET_KEY, is_setting_key
from checks.dnl.cfgctx import Ctx

# Whole-value placeholders beyond auth_core's `$(X)` / `{X}` / `*` forms: `#{X}#`, `${X}`, `%X%`, `<set me>`.
_TOKEN = re.compile(r"(?i)^(\#\{.*\}\#?|\$\{.*\}|\{\{.*\}\}|%[^%]+%|<[^>]*>)$")
# Key Vault / user-secrets style references: the value lives elsewhere.
_REFERENCE = re.compile(r"(?i)^(@microsoft\.keyvault\(|vault:|keyvault:|secret://)")
# Words a developer leaves in a local file; `changeme` is only ignored under the Development rule.
_WEAK = {"password", "pass", "passwd", "pwd", "secret", "test", "testing", "dev", "development", "local",
         "localhost", "example", "sample", "demo", "changeme", "change-me", "change_me", "admin", "root",
         "default", "token", "apikey", "key", "todo", "tbd", "none", "null", "xxxx", "your-secret-here"}
_WEAK_PATTERN = re.compile(r"(?i)^(change[-_ ]?me.*|your[-_ ].*|replace[-_ ]?me.*|todo.*|insert.*|put.*here)$")
# Key names that hold a secret without containing a secret word (`Jwt:Key` is handled separately).
_KEY_SECRET = re.compile(r"(?i)(signing|secret|encryption|symmetric|master|access|shared|private)key$")
_JWT_PATH = re.compile(r"(?i)jwt|signing|bearer|token")


def _placeholder(v: str) -> bool:
    v = v.strip()
    return bool(PLACEHOLDER.match(v) or _TOKEN.match(v) or _REFERENCE.match(v))


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


def _conn_password(value: str) -> str | None:
    """The first real password value of a connection string, or None when it has none (Integrated
    Security, a placeholder, an empty value)."""
    for m in CONN_PW.finditer(value):
        pw = m.group(2).strip()
        if pw and not _placeholder(pw):
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
