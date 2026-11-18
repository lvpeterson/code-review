"""appsettings*.json and Properties/launchSettings.json reader for the ASP.NET Core
configuration rules: every setting flattened to a colon path (how IConfiguration sees it)
with its exact source line, plus the per-environment override order.

Pure stdlib. The JSON reader is its own tolerant parser (comments, trailing commas, BOM,
duplicate keys) because .NET accepts all of those and line numbers must be exact. A file
that cannot be read is never skipped quietly: it carries an `error` and becomes a model note.
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

from .files import iter_dnl_files, read_source
from .project import ProjectModel

# Folders that hold published or generated copies of a settings file, not the app's own.
_SKIP_PARTS = {"wwwroot"}
_APPSETTINGS = re.compile(r"^appsettings(?:\.(?P<env>.+))?\.json$", re.IGNORECASE)
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
_MAX_DEPTH = 200
_MAX_BYTES = 5 * 1024 * 1024    # a real settings file is a few KB; a bigger one is not read (hostile repo)


@dataclass
class Entry:
    key: str           # colon path, original case: "Jwt:Key", arrays "Hosts:0"
    value: object      # str | int | float | bool | None
    file: str          # repo-relative posix path
    line: int
    env: str | None    # None for appsettings.json, else the environment named in the file name


@dataclass
class SettingsFile:
    path: str
    env: str | None
    entries: list[Entry] = field(default_factory=list)
    error: str | None = None


@dataclass
class Settings:
    files: list[SettingsFile] = field(default_factory=list)

    @staticmethod
    def _dir(f: SettingsFile) -> str:
        """The app directory a file belongs to: launchSettings.json sits in <app>/Properties."""
        d = posixpath.dirname(f.path)
        return posixpath.dirname(d) if f.env == "launch" else d

    def scopes(self) -> list[str]:
        """Distinct directories holding appsettings files (one per app), sorted; "" is the root."""
        return sorted({self._dir(f) for f in self.files if f.env != "launch"})

    def _pick(self, env: str | None, scope: str | None) -> list[SettingsFile]:
        want = env.lower() if env is not None else None
        return [f for f in self.files if (f.env.lower() if f.env is not None else None) == want
                and (scope is None or self._dir(f) == scope)]

    def entries(self, env: str | None = None, scope: str | None = None) -> list[Entry]:
        """Raw entries of the files for one environment (None = the base files), optionally of one app dir."""
        return [e for f in self._pick(env, scope) for e in f.entries]

    def effective(self, env: str, scope: str | None = None) -> dict[str, Entry]:
        """Lower-cased key -> the winning entry: base file, overridden by appsettings.<env>.json, of ONE
        app directory (.NET reads each app's own content root). Unscoped is allowed only when a single
        directory holds settings files; merging several apps would hide one app's value behind another's."""
        if scope is None:
            dirs = self.scopes()
            if len(dirs) > 1:
                raise ValueError(f"settings files in {len(dirs)} directories ({', '.join(dirs)}); pass scope=")
        out: dict[str, Entry] = {}
        for e in self.entries(None, scope) + self.entries(env, scope):
            out[e.key.lower()] = e
        return out


class _Bad(ValueError):
    pass


class _Parser:
    """Recursive-descent JSON reader that tolerates `//` and `/* */` comments and trailing
    commas and records the line of every object member and array element."""

    def __init__(self, text: str):
        self.t = text
        self.i = 0
        self.line = 1

    def fail(self, msg: str):
        raise _Bad(f"{msg} at line {self.line}")

    def ws(self) -> None:
        t = self.t
        while self.i < len(t):
            c = t[self.i]
            if c == "\n":
                self.line += 1
                self.i += 1
            elif c in " \t\r\ufeff":
                self.i += 1
            elif t.startswith("//", self.i):
                while self.i < len(t) and t[self.i] != "\n":
                    self.i += 1
            elif t.startswith("/*", self.i):
                end = t.find("*/", self.i + 2)
                if end < 0:
                    self.fail("unterminated comment")
                self.line += t.count("\n", self.i, end)
                self.i = end + 2
            else:
                return

    def string(self) -> str:
        t, start = self.t, self.i
        self.i += 1
        while self.i < len(t):
            c = t[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == '"':
                self.i += 1
                try:
                    return json.loads(t[start:self.i], strict=False)
                except ValueError:
                    self.fail("bad string escape")
            if c == "\n":
                self.line += 1
            self.i += 1
        self.fail("unterminated string")

    def value(self, depth: int):
        if depth > _MAX_DEPTH:
            self.fail("nesting too deep")
        self.ws()
        t = self.t
        if self.i >= len(t):
            self.fail("unexpected end of file")
        c = t[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if t.startswith(word, self.i):
                self.i += len(word)
                return val
        m = _NUMBER.match(t, self.i)
        if m:
            self.i = m.end()
            s = m.group()
            return float(s) if re.search(r"[.eE]", s) else int(s)
        self.fail(f"unexpected character {c!r}")

    def obj(self, depth: int):
        members: list[tuple[str, int, object]] = []
        self.i += 1
        while True:
            self.ws()
            if self.i >= len(self.t):
                self.fail("unterminated object")
            if self.t[self.i] == "}":
                self.i += 1
                return ("obj", members)
            if self.t[self.i] != '"':
                self.fail("expected a property name")
            line = self.line
            key = self.string()
            self.ws()
            if self.i >= len(self.t) or self.t[self.i] != ":":
                self.fail("expected ':'")
            self.i += 1
            members.append((key, line, self.value(depth + 1)))
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == ",":
                self.i += 1
            elif self.i < len(self.t) and self.t[self.i] == "}":
                continue
            else:
                self.fail("expected ',' or '}'")

    def arr(self, depth: int):
        items: list[tuple[int, object]] = []
        self.i += 1
        while True:
            self.ws()
            if self.i >= len(self.t):
                self.fail("unterminated array")
            if self.t[self.i] == "]":
                self.i += 1
                return ("arr", items)
            line = self.line
            items.append((line, self.value(depth + 1)))
            self.ws()
            if self.i < len(self.t) and self.t[self.i] == ",":
                self.i += 1
            elif self.i < len(self.t) and self.t[self.i] == "]":
                continue
            else:
                self.fail("expected ',' or ']'")


def parse_json(text: str):
    """Parse tolerant JSON to a ("obj", [(key, line, node)]) / ("arr", [(line, node)]) / scalar tree.
    Raises ValueError on malformed input."""
    p = _Parser(text)
    try:
        node = p.value(0)
        p.ws()
        if p.i < len(text):
            p.fail("unexpected data after the top-level value")
    except RecursionError:
        raise _Bad("nesting too deep")
    return node


def _flatten(node, prefix: str, line: int, out: list[tuple[str, object, int]]) -> None:
    if isinstance(node, tuple) and node[0] == "obj":
        last: dict[str, tuple[str, int, object]] = {}
        for key, ln, child in node[1]:
            last.pop(key.lower(), None)        # duplicate (case-insensitive): the last one wins
            last[key.lower()] = (key, ln, child)
        for key, ln, child in last.values():
            _flatten(child, f"{prefix}:{key}" if prefix else key, ln, out)
    elif isinstance(node, tuple) and node[0] == "arr":
        for idx, (ln, child) in enumerate(node[1]):
            _flatten(child, f"{prefix}:{idx}" if prefix else str(idx), ln, out)
    else:
        out.append((prefix, node, line))


def _read(path: Path, rel: str, env: str | None, launch: bool) -> SettingsFile:
    sf = SettingsFile(rel, env)
    try:
        tree = parse_json(read_source(path))
    except (OSError, ValueError) as ex:
        sf.error = f"{rel}: settings file could not be read ({ex}); its settings were not analyzed"
        return sf
    if not (isinstance(tree, tuple) and tree[0] == "obj"):
        sf.error = f"{rel}: settings file is not a JSON object; its settings were not analyzed"
        return sf
    flat: list[tuple[str, object, int]] = []
    if not launch:
        _flatten(tree, "", 0, flat)
    else:
        # profiles.<name>.environmentVariables: process environment of a local run; `A__B` is `A:B`.
        for pkey, _pl, prof in tree[1]:
            if pkey.lower() != "profiles" or not (isinstance(prof, tuple) and prof[0] == "obj"):
                continue
            for _name, _l, body in prof[1]:
                if not (isinstance(body, tuple) and body[0] == "obj"):
                    continue
                for bkey, _bl, evars in body[1]:
                    if bkey.lower() == "environmentvariables" and isinstance(evars, tuple) and evars[0] == "obj":
                        _flatten(evars, "", 0, flat)
        flat = [(k.replace("__", ":"), v, ln) for k, v, ln in flat]
    sf.entries = [Entry(k, v, rel, ln, env) for k, v, ln in flat]
    return sf


def load_settings(model: ProjectModel) -> Settings:
    """Settings files of the projects this model owns. A malformed file keeps its SettingsFile
    (error set), adds a model note and never stops the others."""
    out = Settings()
    for path in iter_dnl_files(model.root, (".json",)):
        rel = path.relative_to(model.root)
        if any(part.lower() in _SKIP_PARTS for part in rel.parts[:-1]):
            continue
        name = path.name
        m = _APPSETTINGS.match(name)
        launch = name.lower() == "launchsettings.json" and rel.parent.name.lower() == "properties"
        if not (m or launch) or not model.owns(path):
            continue
        env = "launch" if launch else m.group("env")
        # A symlink (a device or a file outside the repo) or a huge file is never read: it could hang the scan.
        skip = None
        try:
            if path.is_symlink():
                skip = "is a symbolic link"
            elif path.stat().st_size > _MAX_BYTES:
                skip = f"is larger than {_MAX_BYTES // (1024 * 1024)} MB"
        except OSError as ex:
            skip = f"could not be inspected ({ex})"
        if skip:
            model.notes.append(f"{rel.as_posix()}: settings file {skip}; its settings were not analyzed")
            continue
        sf = _read(path, rel.as_posix(), env, launch)
        if sf.error:
            model.notes.append(sf.error)
        out.files.append(sf)
    return out
