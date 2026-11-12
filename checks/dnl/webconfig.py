"""web.config loading for the legacy .NET analyzer: line-tracked parsing,
XDT (Web.Release.config style) transforms, and anonymous-access evaluation.

Pure stdlib. Every element carries two reserved attributes -- the source line
and the rel path of the file it came from -- so findings can point at the file
that actually introduced a setting (base config vs. a transform).
"""
from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from xml.parsers import expat

from checks.dnl.files import iter_dnl_files, read_source

# Reserved attribute keys. They live in a made-up namespace so they can never
# collide with real config attributes, and locators compare only named attrs.
LINE = "{dnl}line"
ORIGIN = "{dnl}file"
NOTES = "{dnl}notes"          # on a transformed root: approximation notes
DIR = "{dnl}dir"              # on chain roots: dir segments relative to the app root
_RESERVED = {LINE, ORIGIN, NOTES, DIR}
_XDT_URI = "XML-Document-Transform"


@dataclass
class WebConfig:
    path: Path
    rel: str
    root: ET.Element | None
    transforms: dict[str, ET.Element] = field(default_factory=dict)
    is_views: bool = False
    error: str | None = None
    transform_errors: list[str] = field(default_factory=list)  # malformed Web.<Name>.config
    _eff: list | None = field(default=None, repr=False)        # effective() cache


def _qname(name: str, is_tag: bool = False) -> str:
    # expat with namespace_separator=" " yields "uri local"; ET wants "{uri}local".
    # Element namespaces are dropped: old configs sometimes declare a default
    # xmlns (".NetConfiguration/v2.0") that would break every find().
    if " " in name:
        uri, local = name.split(" ", 1)
        return local if is_tag else "{%s}%s" % (uri, local)
    return name


def parse_xml_with_lines(text: str, origin: str) -> ET.Element:
    """Parse XML via expat, stamping LINE/ORIGIN (as strings) on each element.
    Raises ValueError on malformed input."""
    parser = expat.ParserCreate(namespace_separator=" ")
    stack: list[ET.Element] = []
    root: list[ET.Element] = []

    def start(name, attrs):
        el = ET.Element(_qname(name, True), {_qname(k): v for k, v in attrs.items()})
        el.set(LINE, str(parser.CurrentLineNumber))
        el.set(ORIGIN, origin)
        if stack:
            stack[-1].append(el)
        else:
            root.append(el)
        stack.append(el)

    def end(_name):
        stack.pop()

    def chars(data):
        if stack:
            stack[-1].text = (stack[-1].text or "") + data

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    try:
        parser.Parse(text, True)
    except expat.ExpatError as e:
        raise ValueError(f"{origin}: {e}") from e
    if not root:
        raise ValueError(f"{origin}: no root element")
    return root[0]


def load_configs(root: Path) -> list[WebConfig]:
    """Load every web.config under root; sibling web.<Name>.config files are
    parsed as XDT transforms for it. Malformed files are reported in .error."""
    files = list(iter_dnl_files(root, (".config",)))
    out: list[WebConfig] = []
    for p in files:
        if p.name.lower() != "web.config":
            continue
        rel = p.relative_to(root).as_posix()
        views = any(s.lower() == "views" for s in Path(rel).parts[:-1])
        cfg = WebConfig(p, rel, None, {}, views)
        try:
            cfg.root = parse_xml_with_lines(read_source(p), rel)
        except (ValueError, OSError) as e:
            cfg.error = str(e)
        for sib in files:
            m = re.fullmatch(r"web\.(.+)\.config", sib.name, re.I)
            if m and sib.parent == p.parent:
                try:
                    cfg.transforms[m.group(1)] = parse_xml_with_lines(
                        read_source(sib), sib.relative_to(root).as_posix())
                except (ValueError, OSError) as e:
                    # No variant for it, but keep the reason for the caller.
                    cfg.transform_errors.append(str(e))
        out.append(cfg)
    return out


# --- XDT ---------------------------------------------------------------

def _is_xdt_key(k: str) -> bool:
    return k.startswith("{") and _XDT_URI in k.split("}")[0]


def _xdt(el: ET.Element, name: str) -> str | None:
    for k, v in el.attrib.items():
        if _is_xdt_key(k) and k.split("}")[1] == name:
            return v
    return None


def _strip_xdt(el: ET.Element) -> None:
    for e in el.iter():
        for k in [k for k in e.attrib if _is_xdt_key(k)]:
            del e.attrib[k]


def _split_call(spec: str) -> tuple[str, list[str]]:
    m = re.fullmatch(r"\s*(\w+)\s*(?:\((.*)\))?\s*", spec or "", re.S)
    if not m:
        return "", []
    args = [a.strip() for a in (m.group(2) or "").split(",") if a.strip()]
    return m.group(1), args


def _plain_attrs(el: ET.Element) -> dict[str, str]:
    return {k: v for k, v in el.attrib.items() if k not in _RESERVED and not _is_xdt_key(k)}


def _matches(parent: ET.Element, t: ET.Element, notes: list[str]) -> list[ET.Element]:
    cands = [c for c in parent if c.tag == t.tag]
    loc, args = _split_call(_xdt(t, "Locator") or "")
    if loc == "Match":
        # Only the named attributes are compared; reserved keys never are.
        return [c for c in cands if all(c.get(a) == t.get(a) for a in args)]
    if loc:
        notes.append(f"xdt:Locator {loc} approximated")
    return cands


def _merge(base: ET.Element, trans: ET.Element, notes: list[str]) -> None:
    for t in list(trans):
        kind, args = _split_call(_xdt(t, "Transform") or "")
        if not kind:
            # Plain element: descend into the first same-tag base child.
            hit = _matches(base, t, notes)
            if hit:
                _merge(hit[0], t, notes)
            continue
        if kind in ("Insert", "InsertIfMissing"):
            if kind == "InsertIfMissing":
                want = _plain_attrs(t)
                if any(c.tag == t.tag and _plain_attrs(c) == want for c in base):
                    continue
            new = copy.deepcopy(t)
            _strip_xdt(new)
            base.append(new)
            continue
        hits = _matches(base, t, notes)
        if kind == "Replace" and hits:
            new = copy.deepcopy(t)
            _strip_xdt(new)
            base[list(base).index(hits[0])] = new
        elif kind == "Remove" and hits:
            base.remove(hits[0])
        elif kind == "RemoveAll":
            for h in hits:
                base.remove(h)
        elif kind == "SetAttributes":
            names = args or list(_plain_attrs(t))
            for h in hits:
                for a in names:
                    if a in t.attrib:
                        h.set(a, t.get(a))
                # The value now comes from the transform file.
                h.set(ORIGIN, t.get(ORIGIN, ""))
                h.set(LINE, t.get(LINE, ""))
        elif kind == "RemoveAttributes":
            for h in hits:
                for a in args:
                    h.attrib.pop(a, None)
        else:
            # Unknown verbs (InsertBefore, Merge...) are not guessed at.
            notes.append(f"xdt:Transform {kind} unsupported")


def apply_transform(base: ET.Element, transform: ET.Element) -> ET.Element:
    """Return a deep copy of base with the XDT transform applied."""
    out = copy.deepcopy(base)
    notes: list[str] = []
    _merge(out, transform, notes)
    if notes:
        out.set(NOTES, "; ".join(dict.fromkeys(notes)))
    return out


def effective(cfg: WebConfig) -> list[tuple[str, ET.Element]]:
    """The base config plus one transformed copy per Web.<Name>.config."""
    if cfg.root is None:
        return []
    if cfg._eff is None:  # transforms are deep copies, so compute once
        cfg._eff = [("base", cfg.root)] + [(n, apply_transform(cfg.root, t)) for n, t in cfg.transforms.items()]
    return list(cfg._eff)


# --- authorization -----------------------------------------------------

def _segs(path: str) -> list[str]:
    return [s.lower() for s in path.replace("\\", "/").split("/") if s not in ("", ".")]


def _rule_sets(root: ET.Element, url_segs: list[str]) -> list[ET.Element]:
    """Authorization elements of one config applicable to the URL, most
    specific first: matching <location> blocks (longest path), then the root."""
    found: list[tuple[int, ET.Element]] = []
    for loc in root.findall("location"):
        ls = _segs(loc.get("path", ""))
        if url_segs[:len(ls)] == ls:
            for auth in loc.findall("system.web/authorization"):
                found.append((len(ls), auth))
    found.sort(key=lambda x: -x[0])  # stable: file order breaks ties
    sets = [a for _, a in found]
    sets += root.findall("system.web/authorization")
    return sets


def _hits_anonymous(rule: ET.Element) -> bool:
    users = {u.strip() for u in rule.get("users", "").split(",")}
    return "?" in users or "*" in users


def _decides(rule: ET.Element) -> bool:
    # A rule limited to some HTTP verbs cannot decide the general outcome.
    return rule.tag in ("allow", "deny") and not rule.get("verbs") and _hits_anonymous(rule)


def anonymous_denied(chain: list[ET.Element], url_path: str) -> tuple[bool, ET.Element | None]:
    """Decide whether an anonymous request to url_path is denied.
    chain: effective roots, app root first, deepest config last. Roots
    stamped with DIR (by config_chain) get location paths rebased to that
    dir; unstamped roots behave as app-root configs."""
    url_segs = _segs(url_path)
    for root in reversed(chain):
        # Location paths are relative to the config's own directory: strip
        # that prefix, and skip the config if the URL is outside it.
        d = _segs(root.get(DIR, ""))
        if url_segs[:len(d)] != d:
            continue
        for auth in _rule_sets(root, url_segs[len(d):]):
            for rule in auth:
                if _decides(rule):
                    return rule.tag == "deny", rule
    return False, None


def config_chain(configs: list[WebConfig], app_dir: Path, page_dir: Path,
                 variant: str = "base") -> list[ET.Element]:
    """Effective roots for the configs from app_dir down to page_dir."""
    app, page = app_dir.resolve(), page_dir.resolve()
    by_dir = {c.path.parent.resolve(): c for c in configs if c.root is not None}
    dirs = [page] + list(page.parents)
    if app not in dirs:
        return []
    dirs = list(reversed(dirs[:dirs.index(app) + 1]))
    out = []
    for d in dirs:
        c = by_dir.get(d)
        if c is None:
            continue
        eff = dict(effective(c))
        key = next((k for k in eff if k.lower() == variant.lower()), "base")
        # Shallow copy (children shared) so the stamp does not touch the
        # cached root, which different app_dirs would stamp differently.
        rel = d.relative_to(app).as_posix()
        stamped = ET.Element(eff[key].tag, {**eff[key].attrib, DIR: "" if rel == "." else rel})
        stamped.extend(eff[key])
        out.append(stamped)
    return out
