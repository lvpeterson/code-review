"""Insecure deserialization and XML external entity findings read from code (legacy .NET Framework).

DNL-DESER-001  BinaryFormatter / SoapFormatter / NetDataContractSerializer / LosFormatter /
               ObjectStateFormatter `.Deserialize` / `.ReadObject`; REVIEW here, proven by rules_taint
DNL-DESER-002  Json.NET TypeNameHandling other than None (settings object, serializer, attribute)
DNL-DESER-003  `new JavaScriptSerializer(new SimpleTypeResolver())`
DNL-XXE-001    XML parsing that resolves DTDs / external entities; medium here, proven by rules_taint
DNL-XXE-002    project targets .NET Framework < v4.5.2 and parses XML (one finding per project)

Proven DESER-001 / XXE-001 are taint findings (sink kinds `deser` / `xxe`): this module reports only the
configuration shape and skips every line that already carries a taint finding for the same rule.
`insecure_xxe_lines` is the other direction: the taint sink table matches every XML entry point, and
rules_taint keeps an `xxe` hit only when its line is a parse this module judged insecure.

Objects are tracked like rules_crypto tracks ciphers: a field, property, parameter or local holds a
`JsonSerializerSettings` / `JsonSerializer` / `XmlReaderSettings` / `XmlDocument` / `XmlTextReader`, and
every assignment to a member of it in any method of the solution (constructors, other types reaching a
static field as `Type.Member`) and every object initializer or property initializer counts. Types are
matched by the names written in source (Json.NET does not resolve against the reference set), `sym` and
`type_full` when present.

XmlDocument safety follows the owning project's target framework: below v4.5.2 the default resolver
follows external entities unless `XmlResolver = null` was assigned; from v4.5.2 on it is unsafe only
when a non-null resolver is assigned. A reader passed to `Load` / `XDocument.Load` / `XPathDocument` is
judged where the reader is created (`new XmlTextReader`, `XmlReader.Create(.., settings)`).

Findings are route-less unless the code sits inside a route handler's own method; route-less ones are
placed by the analyzers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from checks.dnl import taint_solver
from checks.dnl.findings import dnl_finding
from checks.dnl.ir import MethodIR, TypeIR, call_name, receiver_text, walk
from checks.dnl.project import ProjectModel
from checks.dnl.typestate import RouteIndex, is_null, iter_bodies, simple, tail, type_of
from core.models import Finding

_FORMATTERS = {"binaryformatter", "soapformatter", "netdatacontractserializer", "losformatter",
               "objectstateformatter"}
_JSON_T = {"jsonserializersettings", "jsonserializer"}
_JSON_DESER = {"deserializeobject", "deserializeanonymoustype", "populateobject"}
_JSON_ATTRS = {"jsonproperty", "jsonobject", "jsonarray", "jsondictionary"}
_TNH_KEYS = {"typenamehandling", "itemtypenamehandling"}
_TRACKED = _JSON_T | {"xmlreadersettings", "xmldocument", "xmldatadocument", "xmltextreader"}
_DOC_T = {"xmldocument", "xmldatadocument"}
_READER_T = {"xmltextreader", "xmlreader", "xmlvalidatingreader"}
_PARSE_ONLY = {("xdocument", "load"), ("xelement", "load"), ("xdocument", "parse"), ("xelement", "parse"),
               ("dataset", "readxml")}
_VERSION = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")
_MODERN = (4, 5, 2)


def _version(text: str | None) -> tuple[int, int, int] | None:
    m = _VERSION.fullmatch((text or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else None


@dataclass
class _Event:
    member: str
    value: dict | None
    file: str
    line: int
    b: object = None          # the _Body the event was written in (resolves names in its value)
    path: tuple = ()          # ids of the conditional constructs (if / loop / try / lambda) around it


@dataclass
class _Body:
    t: TypeIR
    label: str
    method: MethodIR | None
    nodes: list[dict]
    scope: tuple
    locals: dict[str, tuple[str, tuple]] = field(default_factory=dict)
    paths: dict[int, tuple] = field(default_factory=dict)     # id(node) -> conditional path
    loops: set = field(default_factory=set)                   # ids of the loop nodes in the body


@dataclass
class _Site:
    """One detected construct: a finding position plus what it is."""
    rule: str
    file: str
    line: int
    t: TypeIR
    where: str
    text: str
    insecure: bool = True      # xml parse sites: whether the parser resolves entities


def _is_none_tnh(v) -> bool:
    """The literal 0 or a `TypeNameHandling.None` member access. A bare name that merely spells `none` is
    not None: it is resolved through its assignments (`_Scan._is_none`)."""
    if not isinstance(v, dict):
        return False
    if v.get("k") == "lit":
        return v.get("v") == 0 and not isinstance(v.get("v"), bool)
    return v.get("k") == "member" and (v.get("name") or "").lower() == "none" \
        and tail(v.get("obj")) == "typenamehandling"


_COND_KINDS = ("if", "loop", "try", "lambda", "cond")     # C# switch / VB Select Case lower to `if`
_SHORT_CIRCUIT = {"&&", "||", "andalso", "orelse", "??"}
_JSONISH = {"jsonserializersettings", "jsonserializer", "jsonformatter", "jsonmediatypeformatter",
            "mediatypeformatter"}
_DTD_WORDS = ("prohibit", "ignore", "parse")


def _mark_paths(node, path: tuple, out: dict, loops: set | None = None) -> None:
    """id(node) -> the conditional constructs enclosing it (a statement in the same or an enclosing
    block of another has a prefix of its path). The right operand of a short-circuit operator is
    conditional too."""
    if isinstance(node, dict):
        out[id(node)] = path
        sub = path + (id(node),) if node.get("k") in _COND_KINDS else path
        if loops is not None and node.get("k") == "loop":
            loops.add(id(node))
        short = node.get("k") == "bin" and str(node.get("op") or "").lower() in _SHORT_CIRCUIT
        for key, v in node.items():
            if isinstance(v, (dict, list)):
                _mark_paths(v, sub + (id(node),) if short and key == "r" else sub, out, loops)
    elif isinstance(node, list):
        for v in node:
            _mark_paths(v, path, out, loops)


def _classify_dtd(e) -> str | None:
    """prohibit / ignore / parse for an enum member expression (not a bare name that merely spells one)."""
    if isinstance(e, dict) and e.get("k") == "member" and (e.get("name") or "").lower() in _DTD_WORDS \
            and tail(e.get("obj")) == "dtdprocessing":
        return (e.get("name") or "").lower()
    return None


def _classify_tnh(e) -> str | None:
    if _is_none_tnh(e):
        return "none"
    if isinstance(e, dict) and (e.get("k") in ("lit", "cast") or (
            e.get("k") == "member" and tail(e.get("obj")) == "typenamehandling")):
        return "other"
    return None


class _Scan:
    def __init__(self, model: ProjectModel, refs):
        self.model = model
        self.sites: list[_Site] = []
        self.parses: list[_Site] = []          # every XML parse, for XXE-002
        self.routes = RouteIndex(refs)
        self.field_types: dict[tuple, str] = {}
        self.events: dict[tuple, list[_Event]] = {}
        self.new_key: dict[int, tuple] = {}     # id(new node) -> holder key it was assigned to
        self.consumed: set[int] = set()         # id(new node) reported through a call
        self.bodies: list[_Body] = []
        self._by_method: dict[int, _Body] = {}
        self.assigns: dict[tuple, list] = {}      # holder key -> [(value expr, body)]: initializer + every `=`
        self.local_init: dict[tuple, dict] = {}   # holder key -> call it was initialised / assigned from
        self.used: set[tuple] = set()             # holder keys a Load / Create in the scan used
        self.stray: list[tuple] = []              # TypeNameHandling set on an untraceable receiver
        self._callers: dict[int, list] | None = None
        self._owners: dict[int, list[TypeIR]] = {}

    def _values(self, expr, b: _Body, classify, depth: int = 0) -> set[str]:
        """The classified values an expression can take. A local or field is followed through its
        declaration and EVERY assignment to it (a name is never trusted for its spelling); anything that
        cannot be resolved contributes "" (unknown)."""
        if depth > 4 or not isinstance(expr, dict):
            return {""}
        w = classify(expr)
        if w is not None:
            return {w}
        r = self.resolve(expr, b)
        vals = self.assigns.get(r[0]) if r else None
        if not vals:
            return {""}
        out: set[str] = set()
        for v, vb in vals:
            out |= self._values(v, vb, classify, depth + 1)
        return out

    def _dtd_safe(self, e: _Event) -> bool:
        """The DtdProcessing value is Prohibit / Ignore on every path."""
        vals = self._values(e.value, e.b, _classify_dtd) if e.b is not None else {""}
        return vals <= {"prohibit", "ignore"}

    def _dtd_state(self, events: list[_Event], is_settings: bool) -> bool | None:
        """Last word on DTD handling over the events of one parser object: True when DTDs are parsed
        (settings; any Parse or unresolvable value counts) / prohibited or ignored (text reader), None
        when never set."""
        state = None
        for e in sorted(events, key=lambda e: (e.file, e.line)):
            if e.member == "dtdprocessing":
                safe = self._dtd_safe(e)
                state = (not safe) if is_settings else safe
            elif e.member == "prohibitdtd" and isinstance(e.value, dict) and e.value.get("k") == "lit" \
                    and isinstance(e.value.get("v"), bool):
                state = (not e.value["v"]) if is_settings else bool(e.value["v"])
        return state

    def _safe_event(self, e: _Event, kind: str) -> bool:
        """An assignment that makes the parser safe (null resolver / Prohibit / ProhibitDtd = true)."""
        if e.member == "xmlresolver":
            return is_null(e.value)
        if kind == "doc":
            return False
        if e.member == "dtdprocessing":
            return self._dtd_safe(e)
        return e.member == "prohibitdtd" and isinstance(e.value, dict) and e.value.get("v") is True

    def _unconditional(self, events: list[_Event], kind: str, path: tuple | None, b) -> list[_Event]:
        """Drop the safe-making assignments that sit inside a conditional / loop / try the statement at
        `path` (in the body `b`) is not inside: they may not have run. An assignment written in another
        method (a field holder) counts only when it is unconditional within its own method."""
        p = path or ()
        return [e for e in events if not (self._safe_event(e, kind) and (
            e.path != p[:len(e.path)] if e.b is b else bool(e.path)))]

    def _is_none(self, v, b) -> bool:
        """A TypeNameHandling value that is None on every path (never judged by the spelling of a name)."""
        if _is_none_tnh(v):
            return True
        return b is not None and isinstance(v, dict) and v.get("k") == "name"             and self._values(v, b, _classify_tnh) == {"none"}

    # -- structure ---------------------------------------------------------------------

    def _build(self) -> None:
        for t in self.model.types():
            if t.kind == "enum":
                continue
            for f in t.fields:
                self.field_types[("f", t.full_name.lower(), f.name.lower())] = type_of(f.type, None, f.init)
            for p in t.properties:
                self.field_types[("f", t.full_name.lower(), p.name.lower())] = type_of(p.type, None, p.init)
            raw = list(iter_bodies(t))
            for label, m, body, scope in raw:
                b = _Body(t, label, m, list(walk(body)), scope)
                if m is not None:
                    for p in m.params:
                        b.locals[p.name.lower()] = (simple(p.type), ("l", t.file, scope, p.name.lower()))
                _mark_paths(body, (), b.paths, b.loops)
                if scope[0] in ("fi", "pi") and body:
                    self.assigns.setdefault(("f", t.full_name.lower(), label.lower()), []).append((body[0], b))
                for n in b.nodes:
                    if n.get("k") == "local" and n.get("name"):
                        nm = n["name"].lower()
                        ty = type_of(n.get("type"), n.get("type_full"), n.get("init")) or b.locals.get(nm, ("",))[0]
                        b.locals[nm] = (ty, ("l", t.file, scope, nm))
                        if isinstance(n.get("init"), dict):
                            self.assigns.setdefault(b.locals[nm][1], []).append((n["init"], b))
                self.bodies.append(b)

    def _owner_types(self, t: TypeIR) -> list[TypeIR]:
        """The type (all partials) plus its base types that live in the solution."""
        if id(t) not in self._owners:
            same = [d for d in self.model.find_types(t.name.split(".")[-1]) if d.full_name == t.full_name] or [t]
            out = list(same)
            for b in self.model.base_chain(t):
                out += [d for d in self.model.find_types(b.split(".")[-1].split("<")[0]) if d not in out]
            self._owners[id(t)] = out
        return self._owners[id(t)]

    def _member_key(self, types: list[TypeIR], name: str) -> tuple[tuple, str] | None:
        nm = name.lower()
        for d in types:
            if any(f.name.lower() == nm for f in d.fields) or any(p.name.lower() == nm for p in d.properties):
                key = ("f", d.full_name.lower(), nm)
                return key, self.field_types.get(key, "")
        return None

    def resolve(self, expr, b: _Body) -> tuple[tuple, str] | None:
        """(holder key, lowered simple type) of a local, parameter, field, property or `Type.Member`."""
        if not isinstance(expr, dict):
            return None
        k = expr.get("k")
        if k == "name":
            nm = (expr.get("id") or "").lower()
            if nm in b.locals:
                ty, key = b.locals[nm]
                return key, ty
            return self._member_key(self._owner_types(b.t), nm)
        if k == "member":
            obj, nm = expr.get("obj"), expr.get("name") or ""
            if tail(obj) in ("this", "me", "mybase", "base") or obj is None:
                return self._member_key(self._owner_types(b.t), nm)
            text = receiver_text(obj)
            head = text.split(".")[0].lower()
            if text and head not in b.locals and not self._member_key(self._owner_types(b.t), head):
                types = self.model.find_types(text.split(".")[-1])
                if types:
                    return self._member_key(types + [x for t in types for x in self._owner_types(t)], nm)
        return None

    # -- events ------------------------------------------------------------------------------

    def _add_events(self, key: tuple, node: dict, b: _Body) -> None:
        self.new_key[id(node)] = key
        self.events.setdefault(key, [])
        for ent in node.get("init") or []:
            v = ent.get("value")
            self.events[key].append(_Event((ent.get("name") or "").lower(), v, b.t.file,
                                           (v or {}).get("line") or node.get("line", 0), b,
                                           b.paths.get(id(node), ())))

    def _collect(self) -> None:
        for b in self.bodies:
            for n in b.nodes:
                k = n.get("k")
                if k == "local" and isinstance(n.get("init"), dict) and n["init"].get("k") == "new":
                    ty = simple(n["init"].get("type_full") or n["init"].get("type"))
                    if ty in _TRACKED:
                        self._add_events(b.locals[n["name"].lower()][1], n["init"], b)
                elif k == "local" and isinstance(n.get("init"), dict) and n["init"].get("k") == "call":
                    self.local_init.setdefault(b.locals[n["name"].lower()][1], n["init"])
                elif k == "new" and simple(n.get("type_full") or n.get("type")) not in _TRACKED:
                    for ent in n.get("init") or []:
                        if (ent.get("name") or "").lower() in _TNH_KEYS:
                            self.stray.append((b, (ent.get("value") or {}).get("line") or n.get("line", 0),
                                               ent.get("value"), None, None if not self.model.find_types(
                                                   simple(n.get("type_full") or n.get("type"))) else (None, "x")))
                elif k == "assign" and n.get("op") == "=":
                    tgt, val = n.get("target"), n.get("value")
                    if isinstance(tgt, dict) and tgt.get("k") == "member":
                        r = self.resolve(tgt.get("obj"), b)
                        if r and r[1] in _TRACKED:
                            self.events.setdefault(r[0], []).append(
                                _Event((tgt.get("name") or "").lower(), val, b.t.file, n.get("line", 0), b,
                                       b.paths.get(id(n), ())))
                            continue
                        if (tgt.get("name") or "").lower() in _TNH_KEYS:
                            self.stray.append((b, n.get("line", 0), val, tgt.get("obj"), r))
                    r = self.resolve(tgt, b)
                    if r:
                        self.assigns.setdefault(r[0], []).append((val, b))
                    if r and isinstance(val, dict) and val.get("k") == "call":
                        self.local_init.setdefault(r[0], val)
                    if r and r[1] in _TRACKED and isinstance(val, dict) and val.get("k") == "new" \
                            and simple(val.get("type_full") or val.get("type")) in _TRACKED:
                        self._add_events(r[0], val, b)
        # field / property initializers `T X = new T { .. }` hold their members as events too
        for b in self.bodies:
            if b.scope[0] in ("fi", "pi") and b.nodes:
                init = b.nodes[0]
                if init.get("k") == "new" and simple(init.get("type_full") or init.get("type")) in _TRACKED:
                    key = ("f", b.t.full_name.lower(), b.label.lower())
                    self._add_events(key, init, b)

    def _json_looking(self, obj, resolved, value, b: _Body) -> bool:
        """A TypeNameHandling assignment on a receiver that is not a tracked settings holder is a finding
        when the value is a TypeNameHandling member, the receiver chain names Json.NET / Web API formatter
        settings, the receiver type is unresolved, or it is a Json.NET / formatter type (then any value that
        is not None on every path counts: a number, a cast, a variable); an unrelated project type's
        member is not."""
        if isinstance(value, dict) and value.get("k") == "member" and tail(value.get("obj")) == "typenamehandling":
            return True
        chain = receiver_text(obj).lower()
        if any(w in chain for w in ("serializersettings", "jsonserializer", "jsonformatter", "formatters")):
            return True
        if resolved is None:
            return True
        return resolved[1] in _JSONISH and self._values(value, b, _classify_tnh) != {"none"}

    def _events_of_new(self, node: dict, b: _Body) -> list[_Event]:
        key = self.new_key.get(id(node))
        if key is not None:
            return self.events.get(key, [])
        return [_Event((e.get("name") or "").lower(), e.get("value"), b.t.file, node.get("line", 0), b,
                       b.paths.get(id(node), ()))
                for e in node.get("init") or []]

    # -- output --------------------------------------------------------------------------------

    def _site(self, rule, b: _Body, line: int, text: str, *, insecure: bool = True, parse: bool = False) -> None:
        s = _Site(rule, b.t.file, line, b.t, b.label, text, insecure)
        if parse:
            self.parses.append(s)
        if insecure:
            self.sites.append(s)

    # -- detection -----------------------------------------------------------------------------

    def run(self) -> None:
        self._build()
        self._collect()
        json_used: set[tuple] = set()
        for b in self.bodies:
            for n in b.nodes:
                k = n.get("k")
                if k == "call":
                    self._call(n, b, json_used)
                elif k == "new":
                    self._new(n, b)
                elif k == "assign" and n.get("op") == "=":
                    tgt, val = n.get("target"), n.get("value")
                    if tail(tgt) == "typeresolver" and isinstance(val, dict) and val.get("k") == "new" \
                            and simple(val.get("type_full") or val.get("type")) == "simpletyperesolver":
                        self._site("DNL-DESER-003", b, n.get("line", 0),
                                   "JavaScriptSerializer.TypeResolver is set to a SimpleTypeResolver")
        self._json_settings(json_used)
        self._attributes()
        self._escapes()

    def _recv_type(self, call: dict, b: _Body) -> str:
        sym = call.get("sym") or ""
        if sym:
            return simple(sym.rsplit(".", 1)[0])
        recv = (call.get("fn") or {}).get("obj")
        if not isinstance(recv, dict):
            return ""
        if recv.get("k") == "new":
            return simple(recv.get("type_full") or recv.get("type"))
        r = self.resolve(recv, b)
        if r:
            return r[1]
        return tail(recv)       # static call `XmlReader.Create(..)`

    def _unsafe_json(self, events: list[_Event]) -> list[_Event]:
        return [e for e in events if e.member in _TNH_KEYS and not self._is_none(e.value, e.b)]

    def _json_unsafe_holder(self, expr, b: _Body) -> tuple[tuple | None, list[_Event]]:
        """(holder key, unsafe events) for an expression that is a settings / serializer holder or an inline new."""
        if isinstance(expr, dict) and expr.get("k") == "new" and simple(expr.get("type_full") or expr.get("type")) in _JSON_T:
            return None, self._unsafe_json(self._events_of_new(expr, b))
        r = self.resolve(expr, b)
        if r and r[1] in _JSON_T:
            return r[0], self._unsafe_json(self.events.get(r[0], []))
        return None, []

    def _call(self, n: dict, b: _Body, json_used: set) -> None:
        name = (call_name(n) or "").lower()
        line = n.get("line", 0)
        args = list(n.get("args") or []) + list((n.get("named") or {}).values())
        rtype = self._recv_type(n, b)
        recv = (n.get("fn") or {}).get("obj")
        # -- DESER-001 (REVIEW; a taint finding on the same line wins)
        if name in ("deserialize", "readobject") and rtype in _FORMATTERS:
            self._site("DNL-DESER-001", b, line, f"{_rtype_label(rtype)}.{call_name(n)} rebuilds arbitrary object "
                       "graphs from its input; no request-derived input was proven to reach it")
        # -- DESER-002 at a call using an unsafe settings object / serializer
        if (name in _JSON_DESER and rtype in ("jsonconvert", "jsonserializer", "")) or \
                (name == "create" and rtype == "jsonserializer"):
            for a in args:
                key, bad = self._json_unsafe_holder(a, b)
                if bad:
                    if key is not None:
                        json_used.add(key)
                    elif isinstance(a, dict):
                        self.consumed.add(id(a))
                    self._site("DNL-DESER-002", b, line, "Json.NET is called with TypeNameHandling = "
                               f"{tail(bad[0].value) or 'a non-None value'}, which lets the payload pick the "
                               "types to instantiate")
        if name in ("deserialize", "populate") and isinstance(recv, dict):
            key, bad = self._json_unsafe_holder(recv, b)
            if bad:
                if key is not None:
                    json_used.add(key)
                else:
                    self.consumed.add(id(recv))
                self._site("DNL-DESER-002", b, line, "A JsonSerializer with TypeNameHandling = "
                           f"{tail(bad[0].value) or 'a non-None value'} deserializes here")
        # -- XML
        self._xml_call(n, name, rtype, args, b)

    def _new(self, n: dict, b: _Body) -> None:
        ty = simple(n.get("type_full") or n.get("type"))
        line = n.get("line", 0)
        args = n.get("args") or []
        if ty == "javascriptserializer" and args:
            for a in args:
                is_res = False
                if isinstance(a, dict) and a.get("k") == "new":
                    is_res = simple(a.get("type_full") or a.get("type")) == "simpletyperesolver"
                else:
                    r = self.resolve(a, b)
                    is_res = bool(r) and r[1] == "simpletyperesolver"
                if is_res:
                    self._site("DNL-DESER-003", b, line, "JavaScriptSerializer is built with a SimpleTypeResolver, "
                               "so the payload can name any type to instantiate")
                    break
        elif ty == "xmltextreader":
            events = self._events_of_new(n, b)
            if self._dtd_state(events, False):
                self._site("DNL-XXE-001", b, line, "", insecure=False, parse=True)
            else:
                self._site("DNL-XXE-001", b, line, "XmlTextReader parses DTDs (DtdProcessing is not Prohibit or "
                           "Ignore), so external entities and entity expansion are processed", parse=True)
        elif ty == "xpathdocument" and args:
            if self._is_reader(args[0], b):
                self._site("DNL-XXE-001", b, line, "", insecure=False, parse=True)
            else:
                old = self._old_framework(b.t.file)
                self._site("DNL-XXE-001", b, line, "XPathDocument parses with the default resolver, which follows "
                           "external entities before .NET Framework 4.5.2", insecure=old, parse=True)

    # -- XML parser state ---------------------------------------------------------------------

    def _old_framework(self, file: str) -> bool:
        p = self.model.project_of(file)
        v = _version(p.target_framework if p else None)
        return v is not None and v < _MODERN

    def _is_reader(self, expr, b: _Body) -> bool:
        """The argument is a reader: a `new XmlTextReader`, an `XmlReader.Create(..)` or a holder of one."""
        if not isinstance(expr, dict):
            return False
        if expr.get("k") == "new":
            return simple(expr.get("type_full") or expr.get("type")) in _READER_T
        if expr.get("k") == "call":
            return (call_name(expr) or "").lower() == "create" and self._recv_type(expr, b) == "xmlreader"
        r = self.resolve(expr, b)
        return bool(r) and r[1] in _READER_T

    # -- state of a document / settings object that did not stay in the method ----------------

    def _events_insecure(self, events: list[_Event]) -> bool:
        """XmlReaderSettings: DTDs parsed and no (last) null XmlResolver."""
        if not self._dtd_state(events, True):
            return False
        res = [e for e in sorted(events, key=lambda e: (e.file, e.line)) if e.member == "xmlresolver"]
        return not (res and is_null(res[-1].value))

    @staticmethod
    def _combine(states: list) -> bool | None:
        if any(s is True for s in states):
            return True
        return False if states and all(s is False for s in states) else None

    def _state_from_events(self, events: list[_Event], kind: str, at: int | None = None,
                           path: tuple | None = None, body=None) -> bool | None:
        """True insecure / False safe / None nothing was set (before line `at`, ignoring conditional safe
        assignments the statement at `path` is not inside, when given)."""
        if at is not None:
            # an insecure setting later in a loop the statement sits in reaches it on the next pass
            loops = (set(path or ()) & body.loops) if body is not None else set()
            events = [e for e in events if e.line <= at or (
                loops and e.b is body and loops & set(e.path) and not self._safe_event(e, kind))]
        events = self._unconditional(events, kind, path, body)
        if kind == "doc":
            res = [e for e in sorted(events, key=lambda e: (e.file, e.line)) if e.member == "xmlresolver"]
            return None if not res else not is_null(res[-1].value)
        return self._events_insecure(events) if events else None

    def _targets(self, call: dict, b: _Body) -> list[tuple[TypeIR, MethodIR]]:
        env: dict[str, str] = {nm: ty for nm, (ty, _k) in b.locals.items() if ty}
        for d in self._owner_types(b.t):
            for f in d.fields:
                ty = self.field_types.get(("f", d.full_name.lower(), f.name.lower()), "")
                if ty:
                    env.setdefault(f.name.lower(), ty)
        return taint_solver.resolve_call(self.model, b.t, call, env)

    @staticmethod
    def _arg_for(call: dict, idx: int, pname: str):
        """The argument a call passes for parameter `idx` / `pname`: positional first, then named."""
        args = call.get("args") or []
        if idx < len(args):
            return args[idx]
        for k, v in (call.get("named") or {}).items():
            if k.lower() == pname.lower():
                return v
        return None

    def _body_of(self, m: MethodIR) -> _Body | None:
        if len(self._by_method) != len({id(x.method) for x in self.bodies if x.method is not None}):
            self._by_method = {}
            for x in self.bodies:
                if x.method is not None:
                    self._by_method.setdefault(id(x.method), x)  # first body wins, as a linear scan would
        return self._by_method.get(id(m))

    def _callers_of(self, m: MethodIR) -> list[tuple[_Body, dict]]:
        """Calls (anywhere in the solution) that pass a tracked document / settings object and reach `m`."""
        if self._callers is None:
            self._callers = {}
            for cb in self.bodies:
                for n in cb.nodes:
                    if n.get("k") != "call":
                        continue
                    cands = [a for a in list(n.get("args") or []) + list((n.get("named") or {}).values())
                             if isinstance(a, dict) and (
                        (a.get("k") == "new" and simple(a.get("type_full") or a.get("type")) in _TRACKED)
                        or ((self.resolve(a, cb) or ((), ""))[1] in _TRACKED))]
                    if cands:
                        for _t, mm in self._targets(n, cb):
                            self._callers.setdefault(id(mm), []).append((cb, n))
        return self._callers.get(id(m), [])

    def _holder_state(self, expr, b: _Body, kind: str, depth: int = 0, events_too: bool = True,
                      at: int | None = None, path: tuple | None = None) -> bool | None:
        """Whether the document (`doc`: resolver set to non-null) / settings (`settings`: DTDs parsed)
        an expression denotes is insecure: from its own events, else from the factory that returned it,
        else from the callers that passed it in. None when nothing resolvable says."""
        if depth > 2 or not isinstance(expr, dict):
            return None
        if expr.get("k") == "call":
            return self._factory_state(expr, b, kind, depth)
        if expr.get("k") == "new":
            return self._state_from_events(self._events_of_new(expr, b), kind) if events_too else None
        r = self.resolve(expr, b)
        if not r:
            return None
        key = r[0]
        if events_too:
            local = key[0] == "l"
            st = self._state_from_events(self.events.get(key, []), kind, at if local else None, path, b)
            if st is not None:
                return st
        if key in self.local_init:
            return self._factory_state(self.local_init[key], b, kind, depth)
        if key[0] == "l" and b.method is not None:
            names = [p.name.lower() for p in b.method.params]
            if key[3] in names:
                idx = names.index(key[3])
                states = []
                for cb, c in self._callers_of(b.method):
                    arg = self._arg_for(c, idx, b.method.params[idx].name)
                    if arg is not None:
                        states.append(self._holder_state(arg, cb, kind, depth + 1, at=c.get("line", 0),
                                                         path=cb.paths.get(id(c))))
                return self._combine(states)
        return None

    def _factory_state(self, call: dict, b: _Body, kind: str, depth: int) -> bool | None:
        states = []
        for _t, m in self._targets(call, b):
            fb = self._body_of(m)
            if fb is None:
                continue
            rets = [(n.get("value"), n.get("line", 0), fb.paths.get(id(n))) for n in fb.nodes
                    if n.get("k") == "return"]
            states.append(self._combine([self._holder_state(v, fb, kind, depth + 1, at=ln, path=pt)
                                         for v, ln, pt in rets]))
        return self._combine(states)

    def _doc_insecure(self, call: dict, b: _Body) -> str | None:
        """Why the XmlDocument being loaded resolves external entities, or None when it does not."""
        recv = (call.get("fn") or {}).get("obj")
        line = call.get("line", 0)
        key, events, local = None, [], False
        if isinstance(recv, dict) and recv.get("k") == "new":
            events = self._events_of_new(recv, b)
            local = True
        else:
            r = self.resolve(recv, b)
            if r:
                key, local = r[0], r[0][0] == "l"
                events = self.events.get(key, [])
                self.used.add(key)
        res = [e for e in sorted(events, key=lambda e: (e.file, e.line)) if e.member == "xmlresolver"]
        if local:
            res = [e for e in self._unconditional(res, "doc", b.paths.get(id(call)), b) if e.line <= line]
            if res:
                return None if is_null(res[-1].value) else "XmlResolver is set to a resolver"
        elif res:
            # a null assignment that only comes after this Load in the same method protects nothing
            eff = [e for e in res if not (is_null(e.value) and e.file == b.t.file and e.line > line
                                          and self._body_at(e.file, e.line) is b)]
            if eff:
                return "XmlResolver is set to a resolver" if any(not is_null(e.value) for e in eff) else None
        if key is not None or (isinstance(recv, dict) and recv.get("k") == "call"):
            ext = self._holder_state(recv, b, "doc", events_too=False, at=line, path=b.paths.get(id(call)))
            if ext is True:
                return "XmlResolver is set to a resolver where the document is created or passed in"
            if ext is False:
                return None
        if self._old_framework(b.t.file):
            return "XmlResolver is never set to null and the project targets .NET Framework before 4.5.2"
        return None

    def _escapes(self) -> None:
        """A non-null XmlResolver / DTD-parsing reader settings assigned to a local that leaves the
        method (argument, return value, stored elsewhere) and is never loaded / used here is reported at
        the assignment, because the code that finally uses it may be anywhere. The state counted is the
        one in force at each escaping statement: a safe assignment (null resolver, Prohibit) clears an
        earlier insecure one only when it is not inside a conditional / loop / try the escape is outside of."""
        for b in self.bodies:
            for nm, (ty, key) in b.locals.items():
                if key in self.used or ty not in _DOC_T | {"xmlreadersettings"}:
                    continue
                evs = self.events.get(key, [])
                for esc, path in self._escape_points(b, key):
                    before = self._unconditional([e for e in evs if e.line <= esc],
                                                 "doc" if ty in _DOC_T else "settings", path, b)
                    if ty in _DOC_T:
                        if self._state_from_events(before, "doc") is not True:
                            continue
                        bad = [e for e in before if e.member == "xmlresolver" and not is_null(e.value)]
                        what = "an XmlDocument with a non-null XmlResolver"
                    else:
                        if not self._events_insecure(before):
                            continue
                        bad = [e for e in before if e.member in ("dtdprocessing", "prohibitdtd")]
                        what = "XmlReaderSettings that parse DTDs"
                    self._site("DNL-XXE-001", b, bad[-1].line, f"{what} is created here and handed to other code "
                               "(argument, return value or stored in a field); whatever loads it resolves "
                               "external entities", parse=True)

    def _escape_points(self, b: _Body, key: tuple) -> list[tuple[int, tuple]]:
        """(line, conditional path) of the statements that hand the holder to other code, in order."""
        def is_it(e) -> bool:
            r = self.resolve(e, b)
            return bool(r) and r[0] == key
        out = []
        for n in b.nodes:
            k = n.get("k")
            if (k in ("call", "new") and any(is_it(a) for a in list(n.get("args") or [])
                                             + list((n.get("named") or {}).values()))) \
                    or (k == "return" and is_it(n.get("value"))) \
                    or (k == "assign" and is_it(n.get("value")) and not is_it(n.get("target"))):
                out.append((n.get("line", 0), b.paths.get(id(n), ())))
        return sorted(out, key=lambda x: x[0])

    def _xml_call(self, n: dict, name: str, rtype: str, args: list, b: _Body) -> None:
        line = n.get("line", 0)
        if rtype in _DOC_T and name in ("load", "loadxml"):
            if args and self._is_reader(args[0], b):
                self._site("DNL-XXE-001", b, line, "", insecure=False, parse=True)
                return
            why = self._doc_insecure(n, b)
            self._site("DNL-XXE-001", b, line, f"XmlDocument.{call_name(n)} resolves external entities: {why}",
                       insecure=why is not None, parse=True)
        elif rtype == "xmlreader" and name == "create":
            for a in args[1:]:
                r = self.resolve(a, b)
                if r:
                    self.used.add(r[0])
            bad = any(self._holder_state(a, b, "settings", at=line, path=b.paths.get(id(n))) is True
                      for a in args[1:])
            self._site("DNL-XXE-001", b, line, "XmlReader.Create is given settings that parse DTDs (DtdProcessing = "
                       "Parse or not Prohibit) without a null XmlResolver", insecure=bad, parse=True)
        elif (rtype, name) in _PARSE_ONLY:
            self._site("DNL-XXE-001", b, line, "", insecure=False, parse=True)

    # -- Json.NET settings, attributes ---------------------------------------------------------

    def _json_settings(self, used: set) -> None:
        """An unsafe settings object nothing was seen using is reported where it is set; so is an
        unsafe inline `new JsonSerializer { .. }` that no call consumed."""
        for key, evs in self.events.items():
            bad = self._unsafe_json(evs)
            if not bad or key in used:
                continue
            ty = self.field_types.get(key, "")
            if key[0] == "l":
                ty = next((v[0] for bb in self.bodies for v in bb.locals.values() if v[1] == key), "")
            if ty not in _JSON_T:
                continue
            for e in bad:
                b = self._body_at(e.file, e.line)
                if b is not None:
                    self._site("DNL-DESER-002", b, e.line, f"TypeNameHandling is set to {tail(e.value) or 'a non-None value'} "
                               "on a Json.NET settings object; no call using it was found, so every deserialization "
                               "that receives it can instantiate payload-chosen types")
        for b, line, value, obj, resolved in self.stray:
            if self._is_none(value, b) or not self._json_looking(obj, resolved, value, b):
                continue
            self._site("DNL-DESER-002", b, line, f"TypeNameHandling is set to {tail(value) or 'a non-None value'} "
                       "on a serializer settings object this scan could not trace (for example the Web API "
                       "JsonFormatter.SerializerSettings), so every payload it handles can pick the types to instantiate")
        for b in self.bodies:
            for n in b.nodes:
                if n.get("k") == "new" and id(n) not in self.new_key and id(n) not in self.consumed \
                        and simple(n.get("type_full") or n.get("type")) in _JSON_T:
                    bad = self._unsafe_json(self._events_of_new(n, b))
                    if bad:
                        self._site("DNL-DESER-002", b, n.get("line", 0), "A Json.NET serializer / settings object is "
                                   f"created with TypeNameHandling = {tail(bad[0].value) or 'a non-None value'}")

    def _body_at(self, file: str, line: int) -> _Body | None:
        best = None
        for b in self.bodies:
            if b.t.file != file:
                continue
            lo = b.method.line if b.method else (min((x.get("line", 0) for x in b.nodes if x.get("line")), default=0))
            hi = (b.method.end_line if b.method else max((x.get("line", 0) for x in b.nodes), default=0)) or lo
            if lo <= line <= hi and (best is None or (hi - lo) < best[0]):
                best = (hi - lo, b)
        return best[1] if best else None

    def _attributes(self) -> None:
        for t in self.model.types():
            groups = [(t.attributes, "type")] + [(p.attributes, p.name) for p in t.properties]
            for attrs, where in groups:
                for a in attrs:
                    if simple(a.name) not in _JSON_ATTRS:
                        continue
                    for key, v in (a.named or {}).items():
                        if key.lower() in _TNH_KEYS and not _is_none_tnh(v):
                            b = _Body(t, where, None, [], ("a", where, a.line))
                            self._site("DNL-DESER-002", b, a.line, f"[{a.name}({key} = {tail(v) or 'a non-None value'})] lets "
                                       "the payload choose the type to instantiate")


def _rtype_label(t: str) -> str:
    return {"binaryformatter": "BinaryFormatter", "soapformatter": "SoapFormatter",
            "netdatacontractserializer": "NetDataContractSerializer", "losformatter": "LosFormatter",
            "objectstateformatter": "ObjectStateFormatter"}.get(t, t)


# -- entry points -------------------------------------------------------------------------------

def _scan(model: ProjectModel, refs) -> _Scan:
    key = ("deser_xml_scan", tuple(id(r) for r in refs or []))
    s = model.cache.get(key)
    if s is None:
        s = _Scan(model, refs)
        s.run()
        model.cache[key] = s
    return s


def insecure_xxe_lines(model: ProjectModel, refs=()) -> set[tuple[str, int]]:
    """(file, line) of every XML parse judged insecure; rules_taint keeps an `xxe` hit only there."""
    if not model.files:
        return set()
    return {(s.file, s.line) for s in _scan(model, refs).sites if s.rule == "DNL-XXE-001"}


_TITLE = {
    "DNL-DESER-001": "Insecure deserialization",
    "DNL-DESER-002": "Json.NET TypeNameHandling enabled",
    "DNL-DESER-003": "JavaScriptSerializer with SimpleTypeResolver",
    "DNL-XXE-001": "XML external entity (XXE)",
    "DNL-XXE-002": "XML parser defaults (.NET Framework before 4.5.2)",
}
_SEVERITY = {"DNL-DESER-001": "medium", "DNL-DESER-002": "high", "DNL-DESER-003": "high", "DNL-XXE-001": "medium"}


def check(model: ProjectModel, refs=()) -> list[Finding]:
    """DESER-001..003 / XXE-001 / XXE-002 configuration-shape findings. `refs` (RouteRefs) decide which
    findings carry a route, and the taint rows decide which lines are left to rules_taint."""
    if not model.files:
        return []
    from checks.dnl import rules_taint
    scan = _scan(model, refs)
    proven_lines = {(r.hit.file, r.hit.line, rules_taint.RULE_FOR_KIND[r.hit.kind])
                    for r in rules_taint.rows_for(model, refs) if r.hit.kind in ("deser", "xxe")}
    found: dict[tuple, Finding] = {}
    for s in scan.sites:
        if (s.file, s.line, s.rule) in proven_lines:
            continue
        key = (s.rule, s.file, s.line)
        if key in found:
            continue
        route = scan.routes.route(s.file, s.line)
        api = bool(route.meta.get("api_surface")) if route else False
        conf = "REVIEW" if s.rule == "DNL-DESER-001" else None
        found[key] = dnl_finding(s.rule, _SEVERITY[s.rule], _TITLE[s.rule], f"{s.text} (in {s.t.name}.{s.where}).",
                                 s.file, s.line, route=route, api_surface=api, confidence=conf)
    # XXE-002: one per project that targets < v4.5.2 and parses XML anywhere.
    first: dict[str, _Site] = {}
    for p in sorted(scan.parses, key=lambda p: (p.file, p.line)):
        proj = model.project_of(p.file)
        if proj is not None and proj.path is not None and proj.name not in first:
            first[proj.name] = p
    for name, p in first.items():
        proj = next(x for x in model.projects if x.name == name)
        v = _version(proj.target_framework)
        if v is not None and v < _MODERN:
            found[("DNL-XXE-002", p.file, p.line)] = dnl_finding(
                "DNL-XXE-002", "low", _TITLE["DNL-XXE-002"],
                f"Project {name} targets .NET Framework {proj.target_framework} and parses XML "
                f"(first at {p.file}:{p.line}); before v4.5.2 XmlDocument, XmlTextReader and XPathDocument "
                "default to resolving DTDs and external entities.", p.file, p.line)
    missing = sorted({proj.name for p in scan.parses
                      if (proj := model.project_of(p.file)) is not None and proj.path is not None
                      and _version(proj.target_framework) is None})
    if missing:
        note = (f"{len(missing)} project(s) that parse XML declare no TargetFrameworkVersion ({', '.join(missing)}); "
                "XML parser defaults were assumed to be those of .NET Framework 4.5.2 or later")
        if note not in model.notes:
            model.notes.append(note)
    return list(found.values())
