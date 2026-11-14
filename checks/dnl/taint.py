"""Intra-procedural taint engine for the legacy .NET analyzer.

Walks one method body in statement order over the roslyn-ir statements and
expressions, tracking which local values carry attacker-controlled data
(request collections, WebForms inputs, tainted parameters or fields) and
recording a SinkHit whenever such a value reaches a sink that it has not been
cleansed for. Tables live in taint_tables.py; this module is the evaluator.

A Taint is a set of Origins (where the data came from) plus `cleansed`, the sink
kinds the value is already safe for ("*" = all). Merging two values unions the
origins and intersects `cleansed`, so a value is only as clean as its dirtiest
contributor. Untainted values are None throughout.

Evaluation is deliberately simple and conservative: both branches of an `if` run
from a copy of the environment and are merged, loops run their body twice, and
unknown external calls return None (no propagation) unless a table says
otherwise. Calls to project methods are resolved through taint_solver.resolve_call
and applied from per-method Summaries (sinks reached by a parameter, what flows to
the return value and into the object's fields); without `summaries` they pass
argument taint through to the result and record no inner sinks.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from checks.dnl import taint_tables as T
from checks.dnl.ir import MethodIR, TypeIR, literal_str, receiver_text


# -- values ---------------------------------------------------------------

@dataclass(frozen=True)
class Origin:
    # "source" (request input) | "param" | "field" | "external" (an outbound response body; read only by
    # DNL-CONSUME-002 -- every request-source rule keys on "source" and ignores it)
    kind: str
    detail: str     # source name, param index (as a string) or field name
    file: str
    line: int


@dataclass(frozen=True)
class Taint:
    origins: frozenset
    cleansed: frozenset


def merge(a: Taint | None, b: Taint | None) -> Taint | None:
    """Union of origins, intersection of cleansed; None means untainted."""
    if a is None:
        return b
    if b is None or a is b:
        return a
    return Taint(a.origins | b.origins, a.cleansed & b.cleansed)


def cleanse(t: Taint | None, kinds: Iterable[str]) -> Taint | None:
    if t is None:
        return None
    return Taint(t.origins, t.cleansed | frozenset(kinds))


@dataclass
class SinkHit:
    kind: str
    sink: str       # matched table entry name
    file: str
    line: int
    taint: Taint
    method: str     # "Type.Method" of the method containing the sink
    # Call chain ("Type.Method" of each caller, outermost first) when the hit was
    # reached through a project call rather than found in the analyzed method itself.
    via: tuple = ()
    # Summary keys (type full name, method name, line) of the same chain, for cycle checks.
    via_keys: tuple = field(default=(), repr=False)


@dataclass
class MethodResult:
    hits: list
    ret: Taint | None
    param_to_ret: frozenset
    truncated: bool = False     # evaluation hit the recursion limit; hits may be incomplete
    # Values written to this object's fields (key -> taint, may carry param origins).
    field_out: dict = field(default_factory=dict)
    # (type full name, method name, line) of every project method the body calls.
    calls: list = field(default_factory=list)
    # End-of-body environment (variable / member text -> taint): `ViewBag.X = v` lands here.
    env: dict = field(default_factory=dict)
    # Merged taint of the model argument of every View()/PartialView() call (None when untainted).
    view_model: Taint | None = None


# -- small helpers --------------------------------------------------------

_COMPARE_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=", "&&", "||", "=", "<>", "andalso", "orelse", "and", "or", "xor", "is",
    "isnot", "like", "is not", "as",
})
_SOURCE_RES = [(s, re.compile(s.sym), re.compile(s.text) if s.text else None) for s in T.SOURCES]
_REQUEST_RE = re.compile(T.REQUEST_TEXT)
_FIELD_SRC_RE = re.compile(T.FIELD_SOURCE_TYPES)
_EXT_SYM_RE = re.compile(T.EXTERNAL_SYM)
_INCOMING_RE = re.compile(T.INCOMING_REQUEST_TEXT)
_EXT_SYM_ONLY_RE = re.compile(T.EXTERNAL_SYM_ONLY_RE)
_SAN_RES = [(s, re.compile(s.member)) for s in T.SANITIZERS]
_GUARD = {g.shape: g for g in T.GUARDS}
_REQUEST_PROP_RE = re.compile(r"(?i)^((this|me)\.)?((httpcontext\.current|context|page)\.)?request$")
_HELPER_RES = [(h, re.compile(h.member)) for h in T.STRING_HELPERS]
_TERMINATORS = ("return", "throw")
# Request access inside the free text of an `unknown` / `other` IR node (`Request["a"]`, `Request.QueryString!q`).
_REQUEST_ANY_RE = re.compile(r"(?i)(?<!\w)(httpcontext\.current\.)?request\s*[.\[(!]")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_ASSIGN_TEXT_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*([+&\-]?)=(?!=)\s*(.+?);?\s*$", re.S)
# String / char literals, longest forms first: interpolated (`$"a{x}"`), verbatim (`@"a""b"`), regular, char.
_LITERAL_RE = re.compile(r"""\$@?"(?:[^"\\]|\\.)*"|@"(?:[^"]|"")*"|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)'""")
_INTERP_HOLE_RE = re.compile(r"(?<!\{)\{([^{}]+)\}")
# Assignment operators (plain and compound), not `==` `!=` `<=` `>=` `=>`.
_ASSIGN_OP_RE = re.compile(r"(?<![=!<>])((?:[+\-*/&|^%]|\?\?)?)=(?![=>])")
_DECL_WORDS = {"var", "dim", "as", "new", "const", "static", "readonly", "let", "ref", "out", "string", "int",
               "long", "short", "byte", "char", "bool", "boolean", "object", "double", "decimal", "float",
               "integer", "single", "date", "datetime", "public", "private", "protected", "internal", "shared"}
_TUPLE_DECL_RE = re.compile(r"^\s*(?:var|dim)?\s*\((.*)\)\s*$", re.S | re.I)
# Calls whose lambda argument takes elements of the (tainted) receiver as its first parameter.
_LAMBDA_BINDERS = re.compile(r"(?i)^(select|selectmany|where|foreach|any|all|first\w*|single\w*|last\w*|find\w*|"
                             r"exists|truefor\w*|orderby\w*|thenby\w*|groupby|takewhile|skipwhile|convertall)$")
_MISSING = object()
# Calls that run their lambda argument to completion before returning: its writes to closure variables
# are visible afterwards. Task.Run, event handlers and stored delegates are not in this set.
_SYNC_CALLBACKS = re.compile(r"(?i)^(foreach|select|selectmany|where|any|all|first\w*|single\w*|last\w*|"
                             r"orderby\w*|thenby\w*|aggregate|sum|count|min|max|groupby|takewhile|skipwhile|"
                             r"tolist|toarray|todictionary|tolookup|exists|findall|convertall|truefor\w*)$")
# Static receivers of the LINQ / parallel forms: `Enumerable.Where(source, x => ..)`.
_STATIC_SEQ_TYPES = {"enumerable", "queryable", "parallel", "parallelenumerable"}


def _strip_literals(text: str) -> str:
    """Drop string / char literal contents so request-looking words inside them are not scanned;
    the `{expr}` holes of an interpolated string stay (they are code)."""
    def sub(m: re.Match) -> str:
        lit = m.group(0)
        if lit.startswith("$"):
            return " " + " ".join(h.group(1) for h in _INTERP_HOLE_RE.finditer(lit)) + " "
        return '""'
    return _LITERAL_RE.sub(sub, text)


def _simple(type_name: str | None) -> str:
    """`System.Collections.Generic.List<T>` / `Foo[]` / `int?` -> `list` / `foo` / `int` (lowered)."""
    if not type_name:
        return ""
    s = type_name.split("<")[0].split("(")[0].replace("[]", "").rstrip("?").strip()
    return s.split(".")[-1].lower()


def _alias_names(name: str) -> set[str]:
    low = name.lower()
    out = {low}
    if low in T.TYPE_ALIASES:
        out.add(T.TYPE_ALIASES[low].lower())
    return out


def _is_string_type(type_name: str | None) -> bool:
    """Exactly `string` / `System.String` (an array or generic of string is a collection)."""
    return (type_name or "").strip().lower() in ("string", "system.string")


def _num(e: Any) -> float | None:
    """Value of a numeric literal (or negated one), else None."""
    if isinstance(e, dict) and e.get("k") == "unary" and e.get("op") == "-":
        v = _num(e.get("e"))
        return -v if v is not None else None
    if isinstance(e, dict) and e.get("k") == "lit":
        v = e.get("v")
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    return None


def _has_replace_call(node: Any) -> bool:
    """Does an IR subtree contain a call to a method named Replace."""
    if isinstance(node, dict):
        if node.get("k") == "call":
            fn = node.get("fn") or {}
            if ((fn.get("name") if fn.get("k") == "member" else fn.get("id")) or "").lower() == "replace":
                return True
        return any(_has_replace_call(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_replace_call(v) for v in node)
    return False


def _split_sym(sym: str) -> tuple[str, str]:
    """`System.Data.SqlClient.SqlCommand.CommandText` -> (type, member)."""
    head, _, member = sym.rpartition(".")
    return head, member


# -- the evaluator --------------------------------------------------------

class _Analysis:
    def __init__(self, model, t: TypeIR, m: MethodIR, param_taint, field_taint, summaries):
        self.model, self.t, self.m = model, t, m
        fir = model.files.get(t.file)
        self.vb = (fir.language if fir else ("vb" if t.file.lower().endswith(".vb") else "cs")) == "vb"
        self.summaries = summaries
        self.method_name = f"{t.name}.{m.name}"
        self.env: dict[str, Taint | None] = {}
        self.types: dict[str, str] = {}          # variable key -> declared / inferred type
        self.fullpaths: set[str] = set()         # variables assigned from Path.GetFullPath
        self.with_stack: list[dict] = []
        self.hits: dict[tuple, SinkHit] = {}
        self.rets: list[Taint | None] = []
        self.truncated = False
        self.str_vars: set[str] = set()          # locals initialised from a string expression
        self.locals: set[str] = set()            # params and declared locals (never field writes)
        self.field_writes: dict[str, Taint | None] = {}
        self.calls: list[tuple] = []
        self.view_model: Taint | None = None
        self._owner_cache: list[TypeIR] | None = None
        self._init_cache: dict[int, Taint | None] = {}
        self.field_taint = {self.key(k): v for k, v in (field_taint or {}).items()}
        self.fields = self._field_types()
        for i, p in enumerate(m.params):
            k = self.key(p.name)
            self.locals.add(k)
            self.env[k] = (param_taint or {}).get(i)
            if p.type:
                self.types[k] = p.type

    # -- naming ----------------------------------------------------------

    def key(self, text: str) -> str:
        """Environment key: VB is case-insensitive; `this.x` / `Me.x` is just `x`."""
        k = text.lower() if self.vb else text
        low = k.lower()
        for pre in ("this.", "me."):
            if low.startswith(pre):
                return k[len(pre):]
        return k

    def _field_types(self) -> dict[str, str]:
        """Declared field/property types of the class (all partial declarations) and its
        project base types, by environment key. Cached per model."""
        cache = self.model.cache.setdefault("taint_fields", {})
        ck = (self.t.full_name.lower(), self.vb)
        if ck in cache:
            return cache[ck]
        out: dict[str, str] = {}
        seen: set[str] = set()
        todo = [self.t]
        while todo:
            cur = todo.pop(0)
            if cur.full_name.lower() in seen:
                continue
            seen.add(cur.full_name.lower())
            for d in self.model.find_types(cur.name.split(".")[-1]):
                if d.full_name.lower() != cur.full_name.lower():
                    continue
                for f in d.fields:
                    if f.type:
                        out.setdefault(self.key(f.name), f.type)
                for p in d.properties:
                    if p.type:
                        out.setdefault(self.key(p.name), p.type)
            for b in cur.bases:
                todo.extend(self.model.find_types(b))
        cache[ck] = out
        return out

    # -- types -----------------------------------------------------------

    def type_of(self, e: Any) -> str | None:
        """Declared / inferred type of an expression, when cheaply known."""
        if not isinstance(e, dict):
            return None
        k = e.get("k")
        if k == "name":
            kk = self.key(e.get("id") or "")
            return self.types.get(kk) or self.fields.get(kk)
        if k == "member":
            obj = self._recv(e)
            if isinstance(obj, dict) and obj.get("k") == "name" and (obj.get("id") or "").lower() in ("this", "me"):
                return self.fields.get(self.key(e.get("name") or ""))
            ot = self.type_of(obj)
            if ot:
                for d in self.model.find_types(_simple(ot)):
                    for f in list(d.fields) + list(d.properties):
                        if f.name.lower() == (e.get("name") or "").lower():
                            return f.type
            return None
        if k == "new":
            return e.get("type_full") or e.get("type")
        if k == "cast":
            return e.get("type")
        return None

    def _recv(self, member: dict) -> Any:
        """Object of a member node; inside a With block a null obj is the With target."""
        obj = member.get("obj")
        if obj is None and self.with_stack:
            return self.with_stack[-1]
        return obj

    def _recv_names(self, recv: Any) -> tuple[set[str], bool]:
        """Lowered simple type names a receiver may have (declared type, or the text itself
        for a static `Type.Member` access) and whether it looks like a static type access."""
        names: set[str] = set()
        t = self.type_of(recv)
        if t:
            names |= _alias_names(_simple(t))
        text = receiver_text(recv)
        static = False
        if text:
            head = self.key(text.split(".")[0])
            if head.lower() not in ("this", "me", "base") and head not in self.env and head not in self.types \
                    and head not in self.fields:
                names |= _alias_names(text.split(".")[-1])
                static = True
        return names, static

    def _text(self, e: Any) -> str:
        """Dotted text of a name/member chain, resolving a With-target null object."""
        if not isinstance(e, dict):
            return ""
        if e.get("k") == "member" and e.get("obj") is None and self.with_stack:
            return f"{self._text(self.with_stack[-1])}.{e.get('name') or ''}"
        return receiver_text(e)

    # -- sources ---------------------------------------------------------

    def _origin(self, name: str, line: int) -> Taint:
        return Taint(frozenset({Origin("source", name, self.t.file, line)}), frozenset())

    def _source(self, e: dict, text: str | None = None) -> Taint | None:
        """Taint of a member / name / index / call node that is itself a source.
        sym is authoritative when present; the text patterns only run without it."""
        sym = e.get("sym")
        line = e.get("line", 0)
        if sym:
            for s, sym_re, _ in _SOURCE_RES:
                if sym_re.match(sym):
                    return self._origin(s.name, line)
            return None
        text = text if text is not None else self._text(e)
        for s, _, text_re in _SOURCE_RES:
            if text_re and text and text_re.match(text):
                return self._origin(s.name, line)
        if e.get("k") == "member" and (e.get("name") or "").lower() in T.FIELD_SOURCE_MEMBERS:
            tn = self.type_of(self._recv(e))
            if tn and _FIELD_SRC_RE.match(_simple(tn)):
                return self._origin(f"{_simple(tn)}.{e.get('name')}", line)
        return None

    # -- sink matching ---------------------------------------------------

    def _record(self, sink: T.Sink, value: Taint | None, line: int) -> None:
        if value is None or sink.kind in value.cleansed or "*" in value.cleansed:
            return
        k = (sink.kind, sink.name, self.t.file, line)
        old = self.hits.get(k)
        self.hits[k] = SinkHit(sink.kind, sink.name, self.t.file, line,
                               merge(old.taint, value) if old else value, self.method_name)

    def _sink_matches(self, sink: T.Sink, member: str, sym: str | None, recv: Any, bare: bool) -> bool:
        if sink.member.lower() != member.lower():
            return False
        if sym:
            stype, smem = _split_sym(sym)
            return smem.lower() == member.lower() and stype in sink.types
        if sink.unresolved_ok and not bare:
            return True
        if recv is not None:
            names, _ = self._recv_names(recv)
            if names & {_simple(x) for x in sink.types}:
                return True
            if sink.recv_text and re.search(sink.recv_text, self._text(recv) or ""):
                return True
        if sink.derives and (recv is None or (self._text(recv) or "").lower() in ("this", "me", "base")):
            return self.model.derives_from(self.t, set(sink.derives))
        return False

    def _arg_ok(self, sink: T.Sink, arg: Any) -> bool:
        """Path sinks take a string in arg slots that overloads reuse for streams / bytes."""
        if sink.kind != "path":
            return True
        tn = self.type_of(arg)
        return not tn or _simple(tn) in ("string", "object")

    def _check_call_sinks(self, call: dict, name: str, recv: Any, args: list, vals: list, nvals: list) -> None:
        bare = recv is None
        names = self._recv_names(recv)[0] if recv is not None else set()
        for sink in T.SINKS:
            if sink.assign or sink.member == ".ctor":
                continue
            if not self._sink_matches(sink, name, call.get("sym"), recv, bare):
                continue
            # `Type.Member(recv, ..)`: only a receiver that names the sink's own type shifts the index
            static = sink.static_args is not None and bool(names & {_simple(x) for x in sink.types})
            idx = range(len(vals)) if sink.all_args else (sink.static_args if static else sink.args)
            for i in idx:
                if i < len(vals) and self._arg_ok(sink, args[i]):
                    self._record(sink, vals[i], call.get("line", 0))
            # Named arguments: positions are unknown without the overload, so check them all.
            for v in nvals:
                self._record(sink, v, call.get("line", 0))

    def _check_new_sinks(self, e: dict, args: list, vals: list, nvals: list) -> bool:
        tf = e.get("type_full")
        tname = tf or e.get("type") or ""
        hit_type = False
        for sink in T.SINKS:
            if sink.member != ".ctor":
                continue
            if tf:
                ok = tf in sink.types
            else:
                ok = _simple(tname) in {_simple(x) for x in sink.types}
            if not ok:
                continue
            hit_type = True
            for i in sink.args:
                if i < len(vals) and self._arg_ok(sink, args[i]):
                    self._record(sink, vals[i], e.get("line", 0))
            for v in nvals:
                self._record(sink, v, e.get("line", 0))
        return hit_type

    def _check_assign_sinks(self, member_name: str, sym: str | None, recv: Any, type_full: str | None,
                            value: Taint | None, line: int) -> None:
        for sink in T.SINKS:
            if not sink.assign or sink.member.lower() != member_name.lower():
                continue
            if sym:
                stype, _ = _split_sym(sym)
                ok = stype in sink.types
            elif type_full:
                ok = type_full in sink.types or _simple(type_full) in {_simple(x) for x in sink.types}
            else:
                ok = self._sink_matches(sink, member_name, None, recv, False)
            if ok:
                self._record(sink, value, line)

    # -- expressions -----------------------------------------------------

    def ev(self, e: Any) -> Taint | None:
        if not isinstance(e, dict):
            return None
        k = e.get("k")
        fn = getattr(self, f"_ev_{k}", None)
        return fn(e) if fn else None

    def _ev_name(self, e: dict) -> Taint | None:
        kk = self.key(e.get("id") or "")
        if kk in self.env:
            return self.env[kk]
        if kk in self.field_taint:
            return self.field_taint[kk]
        return self._getter_taint(self._owners(), e.get("id") or "")

    def _ev_member(self, e: dict) -> Taint | None:
        name = e.get("name") or ""
        recv = self._recv(e)
        text = self._text(e)
        if text:
            kk = self.key(text)
            if kk in self.env:
                return self.env[kk]
            if kk in self.field_taint and kk.find(".") < 0:
                return self.field_taint[kk]
        src = self._source(e, text)
        if src is not None:
            return src
        base = self.ev(recv)
        if self.summaries is not None:
            rtext = (self._text(recv) or "").lower() if recv is not None else "this"
            if rtext in ("this", "me", "mybase", "base"):
                base = merge(base, self._getter_taint(self._owners(), name))
            elif recv is not None and self.type_of(recv):
                owners = self.model.find_types(_simple(self.type_of(recv)))
                base = merge(base, self._getter_taint(owners, name))
        if name.lower() in T.CLEANSING_MEMBERS:
            return cleanse(base, ["*"])
        # A property read on a tainted object stays tainted.
        return base

    def _ev_index(self, e: dict) -> Taint | None:
        obj = e.get("obj")
        for a in e.get("args") or []:
            self.ev(a)
        if not e.get("sym") and _REQUEST_RE.match(self._text(obj) or ""):
            return self._origin("Request", e.get("line", 0))
        src = self._source(e)
        if src is not None:
            return src
        return self.ev(obj)

    def _ev_lit(self, e: dict) -> Taint | None:
        return None

    def _scan_text(self, text: str, line: int) -> Taint | None:
        """Conservative taint of syntax the IR could not lower (`unknown` / `other`): a request access
        in the text is a source; otherwise the merged taint of every known variable it mentions.
        Never a sink."""
        text = _strip_literals(text or "")
        if not text:
            return None
        if _REQUEST_ANY_RE.search(text) or re.match(T.REQUEST_TEXT, text.strip()):
            return self._origin("Request", line)
        out = None
        for tok in _IDENT_RE.findall(text):
            for cand in (tok, tok.split(".")[0]):
                kk = self.key(cand)
                if kk in self.env:
                    out = merge(out, self.env[kk])
                    break
                if kk in self.field_taint:
                    out = merge(out, self.field_taint[kk])
                    break
        return out

    def _ev_unknown(self, e: dict) -> Taint | None:
        return self._scan_text(e.get("text") or "", e.get("line", 0))

    def _ev_lambda(self, e: dict, bind: Taint | None = None, sync: bool = False) -> Taint | None:
        """Evaluate a lambda body on a copy of the environment: closure variables are visible, sinks
        inside are recorded, assignments are discarded unless `sync` (a synchronous callback: the writes are merged back into
        the outer environment, never overwriting with None). `bind` is the taint of the first parameter
        (the element of a tainted receiver for LINQ-style calls); other parameters are untainted."""
        saved = (self.env, self.types, self.locals, len(self.rets))
        self.env, self.types, self.locals = dict(self.env), dict(self.types), set(self.locals)
        pkeys: set[str] = set()
        inner = None
        try:
            for i, p in enumerate(e.get("params") or []):
                kk = self.key(p)
                pkeys.add(kk)
                self.env[kk] = bind if i == 0 else None
                self.locals.add(kk)
                self.types.pop(kk, None)
            body = e.get("body")
            if isinstance(body, list):
                self.block(body)
            else:
                self.ev(body)
        finally:
            inner = (self.env, self.locals)
            self.env, self.types, self.locals = saved[:3]
            del self.rets[saved[3]:]
        if sync and inner is not None:
            lenv, llocals = inner
            declared = (llocals - saved[2]) | pkeys
            for kk, v in lenv.items():
                if kk in declared or v is saved[0].get(kk, _MISSING):
                    continue
                if v is not None:
                    self.env[kk] = merge(self.env.get(kk), v)
        return None

    def _ev_bin(self, e: dict) -> Taint | None:
        a, b = self.ev(e.get("l")), self.ev(e.get("r"))
        if str(e.get("op") or "").lower() in _COMPARE_OPS:
            return None
        return merge(a, b)

    def _ev_unary(self, e: dict) -> Taint | None:
        self.ev(e.get("e"))
        return None

    def _ev_interp(self, e: dict) -> Taint | None:
        out = None
        for p in e.get("parts") or []:
            out = merge(out, self.ev(p))
        return out

    def _ev_cond(self, e: dict) -> Taint | None:
        self.ev(e.get("c"))
        return merge(self.ev(e.get("t")), self.ev(e.get("f")))

    def _ev_cast(self, e: dict) -> Taint | None:
        v = self.ev(e.get("e"))
        if _simple(e.get("type")) in T.SAFE_CAST_TYPES:
            return cleanse(v, ["*"])
        return v

    def _ev_new(self, e: dict) -> Taint | None:
        args = list(e.get("args") or [])
        vals = [self.ev(a) for a in args]
        nvals = [self.ev(a) for a in (e.get("named") or {}).values()]
        init_vals = []
        tf = e.get("type_full")
        for ent in e.get("init") or []:
            v = self.ev(ent.get("value"))
            self._init_cache[id(ent)] = v
            init_vals.append(v)
            if ent.get("name"):
                self._check_assign_sinks(ent["name"], None, None, tf or e.get("type"), v, e.get("line", 0))
        if self._check_new_sinks(e, args, vals, nvals):
            return None
        if self.summaries is not None:
            self._call_ctors(e, args, vals, nvals)
            self._init_setters(e)
        out = None
        for v in vals + nvals + init_vals:
            out = merge(out, v)
        return out

    def _is_mvc_view(self, call: dict, recv: Any) -> bool:
        """`View(..)` is Controller.View: own-object call, and either the symbol says so or (no symbol) the
        type derives Controller and no project method of that name shadows it."""
        if recv is not None and self._text(recv).lower() not in ("this", "me"):
            return False
        sym = call.get("sym")
        if sym:
            return sym.lower().startswith("system.web.mvc.controller.")
        if not self.model.derives_from(self.t, {"Controller"}):
            return False
        chain = [self.t] + [bt for b in self.model.base_chain(self.t) for bt in self.model.find_types(b)]
        return not any(m.name.lower() in ("view", "partialview") for ty in chain for m in ty.methods)

    def _ev_call(self, e: dict) -> Taint | None:
        fn = e.get("fn") or {}
        args = list(e.get("args") or [])
        named = list((e.get("named") or {}).values())
        line = e.get("line", 0)
        fk = fn.get("k")
        if fk == "member":
            name, recv = fn.get("name") or "", self._recv(fn)
        elif fk == "name":
            name, recv = fn.get("id") or "", None
        else:
            # `handlers[0](x)`, `(a ?? b)(x)`: the callee is unknown, so the result carries what it was given.
            out = self.ev(fn)
            for a in args + named:
                out = merge(out, self.ev(a))
            return out
        low = name.lower()
        rv = self.ev(recv) if recv is not None else None
        binder = bool(_LAMBDA_BINDERS.match(low))
        bind = rv if binder else None
        sync = bool(_SYNC_CALLBACKS.match(low) or binder)
        # `Enumerable.Where(source, x => ..)` / `Where(source, ..)`: the first argument is the sequence.
        static_seq = binder and args and not (isinstance(args[0], dict) and args[0].get("k") == "lambda") and (
            (recv is not None and (self._text(recv) or "").lower().split(".")[-1] in _STATIC_SEQ_TYPES)
            or (recv is None and fk == "name"))
        vals = []
        for i, a in enumerate(args):
            vals.append(self._ev_arg(a, bind, sync))
            if i == 0 and static_seq:
                bind = vals[0]
        nvals = [self._ev_arg(a, bind, sync) for a in named]
        self._check_call_sinks(e, name, recv, args, vals, nvals)
        if low in ("view", "partialview") and args and self._is_mvc_view(e, recv):
            # `View("Name", model)` / `View(model)`: a leading string literal is the view name.
            mi = 1 if literal_str(args[0]) is not None else 0
            if mi < len(vals):
                self.view_model = merge(self.view_model, vals[mi])

        # request collections called like methods: VB `Request.QueryString("q")`, `Request("q")`
        src = self._source(e) or self._source(fn) or self._request_default(fn)
        if src is not None:
            return src
        # sanitizers
        san = self._sanitize(e, fn, name, recv, args, vals, rv)
        if san is not False:
            return san
        ext = self._external_call(e, low, recv, vals + nvals, rv)
        if ext is not False:
            return ext
        # collection accessors on a tainted receiver
        if low in T.ACCESSOR_METHODS and rv is not None:
            return rv
        targets = self._targets(e, fn, recv)
        # collection mutators fold their arguments into the receiver variable
        if low in T.MUTATORS and recv is not None and not targets:
            out = None
            for v in vals + nvals:
                out = merge(out, v)
            self._fold_key(recv, out)
            return None
        # string helpers
        if self._is_helper(low, recv, fk == "name" and self._is_local_name(name)):
            out = rv
            for v in vals + nvals:
                out = merge(out, v)
            if low in T.APPEND_LIKE and recv is not None:
                self._fold_into_root(recv, out)
            return out
        # VB `localVar("key")` indexes a collection held in a local
        if self.vb and fk == "name":
            kk = self.key(name)
            if kk in self.env:
                return self.env[kk]
        # project methods: summaries decide what reaches the result, sinks and fields
        if targets:
            out = self._project_call(e, targets, vals, nvals, recv, rv)
            return merge(out, None if low in T.NON_PROPAGATING else rv)
        # any other external instance call on a tainted receiver keeps the taint, except
        # members that return a bool / number / type rather than text derived from the receiver
        if rv is not None and recv is not None and low not in T.NON_PROPAGATING:
            return rv
        return None

    def _ev_arg(self, a: Any, bind: Taint | None, sync: bool = False) -> Taint | None:
        if isinstance(a, dict) and a.get("k") == "lambda":
            return self._ev_lambda(a, bind, sync)
        return self.ev(a)

    def _external_call(self, e: dict, low: str, recv: Any, vals: list, rv: Taint | None):
        """Outbound-response taint (origin kind "external"): a call that reads a response body is a
        source, and a deserializer / parser turns an external value into a value that keeps only
        the external origin. False when the call is neither, so the normal rules go on. A receiver
        that already carries request taint keeps it (the result adds the external origin to it)."""
        sym = e.get("sym")
        line = e.get("line", 0)
        is_src = False
        if _INCOMING_RE.match(self._text(recv) or ""):
            if low in T.INCOMING_BODY_READS:
                # `Request.Content.ReadAsStringAsync()`: the client's body is request input.
                src = self._origin(f"Request.Content.{e.get('fn', {}).get('name') or low}", line)
                return Taint(src.origins | rv.origins, src.cleansed & rv.cleansed) if rv is not None else src
            is_src = False
        elif low in T.EXTERNAL_NAMES:
            is_src = not sym or bool(_EXT_SYM_RE.match(sym))
        elif low in T.EXTERNAL_SYM_ONLY:
            is_src = bool(sym and _EXT_SYM_ONLY_RE.match(sym))
        if is_src:
            origin = Origin("external", f"response of {e.get('fn', {}).get('name') or low}", self.t.file, line)
            if rv is not None:
                return Taint(rv.origins | {origin}, rv.cleansed)
            return Taint(frozenset({origin}), frozenset())
        parse = low == "parse" and recv is not None and _simple(self.type_of(recv) or "").lower() in T.PARSER_TYPES
        parse = parse or (low == "parse" and recv is not None
                          and (self._text(recv) or "").split(".")[-1].lower() in T.PARSER_TYPES)
        if low in T.DESERIALIZERS or parse:
            merged = None
            for v in vals:
                merged = merge(merged, v)
            ext = frozenset(o for o in (merged.origins if merged else ()) if o.kind == "external")
            if ext:
                if rv is not None:
                    return Taint(rv.origins | ext, rv.cleansed)
                return Taint(ext, merged.cleansed)
            return False
        return False

    def _request_default(self, fn: dict) -> Taint | None:
        """`Request("q")`: the call's own and the member's syms name HttpRequest.Item / Page.Request,
        so recognise the receiver-less `Request` property by name."""
        if fn.get("k") not in ("name", "member"):
            return None
        sym = fn.get("sym")
        if _REQUEST_PROP_RE.match(self._text(fn) or "") and (not sym or sym.endswith(".Request")):
            return self._origin("Request", fn.get("line", 0))
        return None

    def _is_local_name(self, name: str) -> bool:
        """A local / parameter / field of this name (a VB indexer `Left(i)` is not the Left function)."""
        kk = self.key(name)
        return kk in self.env or kk in self.fields or kk in self.field_taint

    def _is_helper(self, low: str, recv: Any, local: bool = False) -> bool:
        for h, mre in _HELPER_RES:
            if not mre.match(low):
                continue
            if not h.types:
                if recv is not None or (h.bare and not local):
                    return True
                continue
            if recv is not None:
                names, _ = self._recv_names(recv)
                if names & {x.lower() for x in h.types}:
                    return True
        return False

    def _fold_key(self, recv: Any, value: Taint | None) -> None:
        """`list.Add(x)`: fold x into the receiver's own key (`cmd.Parameters.Add(x)` taints
        `cmd.parameters`, not `cmd`, so parameterized commands stay clean)."""
        text = self._text(recv)
        if not text:
            self._fold_into_root(recv, value)
            return
        kk = self.key(text)
        self.env[kk] = merge(self.env.get(kk, self.field_taint.get(kk)), value)
        self._note_write(text, value)

    def _fold_into_root(self, recv: Any, value: Taint | None) -> None:
        """`sb.Append(x)` (possibly chained): fold the result into the variable holding the builder."""
        cur = recv
        while isinstance(cur, dict) and cur.get("k") in ("call", "member"):
            cur = (cur.get("fn") or {}).get("obj") if cur["k"] == "call" else self._recv(cur)
        # a chain `a.b.Append(x)` roots at a dotted name; a call chain roots at its innermost receiver
        text = self._text(cur if isinstance(cur, dict) else recv)
        if text:
            kk = self.key(text)
            self.env[kk] = merge(self.env.get(kk, self.field_taint.get(kk)), value)
            self._note_write(text, value)

    def _sanitize(self, e, fn, name, recv, args, vals, rv):
        """Result of a sanitizing call, or False when the call is not a sanitizer."""
        sym = e.get("sym")
        bare = recv is None
        names = self._recv_names(recv)[0] if recv is not None else set()
        for s, mre in _SAN_RES:
            if not mre.match(name):
                continue
            if sym:
                stype, _ = _split_sym(sym)
                if s.types and stype not in s.types:
                    continue
            elif s.types:
                if bare:
                    if not s.bare_ok:
                        continue
                elif not (names & {_simple(x) for x in s.types}):
                    continue
            if s.name == "ldap-escape":
                # A project method merely named like an escaper must actually rewrite something.
                tg = self._targets(e, fn, recv)
                if tg and all(tm.body and not _has_replace_call(tm.body) for _ty, tm in tg):
                    continue
            out = rv if not s.types or s.crlf else None
            for v in vals:
                out = merge(out, v)
            if s.crlf:
                # VB `Replace(s, find, repl)` shifts the arguments by one.
                off = 1 if bare else 0
                mark = self._crlf_marker(args[off] if len(args) > off else None,
                                         args[off + 1] if len(args) > off + 1 else None)
                if mark is None:
                    continue
                return self._with_marker(out, mark)
            if name.lower().startswith("try") and "parse" in name.lower():
                self._bind_out_args(args, out)
            return cleanse(out, s.kinds)
        return False

    def _crlf_marker(self, find: Any, repl: Any) -> str | None:
        """Which single line-break character a Replace(find, repl) removes ("~cr" or "~lf"), else
        None. Removing the two-character pair (vbCrLf, Environment.NewLine, "CRLF") leaves a lone
        CR or LF behind, so it contributes nothing; a replacement that is not a constant free of
        CR / LF puts one back."""
        rl = literal_str(repl)
        rtext = (self._text(repl) or "").lower()
        if not ((rl is not None and "\r" not in rl and "\n" not in rl) or rtext in ("string.empty", "vbnullstring")):
            return None
        fl = literal_str(find)
        if fl is not None:
            return {"\r": "~cr", "\n": "~lf"}.get(fl)
        return {"vbcr": "~cr", "vblf": "~lf"}.get((self._text(find) or "").lower())

    @staticmethod
    def _with_marker(value: Taint | None, mark: str) -> Taint | None:
        """Record a removed line-break character in `cleansed`; header and log are safe only
        once both CR and LF have been removed."""
        if value is None:
            return None
        c = set(value.cleansed) | {mark}
        if {"~cr", "~lf"} <= c:
            c |= {"header", "log"}
        return Taint(value.origins, frozenset(c))

    def _bind_out_args(self, args: list, src: Taint | None) -> None:
        """TryParse(text, out x): x is a number whatever text held."""
        for a in args[1:]:
            if not isinstance(a, dict):
                continue
            nm = None
            if a.get("k") == "name":
                nm = a.get("id")
            elif a.get("k") in ("unknown", "other") and a.get("text"):
                nm = a["text"].split()[-1]
            if nm:
                self.env[self.key(nm)] = cleanse(src, ["*"])
                self.locals.add(self.key(nm))

    # -- project method calls ---------------------------------------------

    def _env_types(self) -> dict[str, str]:
        return {**self.fields, **self.types}

    def _targets(self, e: dict, fn: dict, recv: Any) -> list[tuple[TypeIR, MethodIR]]:
        from checks.dnl.taint_solver import resolve_call
        with_t = self.with_stack[-1] if self.with_stack else None
        return resolve_call(self.model, self.t, e, self._env_types(), type_of=self.type_of, with_target=with_t)

    def _owners(self) -> list[TypeIR]:
        """This type's declarations (partials) and its project base types."""
        if self._owner_cache is None:
            out = [d for d in self.model.find_types(self.t.name.split(".")[-1])
                   if d.full_name.lower() == self.t.full_name.lower()] or [self.t]
            for b in self.model.base_chain(self.t):
                out.extend(self.model.find_types(_simple(b)))
            self._owner_cache = out
        return self._owner_cache

    def _getter_taint(self, owners: list[TypeIR], name: str) -> Taint | None:
        """Taint a property getter returns on its own (request sources it reads)."""
        if self.summaries is None or not name:
            return None
        low = name.lower()
        for o in owners:
            for p in o.properties:
                if p.get is not None and p.name.lower() == low:
                    key = (o.full_name, f"get_{p.name}", p.line)
                    self.calls.append(key)
                    s = self.summaries.get(key)
                    if s is not None and s.ret_source is not None:
                        return s.ret_source
        return None

    def _note_write(self, text: str, value: Taint | None) -> None:
        """Record a write to a field of this object (`x = v`, `this.x = v`, `x.Add(v)`)."""
        if not text:
            return
        kk = self.key(text)
        if "." in kk or kk not in self.fields:
            return
        if kk in self.locals and not text.lower().startswith(("this.", "me.")):
            return
        self.field_writes[kk] = merge(self.field_writes.get(kk), value)

    @staticmethod
    def _pmods(p) -> set[str]:
        return {x.lower() for x in p.modifiers}

    def _ext_forms(self, e: dict, ty: TypeIR, m: MethodIR) -> list[bool]:
        """Bindings to evaluate for a call: `True` = instance form (receiver bound to the
        extension's `this` parameter, arguments shift by one), `False` = plain / static form.
        Instance when the receiver is an expression (call / index / new: `receiver_text` is
        "" for those), `this` / `base` / `Me` / `MyBase`, or a known local, parameter, field or
        property (fields cover the caller type and its project bases). A dotted receiver whose
        head is a model type / namespace and whose last segment is the class name is static.
        A dotted receiver with an unresolvable head and that last segment is ambiguous (an
        inherited member from outside the model, or a using-alias): both bindings, so no
        taint is ever lost."""
        fn = e.get("fn") or {}
        if not (m.params and "this" in self._pmods(m.params[0]) and fn.get("k") == "member"):
            return [False]
        text = receiver_text(fn.get("obj")) or ""
        parts = text.split(".") if text else []
        head = self.key(parts[0]) if parts else ""
        if (not parts or head.lower() in ("this", "base", "me", "mybase")
                or head in self.env or head in self.types or head in self.fields or head in self.locals):
            return [True]
        if parts[-1].lower() != ty.name.split(".")[-1].lower():
            return [True]
        hl = head.lower()
        known = bool(self.model.find_types(hl)) or any(
            t.namespace.lower() == hl or t.namespace.lower().startswith(hl + ".")
            for t in self.model.types())
        return [False] if known else [False, True]

    def _args_by_param(self, e: dict, ty: TypeIR, m: MethodIR, vals: list, nvals: list,
                       rv: Taint | None = None, inst: bool = False) -> dict[int, Taint | None]:
        """Argument taint by parameter index. An extension method called in instance form
        (`inst`) binds the receiver to its `this` parameter and shifts the arguments by one;
        every argument at or past a `params` / ParamArray position lands on that parameter;
        named arguments map by parameter name."""
        shift = 0
        out: dict[int, Taint | None] = {}
        if inst:
            shift, out[0] = 1, rv
        var = next((i for i, p in enumerate(m.params) if self._pmods(p) & {"params", "paramarray"}), None)
        for j, v in enumerate(vals):
            i = j + shift
            if var is not None and i >= var:
                i = var
            out[i] = merge(out.get(i), v)
        names = [str(n).lower() for n in (e.get("named") or {})]
        for n, v in zip(names, nvals):
            for i, p in enumerate(m.params):
                if p.name.lower() == n:
                    out[i] = merge(out.get(i), v)
        return out

    def _fire(self, h: SinkHit, arg: Taint) -> None:
        """A callee sink reached through a parameter fires here when the argument is tainted."""
        extra = frozenset(o for o in h.taint.origins if o.kind != "param")
        t = Taint(arg.origins | extra, arg.cleansed | h.taint.cleansed)
        me = (self.t.full_name, self.m.name, self.m.line)
        # A method already on the chain is a cycle: its own hit already exists.
        if h.kind in t.cleansed or "*" in t.cleansed or me in h.via_keys:
            return
        k = (h.kind, h.sink, h.file, h.line)
        via, vkeys = (self.method_name,) + h.via, (me,) + h.via_keys
        old = self.hits.get(k)
        if old is None:
            self.hits[k] = SinkHit(h.kind, h.sink, h.file, h.line, t, h.method, via, vkeys)
        else:
            keep_old = len(old.via) <= len(via)
            self.hits[k] = SinkHit(h.kind, h.sink, h.file, h.line, merge(old.taint, t), old.method,
                                   old.via if keep_old else via, old.via_keys if keep_old else vkeys)

    def _apply_summaries(self, e: dict, targets: list, vals: list, nvals: list,
                         rv: Taint | None = None) -> tuple[Taint | None, dict]:
        """Fire callee sinks; return the call's result taint and the taint the receiver
        picks up (callee `this` fields written from tainted arguments, by field key;
        "" = unknown field)."""
        out: Taint | None = None
        this_in: dict[str, Taint | None] = {}
        for ty, tm in targets:
            key = (ty.full_name, tm.name, tm.line)
            self.calls.append(key)
            s = self.summaries.get(key)
            if s is None:
                continue
            for inst in self._ext_forms(e, ty, tm):
                args = self._args_by_param(e, ty, tm, vals, nvals, rv, inst)
                if any(v is not None and i >= len(tm.params) for i, v in args.items()):
                    # the mapping would drop a tainted argument: never lose it, pass it to the result
                    for v in list(args.values()):
                        out = merge(out, v)
                for i, hs in s.param_sinks.items():
                    a = args.get(i)
                    if a is not None:
                        for h in hs:
                            self._fire(h, a)
                if s.ret_source is not None:
                    out = merge(out, s.ret_source)
                for i in s.param_to_ret:
                    a = args.get(i)
                    if a is not None:
                        out = merge(out, cleanse(a, s.ret_cleansed))
                for i in s.param_to_this:
                    a = args.get(i)
                    if a is None:
                        continue
                    for fk in (s.this_fields or frozenset({""})):
                        this_in[fk] = merge(this_in.get(fk), a)
        if targets and not any(tm.body for _ty, tm in targets):
            # Interface / abstract members with no implementation in the model: unknown code, so
            # the result carries whatever it was given.
            for v in vals + nvals:
                out = merge(out, v)
        return out, this_in

    def _project_call(self, e: dict, targets: list, vals: list, nvals: list, recv: Any,
                      rv: Taint | None = None) -> Taint | None:
        if self.summaries is None:
            out = None
            for v in vals + nvals:
                out = merge(out, v)
            return out
        out, this_in = self._apply_summaries(e, targets, vals, nvals, rv)
        self._apply_this_in(this_in, recv)
        return out

    def _apply_this_in(self, this_in: dict, recv: Any) -> None:
        """Taint a callee stored into its object's fields reaches the receiver variable, or
        the caller's own fields for a this / implicit receiver."""
        rtext = (self._text(recv) or "").lower() if recv is not None else ""
        implicit = recv is None or rtext in ("this", "me", "base", "mybase", "myclass")
        for fk, v in this_in.items():
            if implicit:
                if fk:
                    self.env[fk] = merge(self.env.get(fk, self.field_taint.get(fk)), v)
                    self.field_writes[fk] = merge(self.field_writes.get(fk), v)
            else:
                self._fold_key(recv, v)

    def _recv_owners(self, recv: Any) -> list[TypeIR]:
        """Project declarations (and bases) a receiver's members live in."""
        rtext = (self._text(recv) or "").lower() if recv is not None else ""
        if recv is None or rtext in ("this", "me", "mybase", "base", "myclass"):
            return self._owners()
        tn = self.type_of(recv)
        if not tn:
            return []
        from checks.dnl.taint_solver import _chain, _types_for
        types = _types_for(self.model, tn, self.t.namespace)
        return [d for t in types for d in _chain(self.model, t)]

    def _call_setter(self, recv: Any, name: str, value: Taint | None) -> None:
        """`obj.Prop = v` / `new T { Prop = v }`: run the property setter's summary."""
        if self.summaries is None or not name:
            return
        from checks.dnl.taint_solver import _accessors
        low = name.lower()
        for o in self._recv_owners(recv):
            for p in o.properties:
                if p.set is None or p.name.lower() != low:
                    continue
                for m in _accessors(self.model, o):
                    if m.name == f"set_{p.name}" and m.line == p.line:
                        _, this_in = self._apply_summaries({}, [(o, m)], [value], [])
                        self._apply_this_in(this_in, recv)
                        return

    def _init_setters(self, e: dict) -> None:
        """Object-initializer members of a project type run that property's setter."""
        tn = e.get("type_full") or e.get("type") or ""
        from checks.dnl.taint_solver import _types_for
        types = _types_for(self.model, tn, self.t.namespace)
        if not types:
            return
        from checks.dnl.taint_solver import _chain, _accessors
        owners = [d for t in types for d in _chain(self.model, t)]
        for ent in e.get("init") or []:
            nm = (ent.get("name") or "").lower()
            for o in owners:
                for p in o.properties:
                    if p.set is not None and nm and p.name.lower() == nm:
                        for m in _accessors(self.model, o):
                            if m.name == f"set_{p.name}" and m.line == p.line:
                                self._apply_summaries({}, [(o, m)], [self._init_val(ent)], [])

    def _init_val(self, ent: dict) -> Taint | None:
        return self._init_cache.get(id(ent))

    def _call_ctors(self, e: dict, args: list, vals: list, nvals: list) -> None:
        """`new Project.Type(x)`: constructor sinks reached by a tainted argument fire."""
        tf, tn = e.get("type_full") or "", e.get("type") or ""
        cands = [d for d in self.model.find_types(_simple(tn or tf))
                 if not tf or d.full_name.lower() == tf.lower() or "." not in tf]
        ctors = [(d, m) for d in cands for m in d.methods if m.name == ".ctor"]
        exact = [c for c in ctors if len(c[1].params) == len(args) + len(nvals)]
        picked = exact or ctors
        if picked:
            self._apply_summaries(e, picked, vals, nvals)

    # -- guards ----------------------------------------------------------

    def _vkey(self, e: Any) -> str | None:
        text = self._text(e)
        return self.key(text) if text else None

    def _guard_call(self, c: dict) -> tuple[str, frozenset] | None:
        """(variable key, cleansed kinds) when a call expression is a recognised guard."""
        fn = c.get("fn") or {}
        name = ((fn.get("name") if fn.get("k") == "member" else fn.get("id")) or "").lower()
        args = c.get("args") or []
        recv = self._recv(fn) if fn.get("k") == "member" else None
        g = _GUARD
        if name in ("islocalurl", "isurllocaltohost") and args:
            k = self._vkey(args[0])
            return (k, g["islocalurl"].cleanses) if k else None
        if name == "contains" and args and recv is not None:
            # `text.Contains(x)` searches inside x's container, it does not whitelist x: skip
            # literal / string-typed / tainted receivers.
            if recv.get("k") in ("lit", "interp") or _is_string_type(self.type_of(recv)) \
                    or (self._vkey(recv) in self.str_vars) or self.ev(recv) is not None:
                return None
            k = self._vkey(args[0])
            return (k, g["contains"].cleanses) if k else None
        if name == "startswith" and recv is not None:
            rk = self._vkey(recv)
            if rk and rk in self.fullpaths:
                return (rk, g["startswith-fullpath"].cleanses)
        return None

    def _guards(self, cond: Any, when_true: bool) -> list[tuple[str, frozenset]]:
        """Guards that hold when `cond` evaluates to when_true."""
        if not isinstance(cond, dict):
            return []
        k = cond.get("k")
        if k == "unary" and cond.get("op") in ("!", "Not"):
            return self._guards(cond.get("e"), not when_true)
        if k == "call":
            g = self._guard_call(cond)
            return [g] if g and when_true else []
        if k == "bin":
            op = str(cond.get("op") or "").lower()
            if op in ("&&", "andalso", "and") and when_true:
                return self._guards(cond.get("l"), True) + self._guards(cond.get("r"), True)
            if op in ("||", "orelse", "or") and not when_true:
                return self._guards(cond.get("l"), False) + self._guards(cond.get("r"), False)
            # Array.IndexOf(arr, x) >= 0   /   > -1   /   != -1   (and the negated forms)
            l = cond.get("l")
            if isinstance(l, dict) and l.get("k") == "call":
                lfn = l.get("fn") or {}
                largs = l.get("args") or []
                if (lfn.get("name") or "").lower() == "indexof" and len(largs) >= 2 \
                        and (self._text(lfn.get("obj")) or "").lower().split(".")[-1] == "array":
                    lit = _num(cond.get("r"))
                    found = (op == ">=" and lit == 0) or (op in (">", "!=", "<>") and lit == -1)
                    absent = (op == "<" and lit == 0) or (op in ("==", "=") and lit == -1)
                    if (found and when_true) or (absent and not when_true):
                        kk = self._vkey(largs[1])
                        return [(kk, _GUARD["indexof"].cleanses)] if kk else []
        return []

    def _apply_guards(self, guards: list[tuple[str, frozenset]]) -> None:
        for kk, kinds in guards:
            cur = self.env.get(kk, self.field_taint.get(kk))
            if cur is not None:
                self.env[kk] = cleanse(cur, kinds)

    # -- statements ------------------------------------------------------

    def block(self, stmts: Any) -> bool:
        """Run statements in order; True when the block always ends in return/throw."""
        for s in stmts or []:
            if self.stmt(s):
                return True
        return False

    def stmt(self, s: Any) -> bool:
        if not isinstance(s, dict):
            return False
        fn = getattr(self, f"_st_{s.get('k')}", None)
        return bool(fn(s)) if fn else False

    def _st_local(self, s: dict) -> bool:
        kk = self.key(s.get("name") or "")
        init = s.get("init")
        self.env[kk] = self.ev(init)
        self.locals.add(kk)
        tn = s.get("type_full") or s.get("type")
        if not tn or tn.lower() in ("var", "dim"):
            tn = self.type_of(init)
        if tn:
            self.types[kk] = tn
        else:
            self.types.pop(kk, None)
        self._note_fullpath(kk, init)
        if self._stringy(init):
            self.str_vars.add(kk)
        else:
            self.str_vars.discard(kk)
        return False

    def _stringy(self, e: Any) -> bool:
        """A string literal, interpolation, or concatenation involving one."""
        if not isinstance(e, dict):
            return False
        k = e.get("k")
        if k == "lit":
            return isinstance(e.get("v"), str)
        if k == "interp":
            return True
        if k == "bin" and str(e.get("op") or "").lower() in ("+", "&", "concat"):
            return self._stringy(e.get("l")) or self._stringy(e.get("r"))
        return False

    def _note_fullpath(self, kk: str, value: Any) -> None:
        if isinstance(value, dict) and value.get("k") == "call" and \
                ((value.get("fn") or {}).get("name") or "").lower() == "getfullpath":
            self.fullpaths.add(kk)

    def _st_other(self, s: dict) -> bool:
        """A statement the IR could not lower: every `=` assignment in its text (plain, compound,
        tuple `(a, b) = ..`, chained `a = b = ..`) taints each identifier on its left side with the
        conservatively scanned right-hand side. Never a sink."""
        text = _strip_literals(s.get("text") or "").strip().rstrip(";")
        ops, depth = [], 0
        for i, c in enumerate(text):
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "=" and depth == 0:
                m = _ASSIGN_OP_RE.match(text, i - 1) if i and text[i - 1] in "+-*/&|^%?" else None
                m = m or _ASSIGN_OP_RE.match(text, i)
                if m and m.end() == i + 1:
                    ops.append((m.start(), m.end(), bool(m.group(1))))
        if not ops:
            return False
        segs, prev = [], 0
        for st, en, comp in ops:
            segs.append(text[prev:st])
            prev = en
        rhs = text[prev:]
        value = self._scan_text(rhs, s.get("line", 0))
        for seg, (_, _, comp) in zip(segs, ops):
            for tok in _IDENT_RE.findall(seg):
                if tok.lower() in _DECL_WORDS:
                    continue
                kk = self.key(tok)
                v = merge(self.env.get(kk, self.field_taint.get(kk)), value) if comp else value
                self.env[kk] = v
                self._note_write(tok, v)
        return False

    def _st_expr(self, s: dict) -> bool:
        self.ev(s.get("expr"))
        return False

    def _st_return(self, s: dict) -> bool:
        self.rets.append(self.ev(s.get("value")))
        return True

    def _st_throw(self, s: dict) -> bool:
        self.ev(s.get("value"))
        return True

    def _st_assign(self, s: dict) -> bool:
        target, op = s.get("target") or {}, s.get("op") or "="
        line = s.get("line", 0)
        value = self.ev(s.get("value"))
        k = target.get("k")
        if op in ("+=", "concat="):
            value = merge(self.ev(target), value)
        elif op == "-=":
            value = None
        if k == "name":
            kk = self.key(target.get("id") or "")
            self.env[kk] = value
            self._note_write(target.get("id") or "", value)
            if kk not in self.locals:
                self._call_setter(None, target.get("id") or "", value)
            self._note_fullpath(kk, s.get("value"))
        elif k == "member":
            recv = self._recv(target)
            self.ev(recv) if recv is not None else None
            self._check_assign_sinks(target.get("name") or "", target.get("sym"), recv,
                                     None if target.get("sym") else self._assign_type(recv), value, line)
            self._call_setter(recv, target.get("name") or "", value)
            text = self._text(target)
            if text:
                self.env[self.key(text)] = value
                self._note_write(text, value)
        elif k == "index":
            text = self._text(target.get("obj"))
            if text:
                kk = self.key(text)
                self.env[kk] = merge(self.env.get(kk, self.field_taint.get(kk)), value)
                self._note_write(text, value)
        elif k == "unknown":
            # Tuple deconstruction `(a, b) = ..`: every identifier on the left receives the value.
            for tok in _IDENT_RE.findall(_strip_literals(target.get("text") or "")):
                if tok.lower() in _DECL_WORDS:
                    continue
                kk = self.key(tok)
                v = merge(self.env.get(kk, self.field_taint.get(kk)), value) if op != "=" else value
                self.env[kk] = v
                self._note_write(tok, v)
        return False

    def _assign_type(self, recv: Any) -> str | None:
        return self.type_of(recv)

    def _st_if(self, s: dict) -> bool:
        cond = s.get("cond")
        self.ev(cond)
        saved = self.env
        self.env = dict(saved)
        self._apply_guards(self._guards(cond, True))
        t_term = self.block(s.get("then"))
        env_t, self.env = self.env, dict(saved)
        self._apply_guards(self._guards(cond, False))
        e_term = self.block(s.get("else"))
        env_e = self.env
        if t_term and e_term:
            self.env = self._merge_envs(env_t, env_e)
            return True
        if t_term:
            self.env = env_e
        elif e_term:
            self.env = env_t
        else:
            self.env = self._merge_envs(env_t, env_e)
        return False

    @staticmethod
    def _merge_envs(a: dict, b: dict) -> dict:
        out = {}
        for k in a.keys() | b.keys():
            out[k] = merge(a.get(k), b.get(k))
        return out

    def _st_loop(self, s: dict) -> bool:
        header = s.get("header") or []
        # foreach: [loop variable, collection]; `for` / `while` headers hold expressions only.
        tup = _TUPLE_DECL_RE.match(header[0].get("text") or "") if len(header) == 2 and isinstance(header[0], dict) \
            and header[0].get("k") == "unknown" else None
        if len(header) == 2 and isinstance(header[0], dict) and header[0].get("k") == "name" \
                and (header[1] or {}).get("k") != "unary":
            self.env[self.key(header[0].get("id") or "")] = self.ev(header[1])
            self.locals.add(self.key(header[0].get("id") or ""))
        elif tup is not None and isinstance(header[1], dict):
            # `foreach (var (a, b) in xs)`: every deconstructed name carries the collection's taint.
            v = self.ev(header[1])
            for piece in tup.group(1).split(","):
                words = _IDENT_RE.findall(piece)
                if words and words[-1] != "_":
                    self.env[self.key(words[-1])] = v
                    self.locals.add(self.key(words[-1]))
        else:
            for h in header:
                self.ev(h)
        pre = dict(self.env)
        for _ in range(2):
            self.block(s.get("body"))
        self.env = self._merge_envs(pre, self.env)
        return False

    def _st_try(self, s: dict) -> bool:
        pre = dict(self.env)
        b_term = self.block(s.get("body"))
        after_body = self.env
        outs = [after_body]
        for c in s.get("catches") or []:
            self.env = self._merge_envs(pre, after_body)
            if c.get("name"):
                self.env[self.key(c["name"])] = None
                self.locals.add(self.key(c["name"]))
            self.block(c.get("body"))
            outs.append(self.env)
        merged = outs[0]
        for o in outs[1:]:
            merged = self._merge_envs(merged, o)
        self.env = merged
        f_term = self.block(s.get("finally"))
        return f_term

    def _st_using(self, s: dict) -> bool:
        self.block(s.get("resource"))
        return self.block(s.get("body"))

    def _st_with(self, s: dict) -> bool:
        target = s.get("target")
        self.ev(target)
        self.with_stack.append(target)
        try:
            return self.block(s.get("body"))
        finally:
            self.with_stack.pop()

    # -- driver ----------------------------------------------------------

    def run(self) -> MethodResult:
        try:
            self.block(self.m.body)
        except RecursionError:
            # Absurdly deep IR: keep what was found so far and flag it.
            self.truncated = True
        ret = None
        for r in self.rets:
            ret = merge(ret, r)
        p2r = frozenset(int(o.detail) for o in (ret.origins if ret else ())
                        if o.kind == "param" and "*" not in ret.cleansed and o.detail.isdigit())
        return MethodResult(list(self.hits.values()), ret, p2r, self.truncated, dict(self.field_writes), self.calls,
                            dict(self.env), self.view_model)


def analyze_method(model, t: TypeIR, m: MethodIR, *, param_taint: dict[int, Taint] | None = None,
                   field_taint: dict[str, Taint] | None = None, summaries: dict | None = None) -> MethodResult:
    """Evaluate one method body; see the module docstring for the semantics."""
    return _Analysis(model, t, m, param_taint, field_taint, summaries).run()
