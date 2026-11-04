"""AST-based Java crypto checks (JC-0xx) built on javalang.

The regex rules in checks/crypto.py only see one line at a time, so they
miss the common real-world shapes:

    private static final String TRANSFORM = "AES/ECB/PKCS5Padding";   // constant
    private final byte[] iv = new byte[16];                            // never filled
    Cipher.getInstance(TRANSFORM);                                     // used elsewhere
    encrypt(data, FIXED_IV);  ->  void encrypt(byte[] d, byte[] iv) { new IvParameterSpec(iv) }

This module parses every .java file and resolves the value reaching each
crypto sink through:
  * literals, string concatenation, ternaries, casts, array initialisers
  * local variables (every assignment in the method)
  * fields (declaration + every assignment in the class, incl. constructors)
  * constants in other classes (Constants.KEY) and static imports (KEY)
  * method parameters, by resolving the argument at every call site
  * return values of small helper methods (getIv() { return IV; })
  * byte arrays that are allocated but never filled (all zeros), vs. filled
    by SecureRandom.nextBytes
  * "x".getBytes(), "x".toCharArray(), Base64/Hex decoding of literals

Each finding says where the bad value came from ("via constant
Config.TRANSFORM (Config.java:4)", "via parameter iv of encrypt(), called
from Service.java:31"), so it can be verified quickly.

Files javalang can't parse fall back to the regex rules (crypto.py).
"""
from __future__ import annotations

import codecs
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import javalang
from javalang import tree as T

from core.models import Finding
from core.rulescan import make_finding, rel

MAX_DEPTH = 6
_SECURITY_CONTEXT = re.compile(r"(?i)key|token|secret|salt|nonce|(?:^|_)iv(?:$|_)|password|passwd|otp|session|csrf|crypt")


# ── abstract values ─────────────────────────────────────────────────────────

@dataclass
class Val:
    kind: str                      # str | int | bytes_const | zero_bytes | random_bytes | chars_const | clock | array | unknown
    value: object = None
    via: tuple = ()                # human-readable hops, outermost first

    def hop(self, text: str) -> "Val":
        return Val(self.kind, self.value, (text,) + self.via)

    def origin(self) -> str:
        return (" Value resolved " + " <- ".join(self.via) + ".") if self.via else ""


UNKNOWN = Val("unknown")
CONST_BYTES = ("bytes_const", "zero_bytes")


# ── project index ───────────────────────────────────────────────────────────

@dataclass
class MethodInfo:
    node: object
    name: str
    cls: "ClassInfo"
    params: list
    types: dict = field(default_factory=dict)       # local + param name -> simple type
    assigns: dict = field(default_factory=dict)     # local name -> [expr]
    filled: dict = field(default_factory=dict)      # array name -> "random" | "other"
    returns: list = field(default_factory=list)
    line: int = 0
    kpg_alg: dict = field(default_factory=dict)     # var name -> getInstance() arg expr


@dataclass
class ClassInfo:
    name: str
    file: Path
    node: object
    types: dict = field(default_factory=dict)       # field name -> simple type
    assigns: dict = field(default_factory=dict)     # field name -> [(expr, line, MethodInfo|None)]
    filled: dict = field(default_factory=dict)
    methods: dict = field(default_factory=dict)     # name -> [MethodInfo]
    field_lines: dict = field(default_factory=dict)


@dataclass
class Ctx:
    cls: Optional[ClassInfo]
    method: Optional[MethodInfo]
    file: Path


def _simple_type(t) -> str:
    if t is None:
        return ""
    name = getattr(t, "name", "") or ""
    sub = getattr(t, "sub_type", None)
    while sub is not None:
        name = sub.name
        sub = getattr(sub, "sub_type", None)
    dims = getattr(t, "dimensions", None) or []
    return name + "[]" * len(dims)


def _first_line(node) -> int:
    """javalang leaves position None on ClassCreator/BinaryOperation etc.;
    use the first descendant that has one."""
    pos = getattr(node, "position", None)
    if pos:
        return pos.line
    if isinstance(node, T.Node):
        for _, child in node:
            pos = getattr(child, "position", None)
            if pos:
                return pos.line
    return 0


def _children(node) -> Iterable:
    # Static/instance initializer blocks come through as plain lists.
    items = node if isinstance(node, (list, tuple)) else node.children
    for c in items:
        if isinstance(c, T.Node):
            yield c
        elif isinstance(c, (list, tuple, set)):
            for x in c:
                if isinstance(x, T.Node):
                    yield x
                elif isinstance(x, (list, tuple)):
                    for y in x:
                        if isinstance(y, T.Node):
                            yield y


def _walk_no_classes(node):
    """Yield descendants without entering nested/anonymous class bodies."""
    for child in _children(node):
        yield child
        if isinstance(child, (T.ClassDeclaration, T.InterfaceDeclaration, T.EnumDeclaration)):
            continue
        if isinstance(child, T.ClassCreator) and child.body:
            for a in child.arguments or []:
                yield a
                yield from _walk_no_classes(a)
            continue
        yield from _walk_no_classes(child)


_NOT_A_FILL = {"toString", "encodeToString", "encode", "println", "print", "printf", "debug", "info", "warn",
               "error", "trace", "hashCode", "equals", "length", "copyOf", "doFinal", "update", "init", "write",
               "wrap", "putExtra", "format", "valueOf", "hex", "toHexString", "encodeHex", "encodeHexString"}


def _record_fills(node, filled: dict):
    for n in _walk_no_classes(node):
        if isinstance(n, T.MethodInvocation):
            for i, a in enumerate(n.arguments or []):
                if isinstance(a, T.MemberReference) and not a.selectors and a.qualifier in ("", None, "this"):
                    if n.member == "nextBytes":
                        filled[a.member] = "random"
                    elif n.member == "arraycopy" and i != 2:
                        continue
                    elif n.member not in _NOT_A_FILL:
                        filled.setdefault(a.member, "other")
        elif isinstance(n, T.Assignment):
            t = n.expressionl
            if isinstance(t, T.MemberReference) and any(isinstance(s, T.ArraySelector) for s in (t.selectors or [])):
                filled.setdefault(t.member, "other")


class Project:
    def __init__(self):
        self.classes: list[ClassInfo] = []
        self.by_name: dict[str, list[ClassInfo]] = {}
        self.static_fields: dict[str, list[ClassInfo]] = {}   # simple field name -> classes declaring it
        self.calls: dict[tuple[str, int], list[tuple[object, Ctx]]] = {}
        self.trees: dict[Path, object] = {}

    # -- indexing --
    def add_file(self, path: Path, tree):
        self.trees[path] = tree
        for _, node in tree:
            if isinstance(node, (T.ClassDeclaration, T.EnumDeclaration, T.InterfaceDeclaration)):
                self._add_class(node.name, node.body or [], path, node)
            elif isinstance(node, T.ClassCreator) and node.body:
                self._add_class(f"<anonymous {_simple_type(node.type)}>", node.body, path, node)

    def _add_class(self, name, body, path, node):
        ci = ClassInfo(name, path, node)
        node._ci = ci
        for member in body:
            if isinstance(member, T.FieldDeclaration):
                for d in member.declarators:
                    ci.types[d.name] = _simple_type(member.type)
                    ci.field_lines[d.name] = _first_line(member)
                    if d.initializer is not None:
                        ci.assigns.setdefault(d.name, []).append((d.initializer, _first_line(member), None))
                    self.static_fields.setdefault(d.name, []).append(ci)
            elif isinstance(member, (T.MethodDeclaration, T.ConstructorDeclaration)):
                mi = self._add_method(member, ci)
                ci.methods.setdefault(mi.name, []).append(mi)
        for member in body:
            if not isinstance(member, (T.ClassDeclaration, T.InterfaceDeclaration, T.EnumDeclaration)):
                _record_fills(member, ci.filled)
        self.classes.append(ci)
        self.by_name.setdefault(name, []).append(ci)

    def _add_method(self, node, ci: ClassInfo) -> MethodInfo:
        params = [p.name for p in node.parameters]
        mi = MethodInfo(node, node.name, ci, params, line=_first_line(node))
        node._mi = mi
        for p in node.parameters:
            mi.types[p.name] = _simple_type(p.type) + ("[]" if getattr(p, "varargs", False) else "")
        for n in _walk_no_classes(node):
            if isinstance(n, T.LocalVariableDeclaration):
                for d in n.declarators:
                    mi.types[d.name] = _simple_type(n.type)
                    if d.initializer is not None:
                        mi.assigns.setdefault(d.name, []).append(d.initializer)
                        if _is_static_call(d.initializer, "KeyPairGenerator", "getInstance") and d.initializer.arguments:
                            mi.kpg_alg[d.name] = d.initializer.arguments[0]
            elif isinstance(n, T.Assignment) and n.type == "=":
                target = n.expressionl
                tname, is_this = None, False
                if isinstance(target, T.MemberReference) and not target.selectors:
                    tname = target.member
                    is_this = target.qualifier == "this"
                elif isinstance(target, T.This) and target.selectors and isinstance(target.selectors[-1], T.MemberReference):
                    tname, is_this = target.selectors[-1].member, True
                if tname:
                    if not is_this and tname in mi.types:
                        mi.assigns.setdefault(tname, []).append(n.value)
                    else:
                        ci.assigns.setdefault(tname, []).append((n.value, _first_line(n), mi))
                    if _is_static_call(n.value, "KeyPairGenerator", "getInstance") and n.value.arguments:
                        mi.kpg_alg[tname] = n.value.arguments[0]
            elif isinstance(n, T.ReturnStatement) and n.expression is not None:
                mi.returns.append(n.expression)
        _record_fills(node, mi.filled)
        return mi

    def index_calls(self):
        for ci in self.classes:
            for methods in ci.methods.values():
                for mi in methods:
                    ctx = Ctx(ci, mi, ci.file)
                    for n in _walk_no_classes(mi.node):
                        if isinstance(n, T.MethodInvocation):
                            self.calls.setdefault((n.member, len(n.arguments or [])), []).append((n, ctx))
                        for sel in getattr(n, "selectors", None) or []:
                            if isinstance(sel, T.MethodInvocation):
                                self.calls.setdefault((sel.member, len(sel.arguments or [])), []).append((sel, ctx))


def _is_static_call(node, cls: str, member: str) -> bool:
    return isinstance(node, T.MethodInvocation) and node.member == member and \
        (node.qualifier or "").split(".")[-1] == cls


def _method_ctx_types(ctx: Ctx, name: str) -> str:
    if ctx.method and name in ctx.method.types:
        return ctx.method.types[name]
    if ctx.cls and name in ctx.cls.types:
        return ctx.cls.types[name]
    return ""


# ── value resolution ────────────────────────────────────────────────────────

def _parse_str(lit: str) -> Optional[str]:
    if len(lit) >= 2 and lit[0] == lit[-1] == '"':
        body = lit[1:-1]
        try:
            return codecs.decode(body, "unicode_escape")
        except Exception:
            return body
    return None


def _parse_int(lit: str) -> Optional[int]:
    s = lit.replace("_", "").rstrip("lL")
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        if s.lower().startswith("0b"):
            return int(s, 2)
        return int(s)
    except ValueError:
        return None


class Resolver:
    def __init__(self, project: Project, root: Path):
        self.p = project
        self.root = root

    def _where(self, ci_file: Path, line: int, ctx: Ctx) -> str:
        return f"{ci_file.name}:{line}"

    def resolve(self, expr, ctx: Ctx, depth: int = 0) -> list[Val]:
        if expr is None or depth > MAX_DEPTH:
            return [UNKNOWN]
        vals = self._core(expr, ctx, depth)
        for sel in getattr(expr, "selectors", None) or []:
            vals = [self._apply(v, sel, ctx, depth) for v in vals]
        return vals or [UNKNOWN]

    def _apply(self, v: Val, sel, ctx, depth) -> Val:
        if isinstance(sel, T.MethodInvocation):
            return self._method_on(v, sel.member, sel.arguments or [], ctx, depth)
        return UNKNOWN

    def _method_on(self, v: Val, member: str, args, ctx, depth) -> Val:
        if member == "getBytes" and v.kind == "str":
            return Val("bytes_const", v.value, v.via)
        if member == "toCharArray" and v.kind == "str":
            return Val("chars_const", v.value, v.via)
        if member in ("clone", "trim", "intern") and v.kind != "unknown":
            return v
        if member in ("decode", "decodeHex", "parseHexBinary", "decodeBase64", "hexStringToByteArray",
                      "fromHex", "hexToBytes", "decodeHexString") and args:
            for a in self.resolve(args[0], ctx, depth + 1):
                if a.kind == "str":
                    return Val("bytes_const", a.value, a.via)
        return UNKNOWN

    def _core(self, expr, ctx: Ctx, depth: int) -> list[Val]:
        if isinstance(expr, T.Literal):
            s = _parse_str(expr.value)
            if s is not None:
                return [Val("str", s)]
            if expr.value.startswith("'"):
                return [UNKNOWN]
            n = _parse_int(expr.value)
            return [Val("int", n)] if n is not None else [UNKNOWN]

        if isinstance(expr, T.Cast):
            return self.resolve(expr.expression, ctx, depth + 1)

        if isinstance(expr, T.TernaryExpression):
            return self.resolve(expr.if_true, ctx, depth + 1) + self.resolve(expr.if_false, ctx, depth + 1)

        if isinstance(expr, T.BinaryOperation):
            if expr.operator == "+":
                left = self.resolve(expr.operandl, ctx, depth + 1)
                right = self.resolve(expr.operandr, ctx, depth + 1)
                out = []
                for a in left:
                    for b in right:
                        if a.kind in ("str", "int") and b.kind in ("str", "int") and "str" in (a.kind, b.kind):
                            out.append(Val("str", f"{a.value}{b.value}", a.via + b.via))
                        elif a.kind == b.kind == "int":
                            out.append(Val("int", a.value + b.value))
                return out or [UNKNOWN]
            if expr.operator == "*":
                left = self.resolve(expr.operandl, ctx, depth + 1)
                right = self.resolve(expr.operandr, ctx, depth + 1)
                if left[0].kind == right[0].kind == "int":
                    return [Val("int", left[0].value * right[0].value)]
            return [UNKNOWN]

        if isinstance(expr, (T.ArrayCreator, T.ArrayInitializer)):
            init = expr if isinstance(expr, T.ArrayInitializer) else expr.initializer
            elem = _simple_type(getattr(expr, "type", None)) if isinstance(expr, T.ArrayCreator) else ""
            if init is not None:
                items = [self.resolve(i, ctx, depth + 1)[0] for i in init.initializers or []]
                if elem in ("char",):
                    return [Val("chars_const", None)]
                if items and all(i.kind == "str" for i in items):
                    return [Val("array", [i.value for i in items])]
                if elem in ("byte", "") and all(i.kind in ("int", "unknown") for i in items):
                    if all(i.kind == "int" for i in items):
                        return [Val("bytes_const", bytes(x & 0xFF for x in (i.value for i in items)))]
                return [UNKNOWN]
            if elem == "byte":
                return [Val("zero_bytes", None)]
            return [UNKNOWN]

        if isinstance(expr, T.This):
            sels = expr.selectors or []
            if sels and isinstance(sels[0], T.MemberReference):
                v = self._field(sels[0].member, ctx, depth)
                for sel in sels[1:]:
                    v = [self._apply(x, sel, ctx, depth) for x in v]
                return v
            return [UNKNOWN]

        if isinstance(expr, T.MemberReference):
            q = expr.qualifier or ""
            if q in ("", "this"):
                return self._name(expr.member, ctx, depth, this_only=(q == "this"))
            return self._qualified(q, expr.member, ctx, depth)

        if isinstance(expr, T.MethodInvocation):
            return [self._invocation(expr, ctx, depth)]

        if isinstance(expr, T.ClassCreator):
            return [UNKNOWN]
        return [UNKNOWN]

    def _invocation(self, inv, ctx: Ctx, depth) -> Val:
        q = inv.qualifier or ""
        if q == "System" and inv.member in ("currentTimeMillis", "nanoTime"):
            return Val("clock", None)
        if q in ("String",) and inv.member == "valueOf" and inv.arguments:
            vs = self.resolve(inv.arguments[0], ctx, depth + 1)
            return Val("str", str(vs[0].value), vs[0].via) if vs[0].kind in ("str", "int") else UNKNOWN
        last = q.split(".")[-1]
        if q in ("", "this"):
            target_classes = [ctx.cls] if ctx.cls else []
        elif last in self.p.by_name and last[:1].isupper():
            target_classes = self.p.by_name[last]          # static helper in the project
        else:
            # Method on a value (key.getBytes(), Config.KEY.getBytes()) or on an
            # external class (Base64.getDecoder().decode(..), Hex.decode(..)).
            base = self._qualified_value(q, ctx, depth)
            return self._method_on(base, inv.member, inv.arguments or [], ctx, depth)
        # same-project helper: resolve its return expressions
        for ci in target_classes:
            for mi in ci.methods.get(inv.member, []):
                if len(mi.params) != len(inv.arguments or []):
                    continue
                for r in mi.returns:
                    for v in self.resolve(r, Ctx(ci, mi, ci.file), depth + 1):
                        if v.kind != "unknown":
                            return v.hop(f"from {mi.name}() return ({self._where(ci.file, _first_line(r) or mi.line, ctx)})")
        return UNKNOWN

    def _qualified_value(self, q: str, ctx: Ctx, depth) -> Val:
        parts = q.split(".")
        if len(parts) == 1:
            vs = self._name(parts[0], ctx, depth)
        else:
            vs = self._qualified(".".join(parts[:-1]), parts[-1], ctx, depth)
        return next((v for v in vs if v.kind != "unknown"), UNKNOWN)

    def _name(self, name: str, ctx: Ctx, depth: int, this_only: bool = False) -> list[Val]:
        mi = ctx.method
        if mi is not None and not this_only:
            if name in mi.assigns:
                out = []
                for e in mi.assigns[name]:
                    for v in self.resolve(e, ctx, depth + 1):
                        out.append(self._fill_state(v, mi.filled.get(name)).hop(f"via local `{name}`"))
                return out
            if name in mi.params:
                return self._param(mi, mi.params.index(name), ctx, depth)
            if name in mi.types:
                return [UNKNOWN]
        return self._field(name, ctx, depth)

    def _fill_state(self, v: Val, state: Optional[str]) -> Val:
        if v.kind == "zero_bytes" and state:
            return Val("random_bytes" if state == "random" else "unknown", None, v.via)
        return v

    def _field(self, name: str, ctx: Ctx, depth: int) -> list[Val]:
        classes = [ctx.cls] if ctx.cls and name in ctx.cls.types else []
        if not classes:
            classes = self.p.static_fields.get(name, [])[:3]   # static import / inherited constant
        out = []
        for ci in classes:
            for e, line, owner in ci.assigns.get(name, []):
                c2 = Ctx(ci, owner, ci.file)
                for v in self.resolve(e, c2, depth + 1):
                    label = f"{ci.name}.{name}"
                    v = self._fill_state(v, ci.filled.get(name) or (owner.filled.get(name) if owner else None))
                    out.append(v.hop(f"via field `{label}` ({self._where(ci.file, line, ctx)})"))
            if name in ci.types and not ci.assigns.get(name):
                out.append(UNKNOWN)
        return out or [UNKNOWN]

    def _qualified(self, q: str, member: str, ctx: Ctx, depth: int) -> list[Val]:
        cls_name = q.split(".")[-1]
        if cls_name in self.p.by_name:
            out = []
            for ci in self.p.by_name[cls_name]:
                if member in ci.types:
                    out += self._field(member, Ctx(ci, None, ci.file), depth + 1)
            if out:
                return out
        return [UNKNOWN]

    def _param(self, mi: MethodInfo, idx: int, ctx: Ctx, depth: int) -> list[Val]:
        out = []
        sites = self.p.calls.get((mi.name, len(mi.params)), [])
        unique = sum(len(c.methods.get(mi.name, [])) for c in self.p.classes) == 1
        for inv, cctx in sites[:25]:
            q = getattr(inv, "qualifier", "") or ""
            qtype = _method_ctx_types(cctx, q.split(".")[0]) if q else ""
            same = (q in ("", "this") and cctx.cls is mi.cls) or q.split(".")[-1] == mi.cls.name or qtype == mi.cls.name
            if not (same or (unique and (not qtype or qtype == mi.cls.name))):
                continue
            line = _first_line(inv)
            for v in self.resolve(inv.arguments[idx], cctx, depth + 1):
                if v.kind != "unknown":
                    out.append(v.hop(f"via parameter `{mi.params[idx]}` of {mi.name}(), called from "
                                     f"{cctx.file.name}:{line}"))
        return out or [UNKNOWN]


# ── sinks / rules ───────────────────────────────────────────────────────────

_BROKEN_CIPHERS = {"DES", "DESEDE", "TRIPLEDES", "3DES", "RC4", "ARCFOUR", "RC2", "BLOWFISH", "IDEA"}
_WEAK_DIGEST = re.compile(r"(?i)^(?:MD2|MD4|MD5|SHA-?1|SHA1with\w+|MD5with\w+|HmacMD5|HmacSHA1|PBKDF2WithHmacSHA1)$")
_BROKEN_PBE = re.compile(r"(?i)^PBEWith(?:MD5|SHA1)And(?:DES|RC2|RC4|TripleDES|3KeyTripleDES|DESede)")
_WEAK_TLS = {"SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.1", "TLS1", "TLSV1_1"}
_LOGGER = re.compile(r"(?i)^(?:log|logger|_log|_logger|LOG|LOGGER|slf4jLogger)$")
_SENSITIVE_TYPES = {"PrivateKey", "SecretKey", "SecretKeySpec", "KeyPair", "RSAPrivateKey", "ECPrivateKey", "Key", "char[]"}
_SENSITIVE_NAME = re.compile(r"(?i)password|passwd|secret|private_?key|privkey|apikey|api_key")
_GETINSTANCE_CLASSES = {"Cipher", "KeyGenerator", "KeyPairGenerator", "Signature", "MessageDigest", "Mac", "SecureRandom",
                        "KeyFactory", "SecretKeyFactory", "KeyAgreement", "KeyStore", "SSLContext", "TrustManagerFactory",
                        "KeyManagerFactory"}


@dataclass
class JavaFacts:
    """Per-project facts the BC FIPS project rules in crypto.py need."""
    bc_provider_uses: list = field(default_factory=list)       # (path, line, what)
    unpinned_getinstance: int = 0
    keystore_types: list = field(default_factory=list)          # (path, line, type)
    parsed: set = field(default_factory=set)


class _Scanner:
    def __init__(self, project: Project, root: Path, facts: JavaFacts):
        self.p = project
        self.root = root
        self.r = Resolver(project, root)
        self.facts = facts
        self.findings: list[Finding] = []
        self._line = 1

    def add(self, check_id, severity, title, desc, ctx: Ctx, line: int, confidence=None, val: Optional[Val] = None):
        if val is not None:
            desc += val.origin()
        line = line or self._line
        self.findings.append(make_finding(check_id, severity, title, desc, rel(ctx.file, self.root), line, confidence))

    def first(self, expr, ctx, kinds) -> Optional[Val]:
        for v in self.r.resolve(expr, ctx):
            if v.kind in kinds:
                return v
        return None

    def strings(self, expr, ctx) -> list[Val]:
        return [v for v in self.r.resolve(expr, ctx) if v.kind == "str"]

    # -- traversal --
    def _visit(self, node, ctx: Ctx):
        pos = getattr(node, "position", None)
        if pos:
            self._line = pos.line   # pre-order: last positioned node = enclosing statement
        ci = getattr(node, "_ci", None)
        if ci is not None:
            ctx = Ctx(ci, None, ctx.file)
        mi = getattr(node, "_mi", None)
        if mi is not None:
            ctx = Ctx(ctx.cls, mi, ctx.file)
            self._method_decl(mi, ctx)
        if isinstance(node, T.MethodInvocation):
            self._invocation(node, node.qualifier or "", ctx)
        for sel in getattr(node, "selectors", None) or []:
            if isinstance(sel, T.MethodInvocation):
                self._invocation(sel, "", ctx, chained=True)
        if isinstance(node, T.ClassCreator):
            self._creator(node, ctx)
        if isinstance(node, T.MemberReference) and node.member in ("ALLOW_ALL_HOSTNAME_VERIFIER", "INSTANCE") and \
                (node.qualifier or "").split(".")[-1] in ("SSLSocketFactory", "NoopHostnameVerifier", "TrustAllStrategy"):
            self.add("JC-011", "high", "Certificate / hostname validation disabled",
                     f"{node.qualifier}.{node.member} accepts any certificate or hostname -- any MITM can impersonate "
                     "the server.", ctx, _first_line(node))
        for child in _children(node):
            self._visit(child, ctx)

    # -- method declarations: trust-all managers / verifiers --
    def _method_decl(self, mi: MethodInfo, ctx: Ctx):
        node = mi.node
        if not isinstance(node, T.MethodDeclaration):
            return
        body = node.body or []
        if mi.name in ("checkServerTrusted", "checkClientTrusted") and len(mi.params) in (2, 3):
            if not any(isinstance(n, (T.ThrowStatement, T.MethodInvocation)) for s in body for _, n in s):
                sev = "high" if mi.name == "checkServerTrusted" else "medium"
                self.add("JC-011", sev, f"{mi.name}() accepts every certificate",
                         f"{mi.cls.name}.{mi.name}() neither validates nor throws, so any certificate chain is "
                         "trusted -- a MITM can impersonate the peer and read credentials.", ctx, mi.line)
        if mi.name == "verify" and len(node.parameters) == 2 and _simple_type(node.parameters[1].type) == "SSLSession":
            if _returns_true(body):
                self.add("JC-011", "high", "HostnameVerifier accepts every hostname",
                         "verify() returns true unconditionally, so certificates issued for any host are accepted.",
                         ctx, mi.line)

    # -- object creation --
    def _creator(self, node, ctx: Ctx):
        t = _simple_type(node.type)
        args = node.arguments or []
        line = _first_line(node) or self._line
        if t == "IvParameterSpec" and args:
            v = self.first(args[0], ctx, CONST_BYTES + ("str",))
            if v:
                what = "all-zero" if v.kind == "zero_bytes" else "constant"
                self.add("JC-005", "high", f"Static IV ({what})",
                         "The IV is the same for every encryption, which makes CBC deterministic (identical "
                         "plaintext prefixes produce identical ciphertext). Generate a fresh random IV per "
                         "message with SecureRandom and send it with the ciphertext.", ctx, line, val=v)
        elif t == "GCMParameterSpec" and len(args) >= 2:
            tag = self.first(args[0], ctx, ("int",))
            if tag and tag.value is not None and tag.value < 128:
                self.add("JC-014", "low", f"Short GCM authentication tag ({tag.value} bits)",
                         "Use the full 128-bit tag.", ctx, line, val=tag)
            v = self.first(args[1], ctx, CONST_BYTES + ("str",))
            if v:
                self.add("JC-005", "high", "Static GCM nonce",
                         "Reusing a GCM nonce under the same key lets an attacker recover the authentication "
                         "key and forge messages, and XOR of two ciphertexts leaks the plaintexts. Use a fresh "
                         "12-byte random nonce per message (or a counter that never repeats per key).",
                         ctx, line, val=v)
        elif t == "SecretKeySpec" and args:
            v = self.first(args[0], ctx, CONST_BYTES + ("str",))
            if v:
                what = "all-zero" if v.kind == "zero_bytes" else "hardcoded"
                self.add("JC-006", "high", f"Hardcoded symmetric key ({what})",
                         "The key is compiled into the jar, so anyone with the artifact can decrypt or forge. "
                         "Load keys from a keystore (BCFKS under FIPS), KMS or an HSM.", ctx, line, val=v)
        elif t == "PBEKeySpec" and args:
            pw = self.first(args[0], ctx, ("chars_const", "str"))
            if pw:
                self.add("JC-013", "high", "Hardcoded password for key derivation",
                         "The password fed to PBKDF2 is a literal, so the derived key is effectively hardcoded.",
                         ctx, line, val=pw)
            if len(args) >= 2:
                salt = self.first(args[1], ctx, CONST_BYTES + ("str",))
                if salt:
                    self.add("JC-017", "medium", "Static salt for key derivation",
                             "A constant salt lets an attacker precompute guesses once for every user/record. "
                             "Generate a random 16+ byte salt per derivation and store it alongside the output.",
                             ctx, line, val=salt)
            if len(args) >= 3:
                it = self.first(args[2], ctx, ("int",))
                if it and it.value is not None and it.value < 100_000:
                    self.add("JC-010", "medium", f"Low PBKDF2 iteration count ({it.value})",
                             "OWASP recommends >= 600,000 iterations for PBKDF2-HMAC-SHA256 (SP 800-132's 1,000 "
                             "minimum is far too low today).", ctx, line, val=it)
        elif t == "RSAKeyGenParameterSpec" and args:
            n = self.first(args[0], ctx, ("int",))
            if n and n.value is not None and n.value < 2048:
                self.add("JC-009", "high", f"RSA key size {n.value} bits",
                         "RSA below 2048 bits is factorable/not FIPS-acceptable. Use 3072+.", ctx, line, val=n)
        elif t == "PasswordProtection" and args:
            pw = self.first(args[0], ctx, ("chars_const", "str"))
            if pw:
                self.add("JC-013", "high", "Hardcoded keystore entry password",
                         "The keystore password is in the code; read it from a secrets manager at runtime.",
                         ctx, line, val=pw)
        elif t == "SecureRandom" and args:
            v = self.first(args[0], ctx, CONST_BYTES + ("str",))
            if v:
                self.add("JC-008", "high", "SecureRandom constructed with a constant seed",
                         "Seeding SecureRandom with a constant can make its output reproducible (always with "
                         "SHA1PRNG). Use the no-arg constructor / DRBG.", ctx, line, val=v)
        elif t == "Random":
            self._weak_random(ctx, line, "new Random()")
        elif t == "BouncyCastleProvider":
            self.facts.bc_provider_uses.append((ctx.file, line, "new BouncyCastleProvider()"))
        elif t in ("NoopHostnameVerifier", "TrustAllStrategy", "TrustSelfSignedStrategy"):
            self.add("JC-011", "high" if t != "TrustSelfSignedStrategy" else "medium",
                     f"{t} disables certificate / hostname validation",
                     f"{t} accepts certificates or hostnames without validation -- any MITM can impersonate "
                     "the server.", ctx, line)

    def _weak_random(self, ctx: Ctx, line: int, what: str):
        names = []
        if ctx.method:
            names = [ctx.method.name] + list(ctx.method.types)
        names += [ctx.cls.name] if ctx.cls else []
        if any(_SECURITY_CONTEXT.search(n) for n in names):
            self.add("JC-007", "medium", f"Non-cryptographic RNG ({what}) in security-sensitive code",
                     "java.util.Random / Math.random / ThreadLocalRandom are predictable from a few outputs. "
                     "Use SecureRandom (CryptoServicesRegistrar.getSecureRandom() under BC FIPS) for keys, "
                     "IVs, salts and tokens.", ctx, line, "REVIEW")

    # -- method calls --
    def _invocation(self, inv, qualifier: str, ctx: Ctx, chained: bool = False):
        m = inv.member
        args = inv.arguments or []
        line = _first_line(inv) or self._line
        qcls = qualifier.split(".")[-1]
        if m == "getInstance" and qcls in _GETINSTANCE_CLASSES and args:
            self._get_instance(qcls, args, ctx, line)
            return
        if qualifier == "Math" and m == "random" or qualifier == "ThreadLocalRandom" and m == "current":
            self._weak_random(ctx, line, f"{qualifier}.{m}()")
            return
        recv_type = _method_ctx_types(ctx, qualifier.split(".")[0]) if qualifier and not chained else ""
        if m == "initialize" and args and (recv_type == "KeyPairGenerator" or re.search(r"(?i)kpg|keypair", qualifier)):
            n = self.first(args[0], ctx, ("int",))
            if n and n.value is not None:
                alg = self._kpg_alg(qualifier, ctx)
                if alg in ("EC", "ECDSA", "ECDH"):
                    bad, need = n.value < 224, "224 (P-256 recommended)"
                elif alg in ("RSA", "DSA", "DH", "DIFFIEHELLMAN"):
                    bad, need = n.value < 2048, "2048 (3072 recommended)"
                else:
                    bad, need = n.value < 2048 and n.value not in (224, 256, 384, 521), "2048"
                if bad:
                    self.add("JC-009", "high", f"{alg or 'Key pair'} key size {n.value} bits",
                             f"Below the {need}-bit minimum (NIST SP 800-131A / FIPS).", ctx, line, val=n)
        elif m == "init" and args and recv_type == "KeyGenerator":
            n = self.first(args[0], ctx, ("int",))
            if n and n.value is not None and n.value < 128:
                self.add("JC-009", "high", f"Symmetric key size {n.value} bits",
                         "Symmetric keys below 128 bits are brute-forceable. Use AES-256.", ctx, line, val=n)
        elif m == "setSeed" and args and (recv_type == "SecureRandom" or re.search(r"(?i)rand|rng|prng", qualifier)):
            v = self.first(args[0], ctx, ("int", "clock") + CONST_BYTES + ("str",))
            if v:
                what = "the clock" if v.kind == "clock" else "a constant"
                self.add("JC-008", "high", f"SecureRandom seeded with {what}",
                         "An explicitly seeded SecureRandom (always with SHA1PRNG, and with some providers "
                         "otherwise) produces predictable output -- keys and IVs from it can be reproduced.",
                         ctx, line, val=v)
        elif m in ("load", "store") and len(args) == 2 or m == "getKey" and len(args) == 2 or \
                m == "setKeyEntry" and len(args) == 4 or m == "init" and len(args) == 2 and recv_type == "KeyManagerFactory":
            idx = {"load": 1, "store": 1, "getKey": 1, "setKeyEntry": 2, "init": 1}[m]
            if m == "init" or recv_type in ("KeyStore", "") or "store" in qualifier.lower() or "ks" == qualifier.lower():
                pw = self.first(args[idx], ctx, ("chars_const",))
                if pw:
                    self.add("JC-013", "high", "Hardcoded keystore / key password",
                             "The keystore password is in the code, so the keystore's protection is only as good "
                             "as the jar's secrecy. Read it from a secrets manager / environment at runtime.",
                             ctx, line, val=pw)
        elif m == "setEnabledProtocols" and args:
            for v in self.r.resolve(args[0], ctx):
                vals = v.value if v.kind == "array" else ([v.value] if v.kind == "str" else [])
                weak = [p for p in vals if str(p).upper() in _WEAK_TLS]
                if weak:
                    self.add("JC-012", "medium", f"Obsolete TLS protocol enabled ({', '.join(weak)})",
                             "Enable TLSv1.2/TLSv1.3 only.", ctx, line, val=v)
                    break
        elif m in ("setHostnameVerifier", "setDefaultHostnameVerifier") and args:
            a = args[0]
            if isinstance(a, T.LambdaExpression) and _lambda_true(a):
                self.add("JC-011", "high", "HostnameVerifier lambda accepts every hostname",
                         "(host, session) -> true disables hostname verification.", ctx, line)
        elif _LOGGER.match(qualifier.split(".")[-1] or "-") or qualifier in ("System.out", "System.err"):
            self._logged(inv, ctx, line)

    def _kpg_alg(self, var: str, ctx: Ctx) -> str:
        expr = None
        if ctx.method and var in ctx.method.kpg_alg:
            expr = ctx.method.kpg_alg[var]
        elif ctx.cls:
            for e, _, owner in ctx.cls.assigns.get(var, []):
                if _is_static_call(e, "KeyPairGenerator", "getInstance") and e.arguments:
                    expr = e.arguments[0]
        if expr is None:
            return ""
        s = self.strings(expr, ctx)
        return s[0].value.upper() if s else ""

    def _get_instance(self, cls: str, args, ctx: Ctx, line: int):
        algs = self.strings(args[0], ctx)
        if len(args) == 1:
            self.facts.unpinned_getinstance += 1
        else:
            for pv in self.strings(args[1], ctx):
                if pv.value == "BC":
                    self.facts.bc_provider_uses.append((ctx.file, line, f'{cls}.getInstance(..., "BC")'))
            if isinstance(args[1], T.MemberReference) and args[1].member == "PROVIDER_NAME" and \
                    (args[1].qualifier or "").endswith("BouncyCastleProvider"):
                self.facts.bc_provider_uses.append((ctx.file, line, "BouncyCastleProvider.PROVIDER_NAME"))
        for v in algs:
            alg = v.value
            if cls == "Cipher":
                self._cipher(alg, ctx, line, v)
            elif cls in ("MessageDigest", "Signature", "Mac", "SecretKeyFactory", "KeyPairGenerator") and _WEAK_DIGEST.match(alg):
                self.add("JC-004", "medium", f"Weak hash / signature algorithm ({alg})",
                         "MD5/SHA-1 are collision-broken and SHA-1 signatures aren't FIPS-approved for "
                         "generation. Use SHA-256+ (HMAC-SHA-256 / PBKDF2WithHmacSHA256).", ctx, line, val=v)
            if cls in ("SecretKeyFactory", "Cipher") and _BROKEN_PBE.match(alg):
                self.add("JC-010", "high", f"Broken password-based encryption scheme ({alg})",
                         "These PBE schemes use broken hashes/ciphers. Derive an AES-GCM key with "
                         "PBKDF2WithHmacSHA256 (>= 600k iterations) or use a KMS.", ctx, line, val=v)
            if cls == "SecureRandom" and alg.upper() == "SHA1PRNG":
                self.add("JC-008", "medium", "SHA1PRNG SecureRandom",
                         "SHA1PRNG isn't a FIPS-approved DRBG and is deterministic if seeded explicitly. Use "
                         "SecureRandom.getInstance(\"DEFAULT\", \"BCFIPS\") or getInstanceStrong().",
                         ctx, line, val=v)
            if cls == "SSLContext" and alg.upper() in _WEAK_TLS:
                self.add("JC-012", "medium", f"Obsolete SSL/TLS protocol ({alg})", "Use TLSv1.2/TLSv1.3 only.",
                         ctx, line, val=v)
            if cls == "KeyStore" and alg.upper() in ("JKS", "JCEKS", "PKCS12"):
                self.facts.keystore_types.append((ctx.file, line, alg))

    def _cipher(self, transform: str, ctx: Ctx, line: int, v: Val):
        parts = [p.strip().upper() for p in transform.split("/")]
        alg = parts[0]
        mode = parts[1] if len(parts) > 1 else ""
        pad = parts[2] if len(parts) > 2 else ""
        if alg in _BROKEN_CIPHERS:
            self.add("JC-001", "high", f"Broken cipher algorithm ({transform})",
                     "DES/3DES/RC4/RC2/Blowfish are broken or deprecated and not FIPS-approved for new "
                     "encryption (3DES encryption was disallowed after 2023). Use AES-GCM.", ctx, line, val=v)
        elif alg == "RSA":
            if len(parts) == 1 or pad in ("PKCS1PADDING", "NOPADDING"):
                self.add("JC-003", "medium", f"RSA encryption without OAEP ({transform})",
                         "PKCS#1 v1.5 padding is padding-oracle prone (Bleichenbacher) and raw RSA is malleable. "
                         "Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding.", ctx, line, val=v)
        elif len(parts) == 1 and alg == "AES":
            self.add("JC-002", "medium", "Cipher transformation without mode (defaults to ECB)",
                     "\"AES\" alone means AES/ECB/PKCS5Padding in most providers. Specify AES/GCM/NoPadding.",
                     ctx, line, val=v)
        elif mode == "ECB":
            self.add("JC-002", "high", f"ECB mode ({transform})",
                     "ECB encrypts identical blocks to identical ciphertext, leaking data patterns. Use "
                     "AES/GCM/NoPadding with a unique 12-byte nonce per message.", ctx, line, val=v)
        elif alg == "AES" and mode == "CBC" and not self._file_has_mac(ctx.file):
            self.add("JC-015", "low", f"CBC mode without visible integrity protection ({transform})",
                     "Unauthenticated CBC is malleable and padding-oracle prone if decryption errors are "
                     "observable. Prefer AES/GCM, or encrypt-then-MAC with HMAC-SHA-256.",
                     ctx, line, "REVIEW", val=v)

    def _file_has_mac(self, path: Path) -> bool:
        for _, n in self.p.trees[path]:
            if isinstance(n, T.MethodInvocation) and n.member == "getInstance" and (n.qualifier or "").endswith("Mac"):
                return True
        return False

    def _logged(self, inv, ctx: Ctx, line: int):
        for a in inv.arguments or []:
            for _, n in a if isinstance(a, T.Node) else []:
                hit = None
                if isinstance(n, T.MethodInvocation) and n.member in ("getEncoded", "getPrivate"):
                    hit = f"{n.qualifier or ''}.{n.member}()".lstrip(".")
                elif isinstance(n, T.MemberReference) and not n.qualifier:
                    t = _method_ctx_types(ctx, n.member)
                    if t in _SENSITIVE_TYPES or _SENSITIVE_NAME.search(n.member):
                        hit = n.member
                if hit:
                    self.add("JC-016", "medium", f"Key material / secret logged ({hit})",
                             "Key material and passwords written to logs outlive the key's own protections.",
                             ctx, line, "REVIEW")
                    return


def _returns_true(body) -> bool:
    stmts = [s for s in body or []]
    return len(stmts) == 1 and isinstance(stmts[0], T.ReturnStatement) and \
        isinstance(stmts[0].expression, T.Literal) and stmts[0].expression.value == "true"


def _lambda_true(lam) -> bool:
    body = lam.body
    if isinstance(body, T.Literal):
        return body.value == "true"
    if isinstance(body, list):
        return _returns_true(body)
    return False


# ── entry point ─────────────────────────────────────────────────────────────

def scan(root: Path, texts: dict[Path, str]) -> tuple[list[Finding], JavaFacts]:
    """Parse every .java file in `texts`; returns findings plus facts for the
    BC FIPS project rules. Paths that failed to parse are absent from
    facts.parsed (the caller runs the regex rules on those)."""
    facts = JavaFacts()
    project = Project()
    for path, text in texts.items():
        if path.suffix != ".java":
            continue
        try:
            tree = javalang.parse.parse(text)
            project.add_file(path, tree)
        except Exception:
            continue          # regex fallback for this file
        facts.parsed.add(path)
    project.index_calls()
    s = _Scanner(project, root, facts)
    for path, tree in list(project.trees.items()):
        if path not in facts.parsed:
            continue
        before = len(s.findings)
        try:
            s._visit(tree, Ctx(None, None, path))
        except Exception:
            # Never lose a file to an analyzer bug: drop its partial AST
            # results and let the line rules cover it.
            del s.findings[before:]
            facts.parsed.discard(path)
    facts.bc_provider_uses = [u for u in facts.bc_provider_uses if u[0] in facts.parsed]
    facts.keystore_types = [k for k in facts.keystore_types if k[0] in facts.parsed]
    # One finding per (rule, file, line).
    seen, out = set(), []
    for f in s.findings:
        key = (f.check_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out, facts
