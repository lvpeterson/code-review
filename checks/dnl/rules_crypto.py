"""Crypto and hardcoded-secret findings read from code (legacy .NET Framework).

DNL-CRY-001  MD5 / SHA1 (high when the hashed value looks like a password)
DNL-CRY-002  DES / 3DES / RC2
DNL-CRY-003  CipherMode.ECB
DNL-CRY-004  constant key / IV (byte-array literal, Encoding.GetBytes("lit"), Convert.FromBase64String("lit"))
DNL-CRY-005  System.Random feeding a token / password / salt / ... (REVIEW)
DNL-CRY-006  certificate validation disabled (callback or ICertificatePolicy that always accepts)
DNL-CRY-007  ServicePointManager.SecurityProtocol including Ssl3 / Tls / Tls11
DNL-CRY-008  PasswordDeriveBytes, Rfc2898DeriveBytes with fewer than 10000 iterations
DNL-SEC-003  hardcoded credential in code

Every method, accessor body and field initializer of the model is scanned. Types are
identified `sym` first (`type_full`, call / member `sym` under System.Security.Cryptography,
System.Net.*), then by the names written in source, so code that does not resolve against
the net48 reference set is still covered. Crypto objects are tracked per type: a field or
property typed `Aes` / `SymmetricAlgorithm` (or initialised from `Aes.Create()`) marks
`.Mode` / `.Key` / `.IV` assignments in any method of the type, constructors included, and
a field holding constant bytes counts as a constant key or IV wherever it is used.

Findings are route-less unless the code sits inside a route handler's own method (then the
route and its api_surface are attached); route-less ones are placed by the analyzers.
"""
from __future__ import annotations

import re

from checks.dnl.findings import dnl_finding
from checks.dnl.ir import MethodIR, TypeIR, call_name, const_str, literal_str, receiver_text, walk
from checks.dnl.project import ProjectModel
from checks.dnl.rules_config import _CONN_PW, _PLACEHOLDER, _SECRET_KEY, _is_setting_key
from checks.dnl.typestate import RouteIndex, iter_bodies, simple, tail, type_of
from core.models import Finding

_CRYPTO_NS = "System.Security.Cryptography."
_WEAK_HASH_T = re.compile(r"(?i)^(md5|sha1)(cryptoserviceprovider|managed|cng)?$")
_WEAK_CIPHER_T = re.compile(r"(?i)^(des|tripledes|rc2)(cryptoserviceprovider|cng)?$")
_CIPHER_T = re.compile(r"(?i)^(aes\w*|rijndael\w*|symmetricalgorithm|des\w*|tripledes\w*|rc2\w*|hmac\w*|keyedhashalgorithm)$")
_WEAK_HASH_NAMES = {"md5", "sha1", "sha-1", "system.security.cryptography.md5", "system.security.cryptography.sha1"}
_WEAK_CIPHER_NAMES = {"des", "3des", "tripledes", "rc2", "system.security.cryptography.des",
                      "system.security.cryptography.tripledes", "system.security.cryptography.rc2"}
_PASSWORD = re.compile(r"(?i)pass(word)?|pwd")
_SECRET_NAME = re.compile(r"(?i)token|password|salt|otp|nonce|secret|key|code|reset")
_RAND_METHODS = {"next", "nextbytes", "nextdouble"}
_ACCUMULATORS = {"append", "appendformat", "appendline", "insert", "add", "write"}
_CERT_CALLBACKS = {"servercertificatevalidationcallback", "servercertificatecustomvalidationcallback"}
_OLD_PROTOCOLS = {"ssl3", "tls", "tls11"}
# SecurityProtocolType bit values: Ssl3 = 48, Tls = 192, Tls11 = 768.
_OLD_PROTOCOL_BITS = 48 | 192 | 768
_CRED_CTORS = {"networkcredential": 1, "directoryentry": 2}
_CONNECTION_T = re.compile(r"(?i)connection(stringbuilder)?$")
_BRACE_INDEX = re.compile(r"^\{\d+\}$")
_NAME_SUFFIXES = ("key", "name", "id", "label", "text", "field", "param", "parameter", "header", "cookie",
                  "prefix", "setting", "property", "title", "const", "constant")
_STR_NORMAL = re.compile(r"[^a-z0-9]")


_simple = simple


def _is_true(expr) -> bool:
    return isinstance(expr, dict) and expr.get("k") == "lit" and expr.get("v") is True


def _all_true(body) -> bool:
    """Every `return` in the body is literal true (and there is at least one)."""
    returns = [n for n in walk(body) if n.get("k") == "return"]
    return bool(returns) and all(_is_true(r.get("value")) for r in returns)


def _idents(expr) -> set[str]:
    """Lowered names and member names appearing anywhere in an expression."""
    out: set[str] = set()
    for n in walk(expr):
        if n.get("k") == "name" and n.get("id"):
            out.add(n["id"].lower())
        elif n.get("k") == "member" and n.get("name"):
            out.add(n["name"].lower())
    return out


_tail = tail


def _target_name(target) -> str:
    return _tail(target)


def _in_crypto_ns(*syms: str | None) -> bool:
    """False only when a symbol resolved to something outside System.Security.Cryptography."""
    known = [s for s in syms if s]
    return all(s.startswith(_CRYPTO_NS) for s in known)


_type_of = type_of


class _Env:
    """Names visible in one body: locals, parameters and the type's fields / properties,
    mapped to their lowered type names, plus which of them hold constant key material."""

    def __init__(self, scan: "_Scan", t: TypeIR, method: MethodIR | None, nodes: list[dict]):
        self.scan = scan
        self.t = t
        self.names: dict[str, str] = dict(scan.type_names(t))
        self.consts: set[str] = set(scan.type_consts(t))
        self.ints: dict[str, int] = dict(scan.type_ints(t))
        self.strs: set[str] = set(scan.type_strs(t))
        if method is not None:
            for p in method.params:
                self.names[p.name.lower()] = _simple(p.type)
        for n in nodes:
            if n.get("k") == "local" and n.get("name"):
                nm = n["name"].lower()
                self.names[nm] = _type_of(n.get("type"), n.get("type_full"), n.get("init")) or self.names.get(nm, "")
                if self.is_const_text(n.get("init")):
                    self.strs.add(nm)
                iv = self.const_int(n.get("init"))
                if iv is not None:
                    self.ints[nm] = iv
        for n in nodes:
            if n.get("k") == "local" and n.get("name") and self.const_key(n.get("init")):
                self.consts.add(n["name"].lower())
        self.drop_filled(nodes)

    def drop_filled(self, nodes: list[dict], skip: frozenset[str] = frozenset()) -> None:
        """A buffer that starts as `new byte[n]` but is filled (RNG / Array.Copy destination, a
        non-constant `Fill`) or reassigned from a non-constant is not constant key material any
        more, and a string that is appended to or reassigned from a non-constant is not a constant
        string. Applied per method (locals) and per type (fields, from every method): `skip` holds the
        locals / parameters of the method being scanned, so a same-named local never counts as a
        write to the field."""
        def is_field_write(expr) -> bool:
            if isinstance(expr, dict) and expr.get("k") == "name":
                return (expr.get("id") or "").lower() not in skip
            return not skip or (isinstance(expr, dict) and expr.get("k") == "member"
                                and _tail(expr.get("obj")) in ("this", "me"))

        for n in nodes:
            k = n.get("k")
            if k == "assign":
                tgt = n.get("target")
                nm = ""
                if isinstance(tgt, dict) and tgt.get("k") == "name":
                    nm = (tgt.get("id") or "").lower()
                elif isinstance(tgt, dict) and tgt.get("k") == "member" and _tail(tgt.get("obj")) in ("this", "me"):
                    nm = (tgt.get("name") or "").lower()
                if not nm or not is_field_write(tgt):
                    continue
                value = n.get("value")
                if n.get("op") != "=":
                    # `x += v`: a byte buffer stays unknown, a string stays constant while v is.
                    self.consts.discard(nm)
                    if not self.is_const_text(value):
                        self.strs.discard(nm)
                else:
                    if not self.const_key(value):
                        self.consts.discard(nm)
                    if not self.is_const_text(value):
                        self.strs.discard(nm)
            elif k == "call":
                name = (call_name(n) or "").lower()
                args = n.get("args") or []
                fn_obj = (n.get("fn") or {}).get("obj")
                recv = receiver_text(fn_obj).lower()
                dest = None
                if name in ("getbytes", "getnonzerobytes", "nextbytes", "read") and args and "encoding" not in recv:
                    dest = args[0]
                elif name == "fill":
                    if recv.endswith("array") and len(args) >= 2:
                        # Array.Fill(buf, value): a constant value leaves the buffer constant.
                        dest = args[0] if not self.const_elem(args[1]) else None
                    elif recv.endswith("randomnumbergenerator") and args:
                        dest = args[0]
                    elif args and fn_obj is not None and not self.const_elem(args[0]):
                        dest = fn_obj      # span.Fill(value)
                elif name in ("copy", "blockcopy") and len(args) >= 3:
                    # Array.Copy(src, dst, n) / Array.Copy(src, i, dst, j, n) / Buffer.BlockCopy(src, i, dst, j, n)
                    dest = args[1] if name == "copy" and len(args) <= 4 else args[2]
                elif name == "copyto" and args:
                    dest = args[0]
                if dest is not None and _tail(dest) and is_field_write(dest):
                    self.consts.discard(_tail(dest))

    def const_key(self, e, depth: int = 0) -> bool:
        """Constant key / IV material: a byte-array literal, an all-zero `new byte[n]`,
        `Encoding.X.GetBytes("lit")`, `Convert.FromBase64String("lit")`, or a name /
        member that resolves to one (this type's field, a local, another project type's field)."""
        if not isinstance(e, dict) or depth > 3:
            return False
        k = e.get("k")
        if k == "cast":
            return self.const_key(e.get("e"), depth + 1)
        if k == "new":
            ty = (e.get("type") or "").replace(" ", "").lower()
            if ty.startswith(("byte[", "byte(")):
                init = e.get("init") or []
                if init:
                    return all(self.const_elem(i.get("value")) for i in init)
                return bool(re.fullmatch(r"byte[\[(]\d+[\])]", ty))
            return False
        if k == "call":
            name = (call_name(e) or "").lower()
            args = e.get("args") or []
            if name == "getbytes" and args and self.is_const_text(args[0]):
                fn = e.get("fn") or {}
                return "encoding" in receiver_text(fn.get("obj")).lower() or (e.get("sym") or "").startswith("System.Text.Encoding")
            if name in ("frombase64string", "fromhexstring") and args:
                return self.is_const_text(args[0])
            return False
        if k == "name":
            return (e.get("id") or "").lower() in self.consts
        if k == "member":
            obj = e.get("obj")
            if _tail(obj) in ("this", "me", "base", "mybase") or obj is None:
                return (e.get("name") or "").lower() in self.consts
            owner = _tail(obj)
            for ot in self.scan.model.find_types(owner):
                for f in ot.fields:
                    if f.name.lower() == (e.get("name") or "").lower() and self.const_key(f.init, depth + 1):
                        return True
            return False
        return False

    def const_elem(self, e) -> bool:
        """An element of a byte-array initializer that is a compile-time constant:
        a literal, a cast / arithmetic over constants, or a constant field / local."""
        if not isinstance(e, dict):
            return False
        k = e.get("k")
        if k == "lit":
            return True
        if k in ("cast", "unary"):
            return self.const_elem(e.get("e"))
        if k == "bin":
            return self.const_elem(e.get("l")) and self.const_elem(e.get("r"))
        if k == "name":
            return (e.get("id") or "").lower() in self.ints
        if k == "member":
            obj = e.get("obj")
            if obj is None or _tail(obj) in ("this", "me", "base", "mybase"):
                return (e.get("name") or "").lower() in self.ints
        return False

    def is_const_text(self, e, depth: int = 0) -> bool:
        """A compile-time string: a literal or concatenation of literals, or a name / member
        resolving to a constant string field or local (this type, or another project type)."""
        if not isinstance(e, dict) or depth > 3:
            return False
        if const_str(e) is not None:
            return True
        k = e.get("k")
        if k == "bin" and e.get("op") in ("+", "&", "concat"):
            return self.is_const_text(e.get("l"), depth + 1) and self.is_const_text(e.get("r"), depth + 1)
        if k == "name":
            return (e.get("id") or "").lower() in self.strs
        if k == "member":
            obj = e.get("obj")
            if obj is None or _tail(obj) in ("this", "me", "base", "mybase"):
                return (e.get("name") or "").lower() in self.strs
            for ot in self.scan.model.find_types(_tail(obj)):
                for f in ot.fields:
                    if f.name.lower() == (e.get("name") or "").lower() and self.is_const_text(f.init, depth + 1):
                        return True
        return False

    def const_int(self, e) -> int | None:
        if isinstance(e, dict):
            if e.get("k") == "lit" and isinstance(e.get("v"), int) and not isinstance(e.get("v"), bool):
                return e["v"]
            if e.get("k") == "cast":
                return self.const_int(e.get("e"))
            if e.get("k") == "name":
                return self.ints.get((e.get("id") or "").lower())
            if e.get("k") == "member":
                obj = e.get("obj")
                if obj is None or _tail(obj) in ("this", "me", "base", "mybase"):
                    return self.ints.get((e.get("name") or "").lower())
        return None

    def is_cipher_target(self, target) -> bool:
        """Does `x.Key` / `x.IV` / `x.Mode` write to a cipher object?"""
        if not isinstance(target, dict) or target.get("k") != "member":
            return False
        sym = target.get("sym") or ""
        if sym:
            return sym.startswith(_CRYPTO_NS)
        return bool(_CIPHER_T.match(self.names.get(_tail(target.get("obj")), "")))


class _Scan:
    """One pass over a ProjectModel; collects findings keyed by (rule, file, line)."""

    def __init__(self, model: ProjectModel, refs):
        self.model = model
        self.found: dict[tuple, Finding] = {}
        self.routes = RouteIndex(refs)
        self._names: dict[int, dict[str, str]] = {}
        self._consts: dict[int, set[str]] = {}
        self._ints: dict[int, dict[str, int]] = {}
        self._strs: dict[int, set[str]] = {}

    # -- per-type tracked state -------------------------------------------

    def _type_state(self, t: TypeIR) -> None:
        env = _Env.__new__(_Env)
        env.scan, env.t, env.names, env.consts, env.ints, env.strs = self, t, {}, set(), {}, set()
        for p in t.properties:
            env.names[p.name.lower()] = _simple(p.type)
        for f in t.fields:
            env.names[f.name.lower()] = _type_of(f.type, None, f.init) or env.names.get(f.name.lower(), "")
        # Constants second, two rounds (a field may name another, `Iv = Key`); property
        # initializers (`{ get; } = expr`) count like fields.
        decls = [(f.name, f.init) for f in t.fields] + [(p.name, p.init) for p in t.properties]
        for _ in range(2):
            for nm, init in decls:
                if init is None:
                    continue
                if env.is_const_text(init):
                    env.strs.add(nm.lower())
                iv = env.const_int(init)
                if iv is not None:
                    env.ints[nm.lower()] = iv
        for _ in range(2):
            for nm, init in decls:
                if init is not None and env.const_key(init):
                    env.consts.add(nm.lower())
        # Writes to a field from any method of the type (an RNG fill in the constructor, an append).
        for m in t.methods:
            body = list(walk(m.body))
            declared = {p.name.lower() for p in m.params} | {n["name"].lower() for n in body
                                                              if n.get("k") == "local" and n.get("name")}
            env.drop_filled(body, frozenset(declared))
        for p in t.properties:
            env.drop_filled(list(walk(p.get)) + list(walk(p.set)), frozenset({"value", (p.set_param or "").lower()}))
        self._names[id(t)], self._consts[id(t)], self._ints[id(t)] = env.names, env.consts, env.ints
        self._strs[id(t)] = env.strs

    def type_names(self, t: TypeIR) -> dict[str, str]:
        if id(t) not in self._names:
            self._type_state(t)
        return self._names[id(t)]

    def type_consts(self, t: TypeIR) -> set[str]:
        self.type_names(t)
        return self._consts[id(t)]

    def type_ints(self, t: TypeIR) -> dict[str, int]:
        self.type_names(t)
        return self._ints[id(t)]

    def type_strs(self, t: TypeIR) -> set[str]:
        self.type_names(t)
        return self._strs[id(t)]

    # -- output -------------------------------------------------------------

    def add(self, rule: str, severity: str, title: str, text: str, t: TypeIR, where: str, line: int,
            confidence: str | None = None) -> None:
        # The text names the primitive / credential, so two issues on one line stay distinct.
        key = (rule, t.file, line, text)
        if key in self.found:
            return
        route = self.routes.route(t.file, line)
        api = bool(route.meta.get("api_surface")) if route else False
        self.found[key] = dnl_finding(rule, severity, title, f"{text} (in {t.name}.{where}).", t.file, line,
                                      route=route, api_surface=api, confidence=confidence)

    # -- bodies -------------------------------------------------------------

    def run(self) -> list[Finding]:
        for t in self.model.types():
            if t.kind == "enum":
                continue
            bodies = [(label, m, body) for label, m, body, _scope in iter_bodies(t)]
            prepared = [(label, _Env(self, t, m, list(walk(b))), list(walk(b))) for label, m, b in bodies]
            for label, env, nodes in prepared:
                self._weak_crypto(t, label, env, nodes, prepared)
                self._cipher_settings(t, label, env, nodes)
                self._random(t, label, env, nodes)
                self._tls(t, label, env, nodes)
                self._kdf(t, label, env, nodes)
                self._secrets(t, label, env, nodes)
            for f in t.fields:
                if f.init is not None:
                    self._secret_pair(t, f.name, f.name, f.init, f.line or f.init.get("line", 0))
            for p in t.properties:
                if p.init is not None:
                    self._secret_pair(t, p.name, p.name, p.init, p.line or p.init.get("line", 0))
        return list(self.found.values())

    # -- CRY-001 / CRY-002 --------------------------------------------------

    def _weak_crypto(self, t, label, env, nodes, prepared) -> None:
        for n in nodes:
            k = n.get("k")
            line = n.get("line", 0)
            hit = None  # ("hash" | "cipher" | "legacy", what)
            if k == "new":
                ty = _simple(n.get("type_full") or n.get("type"))
                if _in_crypto_ns(n.get("type_full")):
                    if _WEAK_HASH_T.match(ty):
                        hit = ("hash", ty)
                    elif _WEAK_CIPHER_T.match(ty):
                        hit = ("cipher", ty)
            elif k == "call":
                name = (call_name(n) or "").lower()
                recv = _tail((n.get("fn") or {}).get("obj"))
                args = n.get("args") or []
                sym = n.get("sym")
                if sym and sym.startswith(_CRYPTO_NS) and sym.count(".") >= 4:
                    # `using Sha = ...SHA1; Sha.Create()`: the declaring type of the resolved method.
                    recv = sym.rsplit(".", 2)[-2].lower()
                if name == "create" and _in_crypto_ns(sym):
                    if not args and recv in ("md5", "sha1"):
                        hit = ("hash", recv)
                    elif not args and recv in ("des", "tripledes", "rc2"):
                        hit = ("cipher", recv)
                    elif args and recv in ("hashalgorithm", "symmetricalgorithm") and const_str(args[0]) is not None:
                        want = const_str(args[0]).lower()
                        if recv == "hashalgorithm" and want in _WEAK_HASH_NAMES:
                            hit = ("hash", want)
                        elif recv == "symmetricalgorithm" and want in _WEAK_CIPHER_NAMES:
                            hit = ("cipher", want)
                elif name == "createfromname" and recv == "cryptoconfig" and args and const_str(args[0]) is not None:
                    want = const_str(args[0]).lower()
                    if want in _WEAK_HASH_NAMES:
                        hit = ("hash", want)
                    elif want in _WEAK_CIPHER_NAMES:
                        hit = ("cipher", want)
                elif name == "hashpasswordforstoringinconfigfile" and len(args) >= 2:
                    if (const_str(args[1]) or "").lower() in _WEAK_HASH_NAMES:
                        hit = ("legacy", (const_str(args[1]) or "").upper())
            if hit is None:
                continue
            kind, what = hit
            if kind == "cipher":
                self.add("DNL-CRY-002", "high", "Weak symmetric cipher",
                         f"{what.upper()} is a broken or obsolete cipher (56 / 64 bit blocks or keys); use AES-GCM or "
                         f"AES-CBC with HMAC", t, label, line)
                continue
            if kind == "legacy":
                self.add("DNL-CRY-001", "high", "Weak password hash",
                         f"HashPasswordForStoringInConfigFile with {what} stores a fast, unsalted hash; use "
                         f"PBKDF2 (Rfc2898DeriveBytes with a high iteration count), bcrypt or Argon2",
                         t, label, line)
                continue
            password = self._password_context(t, label, n, nodes, prepared)
            self.add("DNL-CRY-001", "high" if password else "medium", "Weak hash algorithm (MD5 / SHA1)",
                     f"{what.upper()} is collision-prone and fast to brute-force"
                     + ("; the hashed value looks like a password, use PBKDF2 / bcrypt / Argon2" if password
                        else "; use SHA-256 or stronger for integrity"), t, label, line)

    def _password_context(self, t, label, site, nodes, prepared) -> bool:
        """Does the weak hash cover a password? Looks at the enclosing method / field name and,
        for `ComputeHash` calls on the weak object, the hashed arguments and the names the
        result is stored in."""
        if _PASSWORD.search(label):
            return True
        # A weak object held in a field is used from any method of the type.
        scopes = [nodes]
        weak: set[str] = set()
        site_ids = {id(x) for x in walk(site)}
        for n in nodes:
            if n.get("k") == "local" and n.get("name"):
                init_ids = {id(x) for x in walk(n.get("init"))}
                if site_ids & init_ids or _WEAK_HASH_T.match(_type_of(n.get("type"), n.get("type_full"))):
                    weak.add(n["name"].lower())
        for f in t.fields:
            if f.init is not None and (id(f.init) in site_ids or _WEAK_HASH_T.match(_type_of(f.type, None, f.init))):
                weak.add(f.name.lower())
                scopes = [ns for _l, _e, ns in prepared]
        for ns in scopes:
            stmts = [x for x in ns if x.get("k") in ("local", "assign")]
            for c in ns:
                if c.get("k") != "call" or (call_name(c) or "").lower() not in ("computehash", "computehashasync", "transformfinalblock"):
                    continue
                recv = (c.get("fn") or {}).get("obj")
                if _tail(recv) not in weak and not (id(site) in {id(x) for x in walk(recv)}):
                    continue
                if any(_PASSWORD.search(i) for i in _idents(c.get("args"))):
                    return True
                cid = id(c)
                for s in stmts:
                    val = s.get("init") if s.get("k") == "local" else s.get("value")
                    if cid in {id(x) for x in walk(val)}:
                        nm = s.get("name") if s.get("k") == "local" else _target_name(s.get("target"))
                        if nm and _PASSWORD.search(nm):
                            return True
        return False

    # -- CRY-003 / CRY-004 --------------------------------------------------

    def _cipher_settings(self, t, label, env, nodes) -> None:
        for n in nodes:
            k = n.get("k")
            line = n.get("line", 0)
            if k == "assign":
                tgt = n.get("target")
                if isinstance(tgt, dict) and tgt.get("k") == "member":
                    self._setting(t, label, env, (tgt.get("name") or "").lower(), tgt, n.get("value"), line)
            elif k == "new":
                ty = _simple(n.get("type_full") or n.get("type"))
                if not _CIPHER_T.match(ty):
                    continue
                for entry in n.get("init") or []:
                    nm = (entry.get("name") or "").lower()
                    if nm:
                        self._setting(t, label, env, nm, None, entry.get("value"), (entry.get("value") or {}).get("line", line))
            elif k == "call" and (call_name(n) or "").lower() in ("createencryptor", "createdecryptor"):
                args = n.get("args") or []
                if len(args) >= 2 and any(env.const_key(a) for a in args[:2]):
                    self.add("DNL-CRY-004", "high", "Constant encryption key or IV",
                             "CreateEncryptor / CreateDecryptor is given a key or IV that is a compile-time constant; "
                             "derive the key from a secret store and use a fresh random IV per message", t, label, line)

    def _setting(self, t, label, env, name, target, value, line) -> None:
        if name == "mode":
            if (isinstance(value, dict) and value.get("k") == "member" and (value.get("name") or "").lower() == "ecb"
                    and (_tail(value.get("obj")) == "ciphermode" or (value.get("sym") or "").endswith("CipherMode.ECB"))):
                self.add("DNL-CRY-003", "high", "ECB cipher mode",
                         "CipherMode.ECB encrypts equal plaintext blocks to equal ciphertext blocks and leaks "
                         "structure; use CBC with a random IV plus a MAC, or an authenticated mode", t, label, line)
        elif name in ("key", "iv") and (target is None or env.is_cipher_target(target)) and env.const_key(value):
            self.add("DNL-CRY-004", "high", "Constant encryption key or IV",
                     f"The cipher's {'key' if name == 'key' else 'IV'} is a compile-time constant (visible to anyone "
                     f"with the assembly); load keys from a secret store and generate a fresh random IV per message",
                     t, label, line)

    # -- CRY-005 ------------------------------------------------------------

    def _rand_call(self, n, env) -> bool:
        if n.get("k") != "call" or (call_name(n) or "").lower() not in _RAND_METHODS:
            return False
        if n.get("sym"):
            return n["sym"].startswith("System.Random.")
        obj = (n.get("fn") or {}).get("obj")
        if isinstance(obj, dict) and obj.get("k") == "new":
            return _simple(obj.get("type_full") or obj.get("type")) == "random"
        return env.names.get(_tail(obj)) == "random"

    def _random(self, t, label, env, nodes) -> None:
        rc = {id(n) for n in nodes if self._rand_call(n, env)}
        if not rc:
            return
        derived: set[str] = set()

        def has(expr) -> bool:
            return any(id(x) in rc or (x.get("k") == "name" and (x.get("id") or "").lower() in derived)
                       for x in walk(expr))

        def derive(name: str | None, line: int) -> None:
            nm = (name or "").lower()
            if not nm or nm in derived:
                return
            derived.add(nm)
            if _SECRET_NAME.search(nm):
                self._rand_site(t, label, f"'{name}'", line)

        for _ in range(3):
            for n in nodes:
                k = n.get("k")
                line = n.get("line", 0)
                if k == "local" and n.get("init") is not None and has(n["init"]):
                    derive(n.get("name"), line)
                elif k == "assign" and has(n.get("value")):
                    derive(_target_name(n.get("target")), line)
                elif k == "call":
                    name = (call_name(n) or "").lower()
                    args = n.get("args") or []
                    if id(n) in rc and name == "nextbytes" and args:
                        derive(_tail(args[0]), line)
                    elif name in _ACCUMULATORS and has(args):
                        derive(_tail((n.get("fn") or {}).get("obj")), line)
                elif k == "return" and has(n.get("value")) and _SECRET_NAME.search(label):
                    self._rand_site(t, label, f"the return value of '{label}'", line)
                elif k == "new":
                    for entry in n.get("init") or []:
                        nm = entry.get("name") or ""
                        if _SECRET_NAME.search(nm) and has(entry.get("value")):
                            self._rand_site(t, label, f"'{nm}'", (entry.get("value") or {}).get("line", line))

    def _rand_site(self, t, label, what, line) -> None:
        self.add("DNL-CRY-005", "medium", "Predictable random number generator for a secret",
                 f"System.Random is not cryptographically secure and feeds {what}; use "
                 f"RandomNumberGenerator / RNGCryptoServiceProvider if this value must be unguessable",
                 t, label, line, confidence="REVIEW")

    # -- CRY-006 / CRY-007 --------------------------------------------------

    def _method_returns_true(self, t: TypeIR, name: str) -> bool:
        owners = [t] + [bt for b in self.model.base_chain(t) for bt in self.model.find_types(b.split(".")[-1])]
        for ot in owners:
            ms = [m for m in ot.methods if m.name.lower() == name.lower()]
            if ms:
                return all(_all_true(m.body) for m in ms)
        return False

    def _accepts_all(self, t: TypeIR, e, depth: int = 0) -> bool:
        """Is this callback value one that returns literal true on every path?"""
        if not isinstance(e, dict) or depth > 3:
            return False
        k = e.get("k")
        if _is_true(e):
            return True
        if k == "cast":
            return self._accepts_all(t, e.get("e"), depth + 1)
        if k == "lambda":
            body = e.get("body")
            return _is_true(body) if isinstance(body, dict) else _all_true(body)
        if k == "new":
            args = e.get("args") or []
            return bool(args) and self._accepts_all(t, args[0], depth + 1)
        if k == "name":
            return self._method_returns_true(t, e.get("id") or "")
        if k == "member":
            if (e.get("name") or "").lower() == "dangerousacceptanyservercertificatevalidator":
                return True
            if _tail(e.get("obj")) in ("this", "me", "base", "mybase") or e.get("obj") is None:
                return self._method_returns_true(t, e.get("name") or "")
        return False

    def _policy_accepts_all(self, e) -> bool:
        if isinstance(e, dict) and e.get("k") == "cast":
            e = e.get("e")
        if not isinstance(e, dict) or e.get("k") != "new":
            return False
        for pt in self.model.find_types(_simple(e.get("type_full") or e.get("type"))):
            ms = [m for m in pt.methods if m.name.lower() == "checkvalidationresult"]
            if ms and all(_all_true(m.body) for m in ms):
                return True
        return False

    def _tls(self, t, label, env, nodes) -> None:
        for n in nodes:
            k = n.get("k")
            line = n.get("line", 0)
            pairs: list[tuple[str, dict | None, int]] = []
            if k == "assign" and isinstance(n.get("target"), dict) and n["target"].get("k") == "member":
                pairs.append(((n["target"].get("name") or "").lower(), n.get("value"), line))
            elif k == "new":
                for entry in n.get("init") or []:
                    if entry.get("name"):
                        pairs.append((entry["name"].lower(), entry.get("value"), (entry.get("value") or {}).get("line", line)))
            for name, value, ln in pairs:
                if name in _CERT_CALLBACKS and self._accepts_all(t, value):
                    self.add("DNL-CRY-006", "high", "TLS certificate validation disabled",
                             "The certificate validation callback returns true for every certificate, so any "
                             "man-in-the-middle certificate is trusted; validate the chain and policy errors "
                             "(or pin the expected certificate)", t, label, ln)
                elif name == "certificatepolicy" and self._policy_accepts_all(value):
                    self.add("DNL-CRY-006", "high", "TLS certificate validation disabled",
                             "ServicePointManager.CertificatePolicy is set to a policy whose CheckValidationResult "
                             "always returns true, so every certificate is trusted", t, label, ln)
                elif name == "securityprotocol":
                    # Only an assignment on ServicePointManager counts, and `&= ~Ssl3` (removal) does not.
                    tgt = n.get("target") if k == "assign" else None
                    if tgt is not None and "servicepointmanager" not in (receiver_text(tgt).lower() + (tgt.get("sym") or "").lower()):
                        continue
                    bad = self._old_protocols(value)
                    if bad:
                        self.add("DNL-CRY-007", "medium", "Obsolete TLS / SSL protocol enabled",
                                 f"ServicePointManager.SecurityProtocol includes {', '.join(sorted(bad))}; "
                                 f"SSL 3.0, TLS 1.0 and TLS 1.1 are deprecated, allow Tls12 (or let the OS choose)",
                                 t, label, ln)

    def _old_protocols(self, value) -> set[str]:
        out: set[str] = set()

        def visit(e) -> None:
            if isinstance(e, list):
                for x in e:
                    visit(x)
                return
            if not isinstance(e, dict):
                return
            k = e.get("k")
            if k == "unary" and e.get("op") in ("~", "Not"):
                return      # clearing a flag is hardening
            if k == "member":
                nm = (e.get("name") or "").lower()
                if nm in _OLD_PROTOCOLS and _tail(e.get("obj")) in ("securityprotocoltype", "servicepointmanager", ""):
                    out.add({"ssl3": "Ssl3", "tls": "Tls", "tls11": "Tls11"}[nm])
            elif k == "lit" and isinstance(e.get("v"), int) and not isinstance(e.get("v"), bool):
                if e["v"] & _OLD_PROTOCOL_BITS:
                    out.add(f"legacy protocol bits ({e['v']})")
            for key, v in e.items():
                if key != "k" and isinstance(v, (dict, list)):
                    visit(v)

        visit(value)
        return out

    # -- CRY-008 ------------------------------------------------------------

    def _kdf(self, t, label, env, nodes) -> None:
        for n in nodes:
            if n.get("k") != "new":
                continue
            ty = _simple(n.get("type_full") or n.get("type"))
            line = n.get("line", 0)
            if ty == "passwordderivebytes" and _in_crypto_ns(n.get("type_full")):
                self.add("DNL-CRY-008", "medium", "PasswordDeriveBytes (PBKDF1)",
                         "PasswordDeriveBytes implements the obsolete PBKDF1 with a weak extension; use "
                         "Rfc2898DeriveBytes with at least 10000 iterations (100000+ with SHA-256)", t, label, line)
            elif ty == "rfc2898derivebytes" and _in_crypto_ns(n.get("type_full")):
                args = n.get("args") or []
                named = {k.lower(): v for k, v in (n.get("named") or {}).items()}
                it = named.get("iterations", args[2] if len(args) >= 3 else None)
                if it is None:
                    self.add("DNL-CRY-008", "medium", "Low PBKDF2 iteration count",
                             "Rfc2898DeriveBytes without an iteration count uses 1000 iterations; pass at least "
                             "10000 (100000+ with SHA-256)", t, label, line)
                    continue
                iv = env.const_int(it)
                if iv is not None and iv < 10000:
                    self.add("DNL-CRY-008", "medium", "Low PBKDF2 iteration count",
                             f"Rfc2898DeriveBytes runs {iv} iterations; use at least 10000 (100000+ with SHA-256)",
                             t, label, line)

    # -- SEC-003 ------------------------------------------------------------

    def _secret_pair(self, t, where, name, value, line) -> None:
        val = const_str(value)
        if val is None or len(val) < 4 or not name:
            return
        text = val.strip()
        if _PLACEHOLDER.match(text) or _BRACE_INDEX.match(text):
            return
        if not _SECRET_KEY.search(name) or _is_setting_key(name):
            return
        # `PasswordKey = "Password"`: the literal just names the thing -- it equals the name minus
        # a common suffix. A literal equal to the whole name (`password = "password"`) or a substring
        # (`adminPassword = "admin"`) is a real weak credential and fires.
        norm_v, norm_n = _STR_NORMAL.sub("", text.lower()), _STR_NORMAL.sub("", name.lower())
        if norm_v and any(norm_n.endswith(sfx) and norm_n[: -len(sfx)] == norm_v for sfx in _NAME_SUFFIXES):
            return
        self.add("DNL-SEC-003", "high", "Hardcoded credential in code",
                 f"'{name}' is assigned a string literal; credentials in source end up in every build, repository "
                 f"clone and decompiled assembly. Read the secret from protected configuration or a vault",
                 t, where, line)

    def _secret_conn(self, t, where, value, line, what) -> None:
        s = const_str(value)
        if s is None:
            return
        m = _CONN_PW.search(s)
        if m and not _PLACEHOLDER.match(m.group(2).strip()) and not _BRACE_INDEX.match(m.group(2).strip()):
            self.add("DNL-SEC-003", "high", "Hardcoded credential in code",
                     f"{what} embeds a database password in a string literal; read the connection string from "
                     f"protected configuration or use integrated security", t, where, line)

    def _secrets(self, t, where, env, nodes) -> None:
        for n in nodes:
            k = n.get("k")
            line = n.get("line", 0)
            if k == "local" and n.get("init") is not None:
                self._secret_pair(t, where, n.get("name") or "", n["init"], line)
            elif k == "assign" and n.get("op") == "=":
                nm = _target_name(n.get("target"))
                self._secret_pair(t, where, nm, n.get("value"), line)
                if nm == "connectionstring":
                    self._secret_conn(t, where, n.get("value"), line, "ConnectionString")
            elif k in ("call", "new"):
                for nm, v in (n.get("named") or {}).items():
                    self._secret_pair(t, where, nm, v, (v or {}).get("line", line))
                if k == "new":
                    ty = _simple(n.get("type_full") or n.get("type"))
                    args = n.get("args") or []
                    for entry in n.get("init") or []:
                        if entry.get("name"):
                            self._secret_pair(t, where, entry["name"], entry.get("value"),
                                              (entry.get("value") or {}).get("line", line))
                    idx = _CRED_CTORS.get(ty)
                    if idx is not None and len(args) > idx:
                        v = const_str(args[idx])
                        if v is not None and len(v) >= 4 and not _PLACEHOLDER.match(v.strip()) and not _BRACE_INDEX.match(v.strip()):
                            self.add("DNL-SEC-003", "high", "Hardcoded credential in code",
                                     f"The password passed to {n.get('type') or ty} is a string literal; read it "
                                     f"from protected configuration or a vault", t, where, line)
                    elif _CONNECTION_T.search(ty) and args:
                        self._secret_conn(t, where, args[0], line, f"The {n.get('type') or ty} connection string")


def check(model: ProjectModel, refs=()) -> list[Finding]:
    """CRY-001..008 and SEC-003 findings over every type of the model. `refs` (RouteRefs)
    only decide which findings carry a route."""
    if not model.files:
        return []
    return _Scan(model, refs).run()
