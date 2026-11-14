"""Logging rules: DNL-LOG-002 (no logging framework configured), DNL-LOG-003 (a secret passed to a log
sink) and DNL-LOG-004 (a login failure branch that logs nothing).

LOG-002 is a scan-level fact read from project references, packages, config files and `using` lines;
it needs no IR. LOG-003 and LOG-004 read the IR.

A "log call" is a call named like a log level on something that is a logger: a resolved
log4net / NLog / Serilog / EntLib / Common.Logging / System.Diagnostics symbol, a field / local /
parameter declared as a logger type or initialised from `GetLogger(..)`, a receiver named like one
(`log`, `_logger`, `Trace`), or a `LogError(..)`-style helper. LOG-004 only counts a log call that
sits directly on the rejecting branch, or in a project method that branch calls and that itself
logs; a log call before the `if`, or under a nested condition, does not.

LOG-003 follows a secret-named value (the SEC key pattern, minus names of settings about a secret)
through locals into the sink argument, also inside string concatenation, interpolation and
String.Format. Reading only `.Length` / `.Count` of a secret is not logging it.
"""
from __future__ import annotations

import re

from checks.dnl.files import iter_dnl_files, read_source
from checks.dnl.findings import dnl_finding
from checks.dnl.flowutil import Ctx, all_lists, login_by_context, own_level, stmt_exprs, terminates, tokens, uncond_nodes
from checks.dnl.ir import call_name, receiver_text, walk
from checks.dnl.rules_config import _SECRET_KEY, _is_setting_key
from checks.dnl.typestate import iter_bodies, simple
from core.models import Finding

# -- LOG-002 --------------------------------------------------------------------

_PKG = (r"log4net|nlog|serilog|elmah|enterpriselibrary\.logging|entlib|common\.logging|microsoft\.extensions\.logging"
        r"|loggly|exceptionless|raygun4net|applicationinsights|sentry|castle\.loggingfacility|seq\.")
_PKG_RE = re.compile(rf"(?i)(?<![a-z0-9]){_PKG}")
_XML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_CONFIG_RE = re.compile(r"(?i)<\s*(log4net|nlog|loggingConfiguration|elmah|serilog)\b|log4net\.Config\.|"
                        r"<\s*(sources|sharedListeners)\b|<\s*listeners\s*>\s*<\s*add\b|Elmah\.ErrorLog")
_USING_RE = re.compile(r"(?im)^\s*(using|imports)\s+(static\s+)?(log4net|nlog|serilog|elmah|"
                       r"microsoft\.practices\.enterpriselibrary\.logging|common\.logging|"
                       r"microsoft\.extensions\.logging)\b|\bnew\s+(System\.Diagnostics\.)?TraceSource\b"
                       r"|\bLoggerConfiguration\b|\bLogManager\.GetLogger\b")


def logging_evidence(model) -> str | None:
    """What shows a logging framework in the scan (first hit), else None."""
    for p in model.projects:
        for ref in p.references:
            if _PKG_RE.match(ref):
                return f"reference {ref}"
    for f in iter_dnl_files(model.root, (".csproj", ".vbproj", ".config", ".json", ".cs", ".vb")):
        suffix = f.suffix.lower()
        if suffix == ".json" and not f.name.lower().startswith(("appsettings", "serilog", "nlog")):
            continue
        try:
            text = read_source(f)
        except OSError:
            continue
        rel = model.rel(f)
        if suffix in (".csproj", ".vbproj"):
            if re.search(rf"(?i)(packages[\\/]|Include=\"){_PKG}", text):
                return f"{rel} references a logging package"
        elif suffix == ".config":
            if f.name.lower() == "packages.config":
                if re.search(rf'(?i)id="{_PKG}', text):
                    return f"{rel} lists a logging package"
            elif _CONFIG_RE.search(_XML_COMMENT.sub("", text)):
                return f"{rel} configures logging"
        elif suffix == ".json":
            if re.search(r'(?i)"(serilog|nlog|logging)"\s*:', text):
                return f"{rel} configures logging"
        elif _USING_RE.search(text):
            return f"{rel} uses a logging framework"
    return None


def _anchor(model) -> str | None:
    """Rel path of the first legacy project file (the finding's anchor)."""
    legacy = sorted(model.rel(p.path) for p in model.projects if p.path is not None and p.is_legacy)
    return legacy[0] if legacy else None


def check_log002(model) -> list[Finding]:
    anchor = _anchor(model)
    if anchor is None or logging_evidence(model) is not None:
        return []
    return [dnl_finding(
        "DNL-LOG-002", "low", "No logging framework configured",
        "No log4net, NLog, Serilog, Enterprise Library, ELMAH, Common.Logging or TraceSource configuration, "
        "package, reference or `using` was found anywhere in the scan, so security events (failed logins, "
        "access denials, errors) are probably not recorded. Confirm logging is provided some other way "
        f"({anchor}).", anchor, 1, confidence="REVIEW")]


# -- log-call recognition ---------------------------------------------------------

_LEVELS = {"debug", "info", "information", "warn", "warning", "error", "fatal", "critical", "trace", "verbose",
           "log", "write", "writeline", "writeif", "writelineif", "tracewarning", "traceerror",
           "traceinformation", "traceevent", "tracedata", "debugformat", "infoformat", "warnformat",
           "errorformat", "fatalformat", "logexception", "audit", "writeentry"}
_HELPER = re.compile(r"(?i)^log(info|information|error|warn|warning|debug|fatal|message|exception|event|trace|"
                     r"critical|failure|audit)$")
_LOG_SYM = re.compile(r"^(log4net\.|NLog\.|Serilog\.|Microsoft\.Practices\.EnterpriseLibrary\.Logging\.|"
                      r"Common\.Logging\.|Microsoft\.Extensions\.Logging\.|Elmah\.|"
                      r"System\.Diagnostics\.(Trace|Debug|TraceSource|TraceListener|EventLog)\.)")
_LOGGER_TYPES = {"ilog", "ilogger", "logger", "tracesource", "logwriter", "iloggerfactory", "loggerwrapper", "ilogwriter"}
_LOGGER_INIT = {"getlogger", "getcurrentclasslogger", "createlogger", "forcontext", "getlog"}
_RECV_NAME = re.compile(r"(?i)^_?(m_)?(log|logger|logging|trace|debug|audit\w*|eventlog\w*|\w+logger|\w+log)$")


def logger_names(model) -> set[str]:
    """Lowered names of fields, properties, parameters and locals that hold a logger, over the solution."""
    cached = model.cache.get("dnl_logger_names")
    if cached is not None:
        return cached
    out: set[str] = set()

    def init_logger(e) -> bool:
        return any(isinstance(n, dict) and n.get("k") == "call" and (call_name(n) or "").lower() in _LOGGER_INIT
                   for n in walk(e))

    for t in model.types():
        for f in list(t.fields) + list(t.properties):
            if simple(f.type) in _LOGGER_TYPES or (getattr(f, "init", None) is not None and init_logger(f.init)):
                out.add(f.name.lower())
        for m in t.methods:
            for p in m.params:
                if simple(p.type) in _LOGGER_TYPES:
                    out.add(p.name.lower())
            for n in walk(m.body):
                if n.get("k") == "local" and n.get("name") and (
                        simple(n.get("type_full") or n.get("type")) in _LOGGER_TYPES or init_logger(n.get("init"))):
                    out.add(n["name"].lower())
    model.cache["dnl_logger_names"] = out
    return out


def is_log_call(call: dict, names: set[str]) -> bool:
    nm = (call_name(call) or "").lower()
    fn = call.get("fn") or {}
    if not nm:
        return False
    sym = call.get("sym") or fn.get("sym")
    if sym and _LOG_SYM.match(sym):
        return nm in _LEVELS or nm.endswith("format") or bool(_HELPER.match(nm))
    if _HELPER.match(nm):
        return True
    if nm not in _LEVELS and not (nm.endswith("format") and nm[:-6] in _LEVELS):
        return False
    recv = fn.get("obj") if fn.get("k") == "member" else None
    if not isinstance(recv, dict):
        return False
    if recv.get("k") == "call":
        return (call_name(recv) or "").lower() in _LOGGER_INIT
    text = receiver_text(recv).lower()
    last = text.split(".")[-1]
    return last in names or text.split(".")[0] in names or bool(_RECV_NAME.match(last))


# -- LOG-003 ----------------------------------------------------------------------

_SECRET_TOKENS = {"pw", "passwd"}
_STRING_OPS = {"format", "concat", "join", "tostring", "trim", "trimstart", "trimend", "substring", "replace",
               "tolower", "toupper", "tolowerinvariant", "toupperinvariant", "padleft", "padright", "insert",
               "append", "appendformat", "appendline", "remove", "split", "normalize", "getbytes", "tochararray"}
_REQUEST_ROOT = re.compile(r"(?i)(^|\.)(request|form|params|querystring|cookies|headers|item)$")


def _is_secret(ident: str) -> bool:
    """SEC key pattern (minus setting names), plus `pw` / `passwd` as a whole identifier segment (so
    `userPw` matches and `pwrSupply` does not). The shared SEC pattern is not changed."""
    if not ident:
        return False
    if _SECRET_KEY.search(ident) and not _is_setting_key(ident):
        return True
    return bool(_SECRET_TOKENS & set(tokens(ident)))


def _key_secret(e) -> str | None:
    """`Request.Form["Password"]` / `Request["Password"]` / VB `Request.Form("pwd")`: a literal key that
    names a secret."""
    if not isinstance(e, dict):
        return None
    k = e.get("k")
    if k == "index":
        recv, args = receiver_text(e.get("obj")), e.get("args") or []
    elif k == "call":
        fn = e.get("fn") or {}
        recv, args = receiver_text(fn) if fn.get("k") in ("name", "member") else "", e.get("args") or []
    else:
        return None
    if _REQUEST_ROOT.search(recv) and "request" in recv.lower() and args and isinstance(args[0], dict) \
            and isinstance(args[0].get("v"), str) and _is_secret(args[0]["v"]):
        return args[0]["v"]
    return None


def _secret_in(e, aliases: set[str], via_calls: bool = True) -> str | None:
    """The first secret-named identifier an expression reads as a value, else None. With `via_calls`
    False a call's arguments count only for string building (`Format`, `Concat`, `ToString` ...): the
    result of `repo.Login(email, pwd)` is not the password."""
    if isinstance(e, list):
        for x in e:
            r = _secret_in(x, aliases, via_calls)
            if r:
                return r
        return None
    if not isinstance(e, dict):
        return None
    k = e.get("k")
    if k == "lit" or k == "lambda":
        return None
    keyed = _key_secret(e)
    if keyed:
        return keyed
    if k == "name":
        nm = e.get("id") or ""
        return nm if nm.lower() in aliases or _is_secret(nm) else None
    if k == "member":
        nm = e.get("name") or ""
        if nm.lower() in ("length", "count"):
            return None
        if _is_secret(nm) or nm.lower() in aliases and e.get("obj") is None:
            return nm
        return _secret_in(e.get("obj"), aliases, via_calls)
    if k == "call" and not via_calls and (call_name(e) or "").lower() not in _STRING_OPS:
        fn = e.get("fn") or {}
        return _secret_in(fn.get("obj"), aliases, via_calls) if fn.get("k") == "member" else None
    return next((r for v in e.values() if isinstance(v, (dict, list)) for r in [_secret_in(v, aliases, via_calls)] if r), None)


def _aliases(body) -> set[str]:
    """Locals that hold a secret-named value (`var pw = model.Password;`), to a fixpoint."""
    out: set[str] = set()
    nodes = [n for n in walk(body) if n.get("k") in ("local", "assign")]
    for _ in range(len(nodes) + 1):
        before = len(out)
        for n in nodes:
            if n["k"] == "local":
                tgt, val = n.get("name"), n.get("init")
            else:
                t = n.get("target") or {}
                tgt, val = (t.get("id") if t.get("k") == "name" else None), n.get("value")
            if tgt and val is not None and tgt.lower() not in out and _secret_in(val, out, via_calls=False):
                out.add(tgt.lower())
        if len(out) == before:
            break
    return out


def check_log003(ctx: Ctx) -> list[Finding]:
    names = logger_names(ctx.model)
    out: list[Finding] = []
    seen: set = set()
    for t in ctx.model.types():
        if t.kind == "enum":
            continue
        for label, _m, body, _scope in iter_bodies(t):
            aliases = None
            for n in walk(body):
                if n.get("k") != "call" or not is_log_call(n, names):
                    continue
                if aliases is None:
                    aliases = _aliases(body)
                what = _secret_in([n.get("args"), list((n.get("named") or {}).values())], aliases)
                key = (t.file, n.get("line"))
                if what and key not in seen:
                    seen.add(key)
                    out.append(ctx.finding(
                        t, label, "DNL-LOG-003", "medium", "Password or secret written to the log",
                        f"The value '{what}' is passed to a log call ({call_name(n)}), so the secret ends up in "
                        "log files and any log aggregator in clear text", n.get("line") or 0))
    return out


# -- LOG-004 ----------------------------------------------------------------------

_LOGIN_TOKENS = {"login", "logon", "signin", "authenticate", "authenticated"}
_NOT_LOGIN = {"logout", "logoff", "signout", "status", "name", "view", "model", "page", "control", "help"}
_FAIL_HANDLER = ({"login", "error"}, {"login", "failed"}, {"authentication", "failed"}, {"logon", "error"},
                 {"login", "failure"})
_FAIL_WORDS = re.compile(r"(?i)\b(invalid|incorrect|wrong|failed|failure|denied|locked|unsuccessful|"
                         r"not (valid|correct|recogni[sz]ed)|bad (user|login|password|credential))")
_REJECT_CALLS = {"addmodelerror", "unauthorized", "forbid", "challenge", "seterror", "rejected"}
_REJECT_NEW = {"httpunauthorizedresult", "unauthorizedresult", "forbidresult", "challengeresult"}
_REJECT_MEMBERS = {"failuretext", "errormessage"}
_RESPONSE_CALLS = {"createresponse", "createerrorresponse"}
_FLAG_KEYS = {"success", "ok", "succeeded", "authenticated", "isvalid", "valid", "status", "result", "loggedin"}
_STATE_ROOTS = {"tempdata", "viewbag", "viewdata"}
_CRED_NAMES = {"validateuser", "passwordsignin", "passwordsigninasync", "checkpassword", "checkpasswordasync",
               "checkpasswordsigninasync", "verifypassword", "logonuser", "trylogin", "trysignin"}
_CRED_PREFIX = re.compile(r"(?i)^(authenticate|validatecredential|validatelogin|validatepassword|verifycredential)")
_OUTCOMES = {"success": "ok", "failure": "bad", "lockedout": "bad", "requiresverification": "bad"}


def is_login_name(name: str) -> bool:
    if not name or name in (".ctor", ".cctor") or name.lower().startswith(("get_", "set_")):
        return False
    tk = tokens(name)
    if not tk or set(tk) & _NOT_LOGIN:
        return False
    if set(tk) & _LOGIN_TOKENS:
        return True
    return any(a == "log" and b in ("in", "on") or a == "sign" and b == "in" for a, b in zip(tk, tk[1:]))


def _is_fail_handler(name: str) -> bool:
    tk = set(tokens(name))
    return any(req <= tk for req in _FAIL_HANDLER)


def is_cred_call(n: dict) -> bool:
    """A call that checks a credential: ValidateUser, PasswordSignIn(Async), CheckPassword(Async),
    `Find(user, password)`, Authenticate* / Validate*Credential*."""
    if n.get("k") != "call":
        return False
    nm = (call_name(n) or "").lower()
    if nm in _CRED_NAMES or _CRED_PREFIX.match(nm):
        return True
    return nm in ("find", "findasync") and len(n.get("args") or []) >= 2


def _cred_locals(body) -> set:
    """Locals assigned from a credential check (`var user = await UserManager.FindAsync(u, p)`)."""
    out: set = set()
    for n in walk(body):
        if n.get("k") == "local" and n.get("name") and n.get("init") is not None \
                and any(is_cred_call(x) for x in walk(n["init"])):
            out.add(n["name"].lower())
        elif n.get("k") == "assign" and (n.get("target") or {}).get("k") == "name" \
                and any(is_cred_call(x) for x in walk(n.get("value"))):
            out.add((n["target"].get("id") or "").lower())
    return out


def _root_name(e) -> str:
    while isinstance(e, dict) and e.get("k") in ("member", "index", "cast"):
        e = e.get("obj") if e.get("k") != "cast" else e.get("e")
    return (e.get("id") or "").lower() if isinstance(e, dict) and e.get("k") == "name" else ""


def _failing_branch(cond, locs: set, chk=None) -> str | None:
    """"then" / "else": the branch of `if (cond)` that runs when the credential check FAILED, else None."""
    flip = False
    while isinstance(cond, dict) and cond.get("k") == "unary" and cond.get("op") in ("!", "Not", "not"):
        cond, flip = cond.get("e"), not flip
    base = _failing_leaf(cond, locs, chk)
    if base is None:
        return None
    return ("else" if base == "then" else "then") if flip else base


def _failing_leaf(c, locs: set, chk=None) -> str | None:
    chk = chk or is_cred_call
    if not isinstance(c, dict):
        return None
    k = c.get("k")
    if k == "bin":
        op = str(c.get("op") or "").lower()
        l, r = c.get("l"), c.get("r")
        # `A || B` takes `then` whenever an operand that fails into `then` fails (`!check || x`);
        # `A && B` takes `else` whenever an operand that fails into `else` fails (`check && x`).
        # Any other shape does not route every failure to one branch, so it is no gate.
        if op in ("||", "orelse", "or"):
            return "then" if any(_failing_branch(x, locs, chk) == "then" for x in (l, r)) else None
        if op in ("&&", "andalso", "and"):
            return "else" if any(_failing_branch(x, locs, chk) == "else" for x in (l, r)) else None
        sides = [x for x in (l, r) if isinstance(x, dict)]
        for me, other in ((l, r), (r, l)):
            if not isinstance(me, dict):
                continue
            checked = chk(me) or _root_name(me) in locs
            if not checked:
                continue
            if isinstance(other, dict) and other.get("k") == "lit":
                if other.get("v") is None:                                   # user == null
                    return "then" if op in ("==", "=", "is") else "else" if op in ("!=", "<>", "isnot") else None
                if isinstance(other.get("v"), bool):                         # check == false
                    want = other["v"] if op in ("==", "=") else (not other["v"] if op in ("!=", "<>") else None)
                    return None if want is None else ("else" if want else "then")
            if isinstance(other, dict) and other.get("k") == "name" and (other.get("id") or "").lower() in ("null", "nothing"):
                return "then" if op in ("==", "=", "is") else "else" if op in ("!=", "<>", "isnot") else None
        for x in sides:                                                     # result == SignInStatus.Failure
            nm = (x.get("name") or "").lower() if x.get("k") == "member" else ""
            if nm in _OUTCOMES:
                eq = op in ("==", "=")
                ne = op in ("!=", "<>")
                if not (eq or ne):
                    return None
                good = _OUTCOMES[nm] == "ok"
                return "else" if (eq == good) else "then"
        return None
    if chk(c) or _root_name(c) in locs and k in ("name", "member", "call"):
        return "else"                                                        # truthy = success
    return None


def _reject_marker(n: dict) -> bool:
    k = n.get("k")
    if k == "call":
        nm = (call_name(n) or "").lower()
        args = n.get("args") or []
        if nm in _REJECT_CALLS:
            return True
        if nm == "httpstatuscoderesult" and any(isinstance(a, dict) and a.get("v") in (401, 403) for a in args):
            return True
        if nm in _RESPONSE_CALLS and any(x.get("k") == "member" and (x.get("name") or "").lower() in
                                         ("unauthorized", "forbidden") for a in args for x in walk(a)):
            return True
        if nm.startswith("redirect") and any(isinstance(a, dict) and a.get("k") == "lit" and isinstance(a.get("v"), str)
                                             and re.search(r"(?i)log_?(in|on)", a["v"]) for a in args):
            return True
        return any(isinstance(a, dict) and a.get("k") == "lit" and isinstance(a.get("v"), str)
                   and _FAIL_WORDS.search(a["v"]) for a in args)
    if k == "new":
        ty = simple(n.get("type"))
        if ty in _REJECT_NEW or (ty == "httpstatuscoderesult"
                                 and any(isinstance(a, dict) and a.get("v") in (401, 403) for a in n.get("args") or [])):
            return True
        for it in n.get("init") or []:                                      # Json(new { success = false })
            v = it.get("value") if isinstance(it, dict) else None
            if isinstance(it, dict) and str(it.get("name") or "").lower() in _FLAG_KEYS \
                    and isinstance(v, dict) and v.get("k") == "lit" and v.get("v") is False:
                return True
    return False


def _rejects(stmts, failing: bool = False) -> int | None:
    """Line of the first statement at this branch's own level that rejects credentials. In a branch known to
    run on a failed check (`failing`) any statement is the rejection."""
    for s in own_level(stmts):
        if failing and s.get("k") in ("expr", "return", "assign", "local", "throw"):
            return s.get("line") or 0
        for n in stmt_exprs(s):
            if _reject_marker(n):
                return s.get("line") or n.get("line") or 0
        if s.get("k") == "assign":
            tgt, val = s.get("target") or {}, s.get("value")
            name = (tgt.get("name") or tgt.get("id") or "").lower() if isinstance(tgt, dict) else ""
            lit = val.get("v") if isinstance(val, dict) and val.get("k") == "lit" else None
            if name in _REJECT_MEMBERS or (name == "authenticated" and lit is False):
                return s.get("line") or 0
            if isinstance(lit, str) and _FAIL_WORDS.search(lit) and name in ("message", "text", "statusmessage", "error"):
                return s.get("line") or 0
            if name == "statuscode" and isinstance(val, dict) and val.get("v") in (401, 403):
                return s.get("line") or 0
            # TempData["err"] = .. / ViewBag.Error = ..
            if _root_name(tgt) in _STATE_ROOTS:
                key = ""
                if tgt.get("k") == "index" and tgt.get("args") and isinstance(tgt["args"][0], dict):
                    key = str(tgt["args"][0].get("v") or "")
                elif tgt.get("k") == "member":
                    key = tgt.get("name") or ""
                if re.search(r"(?i)error|fail|invalid", key) or (isinstance(lit, str) and _FAIL_WORDS.search(lit)):
                    return s.get("line") or 0
    return None


def _logs(ctx: Ctx, t, m, stmts, names, depth: int = 2) -> bool:
    """A log call directly on this branch (its own level, or an unconditionally run try / using body),
    or a call to a project method that itself logs."""
    for s in own_level(stmts):
        for n in stmt_exprs(s) if s.get("k") != "if" else ():
            if n.get("k") != "call":
                continue
            if is_log_call(n, names):
                return True
            if depth > 0:
                for ty, tm in ctx.targets(t, m, n):
                    if any(c.get("k") == "call" and is_log_call(c, names) for c in uncond_nodes(tm.body)) \
                            or (depth > 1 and _logs(ctx, ty, tm, tm.body, names, depth - 1)):
                        return True
    return False


def _any_log(ctx: Ctx, t, m, names) -> bool:
    """A log call anywhere in the method, or in a project method it calls."""
    for n in walk(m.body):
        if n.get("k") == "call":
            if is_log_call(n, names):
                return True
            for _ty, tm in ctx.targets(t, m, n):
                if any(c.get("k") == "call" and is_log_call(c, names) for c in walk(tm.body)):
                    return True
    return False


def _candidates(body, locs: set):
    """(statements, kind, failing) of every branch that might be the credential-rejecting one: then / else
    lists, and the tail after an `if` whose then-branch ends the flow (the success path). `failing` is True
    when the `if` condition is a credential check and this branch runs when it failed."""
    for lst in all_lists(body):
        for i, s in enumerate(lst):
            if not isinstance(s, dict) or s.get("k") != "if":
                continue
            fb = _failing_branch(s.get("cond"), locs)
            if s.get("then"):
                yield s["then"], "then", fb == "then"
            if s.get("else"):
                yield s["else"], "else", fb == "else"
            if s.get("then") and terminates(s["then"]) and i + 1 < len(lst):
                yield lst[i + 1:], "tail", fb == "else"


def _has_cred_check(m) -> bool:
    for n in walk(m.body):
        if is_cred_call(n):
            return True
        if n.get("k") == "assign" and (n.get("target") or {}).get("k") == "member" \
                and (n["target"].get("name") or "").lower() == "authenticated":
            return True
    return False


def check_log004(ctx: Ctx) -> list[Finding]:
    names = logger_names(ctx.model)
    out: list[Finding] = []
    text = ("The branch of this login handler that rejects the credentials has no log call, so a failed "
            "sign-in leaves no trace for detecting guessing or credential stuffing (a log call before "
            "the check, or under another condition, does not count)")
    for t in ctx.model.types():
        if t.kind in ("enum", "interface"):
            continue
        for m in t.methods:
            if not m.body:
                continue
            fail_handler = _is_fail_handler(m.name)
            login = fail_handler or is_login_name(m.name) or login_by_context(t, m)
            if not login:
                continue
            seen_lines: set = set()
            cands = [(m.body, "handler", True)] if fail_handler else list(_candidates(m.body, _cred_locals(m.body)))
            emitted = 0
            for stmts, kind, failing in cands:
                line = (m.line or 0) if kind == "handler" else _rejects(stmts, failing)
                if not line or line in seen_lines or _logs(ctx, t, m, stmts, names):
                    continue
                seen_lines.add(line)
                emitted += 1
                out.append(ctx.finding(t, m.name, "DNL-LOG-004", "low", "Failed login is not logged", text, line,
                                       confidence="REVIEW"))
            # Fallback: a login handler that checks credentials and logs nothing anywhere has no logged failure path.
            if not emitted and not fail_handler and _has_cred_check(m) and not _any_log(ctx, t, m, names):
                out.append(ctx.finding(
                    t, m.name, "DNL-LOG-004", "low", "Failed login is not logged",
                    "This login handler checks credentials but contains no log call (and calls no method that logs), "
                    "so no failure path records the failed sign-in", m.line or 0, confidence="REVIEW"))
    return out


def check(model, refs=()) -> list[Finding]:
    ctx = Ctx(model, refs)
    return check_log002(model) + check_log003(ctx) + check_log004(ctx)
