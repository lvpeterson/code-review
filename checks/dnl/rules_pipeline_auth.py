"""Authentication-related ASP.NET Core configuration rules, called from the rules_pipeline aggregator.

Groups: cookies and session (DNL-SESS-001/002/003 reused, DNL-SESS-009) and antiforgery (DNL-CSRF-001
reused, DNL-CSRF-002). Later tasks add token validation and Identity groups to this module.

Like the other rules_pipeline* modules it must not import rules_auth_core (static inventory test);
shared helpers live in auth_core.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from checks.dnl.auth_core import _NON_AUTHZ_EXTENSIONS
from checks.dnl.cfgctx import Ctx
from checks.dnl.ir import attr_key, call_name, receiver_text
from checks.dnl.options import (Opt, const, lambda_args, opaque_reason, options_of, timespan_minutes, verdict,
                                walk_conditional)
from checks.dnl.pipeline import PipeCall, Pipeline
from checks.dnl.routes_core import CoreRouteRef, _chain_types

# -- cookies and session (DNL-SESS-001, DNL-SESS-002, DNL-SESS-003, DNL-SESS-009) ---------------------

# Calls whose options carry cookie settings; `Configure<T>` counts only for the option types below.
_COOKIE_CALLS = ("AddCookie", "ConfigureApplicationCookie", "ConfigureExternalCookie", "AddSession",
                 "AddAntiforgery", "UseCookiePolicy", "Configure")
_COOKIE_OPTION_TYPES = ("CookiePolicyOptions", "CookieAuthenticationOptions", "SessionOptions",
                        "AntiforgeryOptions")
_MAX_MINUTES = 1440            # one day: a longer fixed or sliding lifetime is a finding

_SECURE_BAD = ("CookieSecurePolicy.None", "CookieSecurePolicy.SameAsRequest")
_SECURE_GOOD = ("CookieSecurePolicy.Always",)
_HTTPONLY_BAD = ("HttpOnlyPolicy.None",)
_HTTPONLY_GOOD = ("HttpOnlyPolicy.Always",)


def _leaf(path: str) -> tuple[str, str]:
    """(parent segment, last segment), lower-cased: ("cookie", "securepolicy") for `Cookie.SecurePolicy`."""
    parts = path.lower().split(".")
    return (parts[-2] if len(parts) > 1 else ""), parts[-1]


def _paths(opts: list[Opt], leaves: tuple[str, ...], *, bare: bool = True) -> list[str]:
    """Distinct (lower-cased) option paths that name one of the cookie settings: a bare name (the
    initializer of a CookieBuilder / CookiePolicyOptions), or one under a `...Cookie` member."""
    out = []
    for o in opts:
        parent, leaf = _leaf(o.path)
        if leaf in leaves and ((bare and not parent) or parent.endswith("cookie")):
            out.append(o.path.lower())
    return list(dict.fromkeys(out))


def _kind(o: Opt, bad: tuple, good: tuple, *, bool_bad: bool | None = None) -> str:
    """"bad" | "good" | "unknown" for an assigned value. Only the known-bad and known-good members count;
    anything else (a variable, a call, an enum member this rule does not know) is unknown, never good."""
    v = const(o.value)
    if bool_bad is not None and isinstance(v, bool):
        return "bad" if v is bool_bad else "good"
    if isinstance(v, str) and v in bad:
        return "bad"
    if isinstance(v, str) and v in good:
        return "good"
    return "unknown"


def _opaque_cookies(opts: list[Opt]) -> list[Opt]:
    """`o.Cookie = <something that is not a new CookieBuilder>`: the whole builder comes from elsewhere."""
    out = []
    for o in opts:
        if _leaf(o.path)[1] == "cookie" and isinstance(o.value, dict) and o.value.get("k") != "new":
            out.append(o)
    return out


def _cookie_calls(ctx: Ctx, pipe: Pipeline) -> list[tuple[PipeCall, str | None]]:
    """[(call, confidence)] of cookie-carrying calls: firm when they certainly run in Production, REVIEW
    under an environment condition that could not be parsed."""
    def wanted(c: PipeCall) -> bool:
        if c.name != "Configure":
            return True
        targs = (c.node.get("fn") or {}).get("targs") or []
        return any(str(x).strip().split(".")[-1] in _COOKIE_OPTION_TYPES for x in targs)
    pairs = ([(c, None) for c in ctx.prod_calls(pipe, *_COOKIE_CALLS)]
             + [(c, "REVIEW") for c in ctx.uncertain_calls(pipe, *_COOKIE_CALLS)])
    return [(c, conf) for c, conf in pairs if wanted(c)]


def check_cookies(ctx: Ctx) -> None:
    seen: set = set()

    def add(cid: str, sev: str, title: str, desc: str, c: PipeCall, line: int, conf: str | None) -> None:
        if c.runs_in("Production") is None:
            conf = "REVIEW"
            desc += " The call sits under an environment condition that could not be parsed."
        key = (cid, c.file, line, conf)      # a helper followed from two sites yields the same fact twice
        if key not in seen:
            seen.add(key)
            ctx.add(cid, sev, title, desc, c.file, line, confidence=conf)

    for pipe in ctx.pipes:
        for c, conf in _cookie_calls(ctx, pipe):
            _opaque(c, conf, add)
            opts = options_of(c.node)
            if not opts:
                continue
            _secure(opts, c, conf, add)
            _httponly(opts, c, conf, add)
            _samesite(opts, c, conf, add)
            _lifetime(opts, c, conf, add)


_OPAQUE_IDS = (("DNL-SESS-001", "medium", "Cookie not restricted to HTTPS", "Secure flag"),
               ("DNL-SESS-002", "low", "Cookie readable by scripts (HttpOnly off)", "HttpOnly flag"),
               ("DNL-SESS-003", "low", "Cookie or session lifetime over one day", "lifetime"),
               ("DNL-SESS-009", "low", "Cookie SameSite is None", "SameSite mode"))


def _kind_of_call(c: PipeCall) -> str:
    """"cookie" | "session" | "antiforgery" | "policy": which cookie a call configures."""
    if c.name == "Configure":
        targs = [str(x).strip().split(".")[-1] for x in (c.node.get("fn") or {}).get("targs") or []]
        return ("session" if "SessionOptions" in targs else "antiforgery" if "AntiforgeryOptions" in targs
                else "policy" if "CookiePolicyOptions" in targs else "cookie")
    return {"AddSession": "session", "AddAntiforgery": "antiforgery", "UseCookiePolicy": "policy"}.get(c.name, "cookie")


def _opaque(c: PipeCall, conf, add) -> None:
    """A cookie call whose options are not all readable (a method group, a variable, a configuration
    section, an options parameter handed to a helper): REVIEW for every id the settings could affect."""
    reason = opaque_reason(c.node)
    if reason is None:
        return
    # Antiforgery and cookie-policy options carry no lifetime, so SESS-003 cannot apply to them.
    skip_life = _kind_of_call(c) in ("antiforgery", "policy")
    for cid, sev, title, what in _OPAQUE_IDS:
        if cid == "DNL-SESS-003" and skip_life:
            continue
        add(cid, sev, title, f"The {what} of the cookie set up by {c.name} could not be read: {reason}. "
                             "Confirm the cookie is Secure, HttpOnly, not SameSite=None and short-lived.",
            c, c.line, "REVIEW")


def _weak_flag(opts: list[Opt], leaves: tuple[str, ...], bad: tuple, good: tuple, bool_bad: bool | None,
               review_unknown: bool) -> list[tuple[Opt, bool, str]]:
    """[(effective assignment, firm, kind)] per cookie setting path that is bad or cannot be read. A
    conditional assignment never clears (verdict): a conditional good value leaves a bad one standing as
    REVIEW, and a conditional bad value is REVIEW. `review_unknown` turns a value that is not a known good
    one into REVIEW (SESS-001 / 002); otherwise only a known-bad value counts (SESS-009)."""
    out = []
    for path in _paths(opts, leaves):
        if review_unknown:
            pred = lambda x: _kind(x, bad, good, bool_bad=bool_bad) != "good"  # noqa: E731
        else:
            pred = lambda x: _kind(x, bad, good, bool_bad=bool_bad) == "bad"   # noqa: E731
        o, uncertain = verdict(opts, path, bad=pred)
        if o is None:
            continue
        k = _kind(o, bad, good, bool_bad=bool_bad)
        if k == "good" or (k == "unknown" and not review_unknown):
            continue
        out.append((o, k == "bad" and not uncertain, k))
    return out


def _secure(opts, c, conf, add) -> None:
    found = _weak_flag(opts, ("securepolicy", "secure"), _SECURE_BAD, _SECURE_GOOD, None, True)
    for o, firm, k in found:
        if k == "bad":
            desc = (f"{o.path} is {const(o.value)}, so the cookie may be sent over plain HTTP and read on the "
                    "network. Use CookieSecurePolicy.Always.")
            if not firm:
                desc += " Some assignment to it sits under a condition, so it may not apply; confirm."
        else:
            desc = (f"{o.path} is not a compile-time CookieSecurePolicy value, so it may be None or "
                    "SameAsRequest in Production; confirm it is Always.")
        add("DNL-SESS-001", "medium", "Cookie not restricted to HTTPS", desc, c, o.line, conf if firm else "REVIEW")
    if not found and not _paths(opts, ("securepolicy", "secure")):
        for o in _opaque_cookies(opts):
            add("DNL-SESS-001", "medium", "Cookie not restricted to HTTPS",
                f"{o.path} is assigned a cookie builder that is not built here, so its SecurePolicy cannot be "
                "read; confirm it is CookieSecurePolicy.Always.", c, o.line, "REVIEW")


def _httponly(opts, c, conf, add) -> None:
    found = _weak_flag(opts, ("httponly",), _HTTPONLY_BAD, _HTTPONLY_GOOD, False, True)
    for o, firm, k in found:
        if k == "bad":
            desc = (f"{o.path} is {const(o.value)}, so page scripts can read the cookie (session theft after "
                    "an XSS). Set HttpOnly = true.")
            if not firm:
                desc += " Some assignment to it sits under a condition, so it may not apply; confirm."
        else:
            desc = (f"{o.path} is not a compile-time value, so it may be false in Production; confirm "
                    "it is true.")
        add("DNL-SESS-002", "low", "Cookie readable by scripts (HttpOnly off)", desc, c, o.line,
            conf if firm else "REVIEW")
    if not found and not _paths(opts, ("httponly",)):
        for o in _opaque_cookies(opts):
            add("DNL-SESS-002", "low", "Cookie readable by scripts (HttpOnly off)",
                f"{o.path} is assigned a cookie builder that is not built here, so its HttpOnly flag cannot "
                "be read; confirm it is true.", c, o.line, "REVIEW")


def _samesite(opts, c, conf, add) -> None:
    good = ("SameSiteMode.Lax", "SameSiteMode.Strict", "SameSiteMode.Unspecified")
    for o, firm, k in _weak_flag(opts, ("samesite", "minimumsamesitepolicy"), ("SameSiteMode.None",), good, None,
                                 True):
        if k != "bad":
            add("DNL-SESS-009", "low", "Cookie SameSite is None",
                f"{o.path} is not a compile-time SameSiteMode value, so it may be None in Production; confirm "
                "it is Lax or Strict.", c, o.line, "REVIEW")
            continue
        desc = (f"{o.path} is SameSiteMode.None, so the browser sends the cookie on every cross-site "
                "request, which removes its CSRF protection. Use Lax or Strict unless the cookie must be "
                "embedded cross-site.")
        if not firm:
            desc += " Some assignment to it sits under a condition, so it may not apply; confirm."
        add("DNL-SESS-009", "low", "Cookie SameSite is None", desc, c, o.line, conf if firm else "REVIEW")


def _span_kind(o: Opt) -> str:
    """"bad" (over a day), "good", or "unknown" (not a compile-time TimeSpan; a literal null MaxAge is good)."""
    m = timespan_minutes(o.value)
    if m is not None:
        return "bad" if m > _MAX_MINUTES else "good"
    v = o.value
    return "good" if isinstance(v, dict) and v.get("k") == "lit" and v.get("v") is None else "unknown"


def _lifetime(opts, c, conf, add) -> None:
    """DNL-SESS-003: ExpireTimeSpan over a day while the expiry slides, and a session IdleTimeout or
    Cookie.MaxAge over a day (AddSession only). A value that is not a compile-time TimeSpan is REVIEW."""
    title = "Cookie or session lifetime over one day"
    specs = [("expiretimespan", True)]
    if c.name in ("AddSession", "Configure"):
        specs += [("idletimeout", False), ("cookie.maxage", False)]
    for path, sliding_matters in specs:
        o, uncertain = verdict(opts, path, bad=lambda x: _span_kind(x) != "good")
        if o is None or _span_kind(o) == "good":
            continue
        if _span_kind(o) == "unknown":
            add("DNL-SESS-003", "low", title,
                f"{o.path} is not a compile-time TimeSpan, so it may be longer than {_MAX_MINUTES} minutes in "
                "Production; confirm it is not.", c, o.line, "REVIEW")
            continue
        firm = not uncertain
        desc = (f"{o.path} is {timespan_minutes(o.value):g} minutes (over {_MAX_MINUTES}), so a stolen cookie "
                "stays usable for days; shorten it")
        if sliding_matters:
            s, s_uncertain = verdict(opts, "slidingexpiration")
            sv = const(s.value) if s is not None else True
            if s is not None and sv is False and not s_uncertain:
                continue        # a fixed expiry: the long span is a deliberate absolute limit
            if s is not None and sv is not False and sv is not True:
                firm = False
                desc += "; SlidingExpiration is not a compile-time value, so each request may extend it"
            elif s is not None and s_uncertain:
                firm = False
                desc += "; SlidingExpiration is set under a condition, so it may still slide"
            else:
                desc += " and the expiry slides on each request"
        desc += "."
        if uncertain:
            desc += " Some assignment to it sits under a condition, so it may not apply; confirm."
        add("DNL-SESS-003", "low", title, desc, c, o.line, conf if firm else "REVIEW")


# -- antiforgery (DNL-CSRF-001 reused for ASP.NET Core, DNL-CSRF-002) -----------------------------------

_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}
_VERB_ATTRS = {f"http{v}" for v in ("get", "post", "put", "delete", "patch", "head", "options")} | {"acceptverbs"}
# Calls whose options lambda can register global filters; `Configure<T>` counts only for the option types below.
_MVC_CALLS = ("AddControllers", "AddControllersWithViews", "AddMvc", "AddMvcCore", "AddMvcOptions", "AddRazorPages",
              "AddRazorPagesOptions", "Configure")
_MVC_OPTION_TYPES = ("MvcOptions", "RazorPagesOptions")
_COOKIE_REGISTRATIONS = ("AddCookie", "AddIdentity", "AddDefaultIdentity")
_VALIDATE_NAMES = {"validateantiforgerytoken", "validateantiforgerytokenattribute",
                   "autovalidateantiforgerytoken", "autovalidateantiforgerytokenattribute"}
_IGNORE_NAMES = {"ignoreantiforgerytoken", "ignoreantiforgerytokenattribute"}
_FORM_TYPES = {"iformfile", "iformfilecollection", "iformcollection"}
_TYPEOF = re.compile(r"\s*typeof\s*\(\s*([\w.<>,\s?]+?)\s*\)\s*")
_PAGE_ATTR = re.compile(r"(IgnoreAntiforgeryToken|(?:Auto)?ValidateAntiforgeryToken)", re.IGNORECASE)


@dataclass
class _Af:
    """What one pipeline says about cookie authentication and global antiforgery filters."""
    cookie: str = "no"                                     # "yes" | "maybe" | "no"
    cookie_why: list = field(default_factory=list)         # why "maybe"
    protect: str = "no"                                    # a global validating filter: "yes" | "maybe" | "no"
    protect_why: list = field(default_factory=list)
    ignore: list = field(default_factory=list)             # [(file, line, firm)] global ignoring filters
    opaque: list = field(default_factory=list)             # [(call, reason)] MVC option calls that cannot be read
    unresolved: list = field(default_factory=list)         # unresolved services calls that could add a filter

    def maybe_protect(self, why: str) -> None:
        if self.protect != "yes":
            self.protect = "maybe"
        self.protect_why.append(why)


def _calls(ctx: Ctx, pipe: Pipeline, *names: str) -> list[tuple[PipeCall, str | None]]:
    """[(call, confidence)]: firm for calls that certainly run in Production, REVIEW under an unparsed guard."""
    return ([(c, None) for c in ctx.prod_calls(pipe, *names)]
            + [(c, "REVIEW") for c in ctx.uncertain_calls(pipe, *names)])


def _cookie_scheme(a) -> bool:
    """An AddAuthentication argument that names the cookie scheme."""
    if not isinstance(a, dict):
        return False
    if a.get("k") == "lit":
        return str(a.get("v")).lower() == "cookies"
    text = receiver_text(a) or ""
    return text.endswith(("CookieAuthenticationDefaults.AuthenticationScheme", "IdentityConstants.ApplicationScheme"))


def _af_kind(ctx: Ctx, name: str) -> str | None:
    """"validate" | "ignore" | None for an attribute or filter type name, including project types derived
    from the framework ones."""
    key = attr_key(name)
    if key in _VALIDATE_NAMES:
        return "validate"
    if key in _IGNORE_NAMES:
        return "ignore"
    simple = name.split("<")[0].split(".")[-1]
    for n in (simple, simple + "Attribute"):
        for t in ctx.model.find_types(n):
            if ctx.model.derives_from(t, _VALIDATE_NAMES):
                return "validate"
            if ctx.model.derives_from(t, _IGNORE_NAMES):
                return "ignore"
    return None


def _filter_add(n: dict) -> tuple[list[str], bool] | None:
    """(filter type names, some argument is not readable) for a Filters.Add(...) / AddService /
    ConfigureFilter call; None for any other call."""
    fn = n.get("fn") if isinstance(n.get("fn"), dict) else {}
    name = call_name(n)
    if name in ("Add", "AddService"):
        if (receiver_text(fn.get("obj")) or "").split(".")[-1] != "Filters":
            return None
    elif name != "ConfigureFilter":
        return None
    types = [str(t) for t in fn.get("targs") or []]
    unreadable = False
    for a in n.get("args") or []:
        if not isinstance(a, dict) or a.get("k") == "lit":
            continue            # the order argument
        if a.get("k") == "new" and a.get("type"):
            types.append(str(a["type"]))
            continue
        m = _TYPEOF.fullmatch(str(a.get("text") or "")) if a.get("k") == "unknown" else None
        if m:
            types.append(m.group(1))
        else:
            unreadable = True
    return types, unreadable


def _mvc_option_calls(ctx: Ctx, pipe: Pipeline) -> list[tuple[PipeCall, str | None]]:
    def wanted(c: PipeCall) -> bool:
        if c.name != "Configure":
            return True
        targs = (c.node.get("fn") or {}).get("targs") or []
        return any(str(x).strip().split(".")[-1] in _MVC_OPTION_TYPES for x in targs)
    return [(c, conf) for c, conf in _calls(ctx, pipe, *_MVC_CALLS) if wanted(c)]


def _af_state(ctx: Ctx, pipe: Pipeline) -> _Af:
    st = _Af()
    # -- is cookie authentication in play? A guess in either direction is REVIEW, never "no".
    present = maybe = False
    for c, conf in _calls(ctx, pipe, *_COOKIE_REGISTRATIONS, "AddAuthentication"):
        if c.name == "AddAuthentication":
            reason = opaque_reason(c.node)
            if reason is not None:
                maybe = True
                st.cookie_why.append(f"the options of AddAuthentication at {c.file}:{c.line} could not be read ({reason})")
            args = list(c.node.get("args") or []) + list((c.node.get("named") or {}).values())
            if not any(_cookie_scheme(a) for a in args):
                continue
        if conf is None:
            present = True
        else:
            maybe = True
            st.cookie_why.append(f"{c.name} at {c.file}:{c.line} sits under an environment condition that could not be parsed")
    for c in pipe.unresolved():
        if c.kind == "services" and c.name not in _NON_AUTHZ_EXTENSIONS and c.runs_in("Production") is not False:
            maybe = True
            st.cookie_why.append(f"{c.name} at {c.file}:{c.line} is not resolved and may register cookie authentication")
            st.unresolved.append(f"{c.name} at {c.file}:{c.line} is not resolved and may register a global antiforgery filter")
    st.cookie = "yes" if present else "maybe" if maybe else "no"
    # -- global filters
    for c, conf in _mvc_option_calls(ctx, pipe):
        reason = opaque_reason(c.node)
        if reason is not None:
            st.opaque.append((c, reason))
            st.maybe_protect(f"the options of {c.name} at {c.file}:{c.line} could not be read ({reason})")
        for lam in lambda_args(c.node):
            for n, cd in walk_conditional(lam):
                added = _filter_add(n) if n.get("k") == "call" else None
                if added is None:
                    continue
                types, unreadable = added
                kinds = {_af_kind(ctx, t) for t in types}
                firm = conf is None and not cd
                line = n.get("line") or c.line
                if "ignore" in kinds:
                    st.ignore.append((c.file, line, firm))
                if "validate" in kinds and call_name(n) != "ConfigureFilter":
                    if firm:
                        st.protect = "yes"
                    else:
                        st.maybe_protect(f"a validating filter at {c.file}:{line} is added only under a condition")
                if unreadable:
                    st.maybe_protect(f"the filter added at {c.file}:{line} is not a new expression or typeof, so "
                                     "it may validate antiforgery tokens")
    return st


def _merge_states(states: list[_Af]) -> _Af:
    """The state a route sees when its project has no pipeline of its own (a controllers library): cookies
    when any host has them, protection only when every host has it."""
    out = _Af()
    if not states:      # controllers in a library with no host project in the scan: nothing to read
        out.cookie = out.protect = "maybe"
        out.cookie_why = ["no host project in the scan, so cookie authentication could not be read"]
        out.protect_why = ["no host project in the scan, so global filters could not be read"]
        return out
    out.cookie = ("yes" if any(s.cookie == "yes" for s in states)
                  else "maybe" if any(s.cookie == "maybe" for s in states) else "no")
    out.cookie_why = [w for s in states for w in s.cookie_why]
    if states and all(s.protect == "yes" for s in states):
        out.protect = "yes"
    elif any(s.protect != "no" for s in states):
        out.protect = "maybe"
        out.protect_why = [w for s in states for w in s.protect_why] or ["only some hosting projects add the filter"]
    out.ignore = [i for s in states for i in s.ignore]
    out.unresolved = [u for s in states for u in s.unresolved]
    return out


def _policy(ctx: Ctx, attrs) -> str | None:
    """"ignore" | "validate" | None from a list of attributes (ignore wins when both are present)."""
    kinds = {_af_kind(ctx, a.name) for a in attrs}
    return "ignore" if "ignore" in kinds else "validate" if "validate" in kinds else None


def _route_policy(ctx: Ctx, ref: CoreRouteRef) -> tuple[str | None, bool]:
    """(policy, on the action itself): the nearest antiforgery attribute: the action or handler, then the
    controller / PageModel class and its base classes, then a page's @attribute directives."""
    if ref.method is not None:
        p = _policy(ctx, ref.method.attributes)
        if p:
            return p, True
    if ref.type is not None:
        for t in _chain_types(ctx.model, ref.type):
            p = _policy(ctx, t.attributes)
            if p:
                return p, False
    kinds = set()
    for raw in ref.route.meta.get("page_attributes") or []:
        for m in _PAGE_ATTR.finditer(str(raw)):
            kinds.add("ignore" if m.group(1).lower().startswith("ignore") else "validate")
    return ("ignore" if "ignore" in kinds else "validate" if kinds else None), False


def _env_state(env: str | None) -> str:
    """"firm" (no environment condition, or one that runs in Production), "skip" (Development only) or
    "review" (any other condition, including one that could not be parsed)."""
    if env is None or env == "!Development":
        return "firm"
    return "skip" if env == "Development" else "review"


def _explicit_mutating(ref: CoreRouteRef) -> bool:
    """A verb attribute names a mutating verb (the GET+POST / name-prefix defaults do not count)."""
    return (ref.method is not None
            and any(attr_key(a.name) in _VERB_ATTRS for a in ref.method.attributes)
            and bool(_MUTATING & {v.upper() for v in ref.route.methods}))


def _form_bound(m) -> str:
    """"yes" | "no" | "maybe" for a minimal-API handler: a [FromForm] / IFormFile / IFormCollection parameter,
    or an [AsParameters] holder that could contain one; "maybe" too when the handler was not resolved."""
    if m is None:
        return "maybe"
    out = "no"
    for p in m.params:
        words = set(re.findall(r"\w+", (p.type or "").lower()))     # IFormFile[], List<IFormFile>, ...
        keys = {attr_key(a.name) for a in p.attributes}
        if "fromform" in keys or words & _FORM_TYPES:
            return "yes"
        if "asparameters" in keys:
            out = "maybe"
    return out


def check_antiforgery(ctx: Ctx) -> None:
    seen: set = set()
    states = {id(p): _af_state(ctx, p) for p in ctx.pipes}

    def state_for(ref: CoreRouteRef) -> _Af:
        own = [states[id(p)] for p in ctx.pipes if ref.project is not None and p.project is ref.project]
        return own[0] if own else _merge_states(list(states.values()))

    def add(cid: str, title: str, desc: str, ref: CoreRouteRef, conf: str | None) -> None:
        r = ref.route
        key = (cid, r.file, r.line, r.handler_name)
        if key not in seen:
            seen.add(key)
            ctx.add(cid, "medium", title, desc, r.file, r.line, route=r, confidence=conf)

    for pipe in ctx.pipes:      # an options call that cannot be read could add a global ignoring filter
        for c, reason in states[id(pipe)].opaque:
            key = ("DNL-CSRF-002", c.file, c.line)
            if key not in seen:
                seen.add(key)
                ctx.add("DNL-CSRF-002", "medium", "Antiforgery filters could not be read",
                        f"The options of {c.name} could not be read ({reason}), so a global "
                        "IgnoreAntiforgeryTokenAttribute filter may be registered there. Confirm none is.",
                        c.file, c.line, confidence="REVIEW")

    for ref in ctx.refs:
        r = ref.route
        st = state_for(ref)
        verbs = {v.upper() for v in r.methods}
        env = _env_state(r.meta.get("env"))
        if ref.style in ("controller", "razorpage"):
            if ref.type is None and ref.style == "razorpage":
                # The PageModel was not found: a page-level directive is all there is to read.
                if _route_policy(ctx, ref)[0] == "ignore" and env != "skip":
                    add("DNL-CSRF-002", f"Antiforgery validation disabled on {r.handler_name}",
                        f"{r.handler_name} ({r.path}) carries @attribute [IgnoreAntiforgeryToken], so its POST "
                        "handlers skip token validation, but the page model could not be resolved to confirm "
                        "which handlers exist.", ref, "REVIEW")
                continue
            if ref.type is None or (ref.style == "controller" and ref.method is None):
                continue
            pol, on_action = _route_policy(ctx, ref)
            where = f"{r.handler_name} ({', '.join(r.methods)} {r.path})"
            global_ignore = [i for i in st.ignore if pol is None]
            firm_global = any(i[2] for i in global_ignore)
            # CSRF-002: the route opts out of token validation.
            mutating = bool(verbs & _MUTATING)
            if env != "skip" and ((pol == "ignore" and (mutating or (on_action and "ANY" in verbs)))
                                  or (global_ignore and mutating)):
                local = pol == "ignore"
                conf = None if (mutating and (local or firm_global) and env == "firm") else "REVIEW"
                src = ("[IgnoreAntiforgeryToken] on the " + ("action" if on_action else "class or page")
                       if local else "a global IgnoreAntiforgeryTokenAttribute filter")
                desc = (f"{where} accepts a mutating request with antiforgery validation switched off by {src}, so a "
                        "page on another site can submit it with the visitor's cookies. Remove the opt-out, or "
                        "authenticate with a header token instead of a cookie.")
                if not mutating:
                    desc += " The action names no HTTP verb, so it accepts POST."
                if not (local or firm_global):
                    desc += " The global filter is registered only under a condition."
                if env == "review":
                    desc += " The route is mapped under an environment condition that is not plain Production."
                add("DNL-CSRF-002", f"Antiforgery validation disabled on {r.handler_name}", desc, ref, conf)
            # CSRF-001: an MVC form post nothing protects. [ApiController] and Razor Pages validate on their own.
            if (ref.style == "controller" and not r.meta.get("api_surface") and pol is None and not firm_global
                    and _explicit_mutating(ref) and st.cookie != "no" and st.protect != "yes" and env != "skip"):
                why = (st.cookie_why if st.cookie == "maybe" else []) + st.protect_why + st.unresolved
                if env == "review":
                    why.append("the controllers are mapped under an environment condition that is not plain Production")
                desc = (f"{where} accepts a mutating request but no [ValidateAntiForgeryToken] covers it (action, "
                        "controller, base classes) and no global AutoValidateAntiforgeryTokenAttribute filter is "
                        "registered, while cookie authentication is in use, so another site can post to it with "
                        "the visitor's cookies.")
                if why:
                    desc += " Not certain: " + "; ".join(dict.fromkeys(why)) + "."
                add("DNL-CSRF-001", f"State-changing MVC action {r.handler_name} lacks anti-forgery validation",
                    desc, ref, "REVIEW" if why else None)
        elif ref.style == "minimalapi":
            calls = list(ref.endpoint_calls) + list(ref.convention_calls) + [c for g in ref.groups for c in g.calls]
            direct = any(call_name(c) == "DisableAntiforgery" for c in calls if isinstance(c, dict))
            # A convention this engine could not follow may be (or hide) a DisableAntiforgery call.
            hidden = any("DisableAntiforgery" in u or "may change this endpoint's metadata" in u
                         or "applied to the result of" in u for u in ref.unknown)
            if not direct and not hidden:
                continue
            form = _form_bound(ref.method)
            if form == "no" or st.cookie == "no" or env == "skip" or verbs <= {"GET", "HEAD", "OPTIONS"}:
                continue
            soft = (not direct or form == "maybe" or st.cookie == "maybe" or env == "review"
                    or any("DisableAntiforgery applied conditionally" in u for u in ref.unknown))
            desc = (f"{r.handler_name} ({', '.join(r.methods)} {r.path}) binds form data and calls "
                    "DisableAntiforgery(), so a page on another site can post to it with the visitor's cookies.")
            if not direct:
                desc = desc.replace("and calls DisableAntiforgery()", "and passes through a call that could not "
                                    "be followed, which may be DisableAntiforgery()")
            if form == "maybe":
                desc += " Its handler could not be read, so form binding is assumed."
            if st.cookie == "maybe":
                desc += " Cookie authentication could not be ruled out: " + "; ".join(st.cookie_why) + "."
            if env == "review":
                desc += " The route is registered under an environment condition that is not plain Production."
            add("DNL-CSRF-002", f"Antiforgery validation disabled on {r.handler_name}", desc, ref,
                "REVIEW" if soft else None)
