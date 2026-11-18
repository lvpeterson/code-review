"""Authentication-related ASP.NET Core configuration rules, called from the rules_pipeline aggregator.

Groups: cookies and session (DNL-SESS-001/002/003 reused, DNL-SESS-009), antiforgery (DNL-CSRF-001
reused, DNL-CSRF-002) and JWT / OIDC token validation (DNL-SESS-010, DNL-SESS-011, DNL-CFG-012,
DNL-SEC-004) and the Identity options (DNL-SEC-005, DNL-SEC-006, DNL-SEC-007).

Like the other rules_pipeline* modules it must not import rules_auth_core (static inventory test);
shared helpers live in auth_core.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from checks.dnl.auth_core import _NON_AUTHZ_EXTENSIONS, PLACEHOLDER
from checks.dnl.cfgctx import Ctx, _scope_of
from checks.dnl.ir import attr_key, call_name, const_str, literal_str, receiver_text, walk
from checks.dnl.options import (Opt, assignments, const, lambda_args, opaque_reason, options_of, param_escapes,
                                timespan_minutes, verdict, walk_conditional)
from checks.dnl.pipeline import PipeCall, Pipeline, _Ctx, _eval, _pred
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
# AddMicrosoftIdentityWebApp and AddIdentityApiEndpoints register the application cookie themselves.
_COOKIE_REGISTRATIONS = ("AddCookie", "AddIdentity", "AddDefaultIdentity", "AddMicrosoftIdentityWebApp",
                         "AddIdentityApiEndpoints")
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
    for c, conf in _calls(ctx, pipe, *_COOKIE_REGISTRATIONS, "AddAuthentication", "AddOpenIdConnect"):
        if c.name == "AddOpenIdConnect":
            # OpenID Connect signs the user in through a cookie scheme; with no AddCookie in sight, which
            # cookie it uses is not visible, so this is a "maybe" (an AddCookie elsewhere makes it "yes").
            maybe = True
            st.cookie_why.append(f"AddOpenIdConnect at {c.file}:{c.line} signs in through a cookie scheme "
                                 "that is not visible here")
            continue
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


# -- JWT and OIDC token validation (DNL-SESS-010, DNL-SESS-011, DNL-CFG-012, DNL-SEC-004) -----------------

# Calls whose options carry JwtBearerOptions / OpenIdConnectOptions settings; `Configure<T>` and
# `PostConfigure<T>` count only for the option types below. AddCookie is read for RequireHttpsMetadata only.
_TOKEN_CALLS = ("AddJwtBearer", "AddOpenIdConnect", "AddMicrosoftIdentityWebApi", "AddMicrosoftIdentityWebApp",
                "AddCookie", "Configure", "PostConfigure")
_TOKEN_OPTION_TYPES = ("JwtBearerOptions", "OpenIdConnectOptions")
_MS_IDENTITY_CALLS = ("AddMicrosoftIdentityWebApi", "AddMicrosoftIdentityWebApp")
_TVP = "TokenValidationParameters"
_TVP_PREFIX = _TVP.lower() + "."
_UNCHECKED_TOKEN_TYPES = ("JwtSecurityToken", "JsonWebToken")
# (option, severity, what switching it off allows)
_VALIDATE_FLAGS = (
    ("validateissuer", "medium", "tokens from any issuer are accepted"),
    ("validateaudience", "medium", "tokens issued for any other API or client are accepted"),
    ("validatelifetime", "medium", "expired tokens are accepted"),
    ("requireexpirationtime", "medium", "tokens that never expire are accepted"),
    ("validateissuersigningkey", "high", "the key that signed the token is not checked, so a forged token can pass"),
    ("requiresignedtokens", "high", "unsigned tokens are accepted, so anyone can forge one"),
)
_MAX_SKEW_MINUTES = 10
_SEC004_TITLE = "Hardcoded symmetric signing key"


def _env_branches(pred) -> tuple[bool | None, bool | None]:
    """(runs in Production when the condition is true, ... when false) for an environment predicate; None
    for a branch whose Production behaviour cannot be told. (True, False) / (False, True) are decided."""
    v = _eval(pred, "production")
    return (None, None) if v is None else (v, not v)


def _prune(node):
    """A copy of the node as Production sees it: an `if` or ternary whose condition is an environment check
    that evaluates for Production is replaced by the branch that runs there (so a Development-only block
    vanishes and its else part is unconditional). Conditions that read no environment, or that could not be
    parsed, stay: the options reader then marks what sits under them conditional (REVIEW)."""
    if isinstance(node, list):
        out: list = []
        for x in node:
            kept = _decided_if(x)
            if kept is None:
                out.append(_prune(x))
            else:
                out.extend(_prune(kept))
        return out
    if not isinstance(node, dict):
        return node
    if node.get("k") == "cond":
        pred = _pred(node.get("c"), {}, _Ctx())
        if pred is not None and _eval(pred, "production") is not None:
            return _prune(node.get("t") if _eval(pred, "production") else node.get("f"))
    return {k: _prune(v) if isinstance(v, (dict, list)) else v for k, v in node.items()}


def _decided_if(s) -> list | None:
    """The statements of the branch an environment `if` takes in Production; None for any other node."""
    if not (isinstance(s, dict) and s.get("k") == "if"):
        return None
    pred = _pred(s.get("cond"), {}, _Ctx())
    if pred is None:
        return None
    v = _eval(pred, "production")
    if v is None:
        return None
    return list((s.get("then") if v else s.get("else")) or [])


def _text(e) -> str:
    """Source-like text of an expression for a REVIEW message."""
    if not isinstance(e, dict):
        return "an expression"
    if e.get("text"):
        return str(e["text"])
    k = e.get("k")
    if k == "lit":
        return repr(e.get("v"))
    if k in ("name", "member"):
        return receiver_text(e) or "an expression"
    if k == "call":
        fn = e.get("fn") if isinstance(e.get("fn"), dict) else {}
        return f"{receiver_text(fn) or call_name(e) or 'a call'}(...)"
    if k == "new":
        return f"new {e.get('type') or ''}(...)".replace("new (", "new(")
    return "an expression"


def _token_calls(ctx: Ctx, pipe: Pipeline) -> list[tuple[PipeCall, str | None]]:
    def wanted(c: PipeCall) -> bool:
        if c.name not in ("Configure", "PostConfigure"):
            return True
        targs = (c.node.get("fn") or {}).get("targs") or []
        return any(str(x).strip().split(".")[-1] in _TOKEN_OPTION_TYPES for x in targs)
    return [(c, conf) for c, conf in _calls(ctx, pipe, *_TOKEN_CALLS) if wanted(c)]


def _without_config_sections(node: dict) -> dict:
    """AddMicrosoftIdentityWebApi(configuration.GetSection("AzureAd")): the section binds the Microsoft
    Identity options (instance, tenant, client id), which hold no validation switches, so it is the normal
    way to call it and not an unreadable options source. The option lambdas next to it are still read."""
    def is_section(a) -> bool:
        if not isinstance(a, dict) or a.get("k") in ("lambda", "new", "lit"):
            return False
        return any((n.get("k") == "call" and call_name(n) == "GetSection")
                   or (n.get("k") == "member" and n.get("name") == "Configuration")
                   or (n.get("k") == "name" and str(n.get("id") or "").lower() in ("configuration", "config"))
                   for n in walk(a))
    out = dict(node)
    out["args"] = [a for a in node.get("args") or [] if not is_section(a)]
    out["named"] = {k: v for k, v in (node.get("named") or {}).items() if not is_section(v)}
    return out


def _enclosing_body(ctx: Ctx, c: PipeCall):
    """The statement list of the method (or accessor) the call node was written in; None when not found."""
    for f in ctx.model.files.values():
        for t in f.types:
            if t.file != c.file:
                continue
            bodies = [m.body for m in t.methods]
            for p in t.properties:
                bodies += [x for x in (p.get, p.set) if x]
            for body in bodies:
                if any(n is c.node for n in walk(body)):
                    return body
    return None


def _chain_root(target) -> tuple[str | None, str]:
    """(root name, dotted path below it) of `p.A.B`; (None, "") for anything else."""
    names: list[str] = []
    n = target
    while isinstance(n, dict) and n.get("k") == "member":
        names.append(n.get("name") or "")
        n = n.get("obj")
    if isinstance(n, dict) and n.get("k") == "name" and all(names):
        return n.get("id"), ".".join(reversed(names))
    return None, ""


def _resolve_local(ctx: Ctx, c: PipeCall, node: dict, name: str) -> tuple[list[Opt] | None, str]:
    """(settings read from the local `name`, "") or (None, why not): the local's `new TokenValidationParameters`
    initializer plus `name.X = v` assignments, one level, in the lambda that declares it or else the
    enclosing method. A local that is handed to another call, reassigned or copied is out of sight."""
    root = node
    decl = [n for n in walk(root) if n.get("k") == "local" and n.get("name") == name]
    if not decl:
        body = _enclosing_body(ctx, c)
        if body is None:
            return None, f"{name} is not declared where this code can see it"
        root = _prune(body)
        decl = [n for n in walk(root) if n.get("k") == "local" and n.get("name") == name]
    if len(decl) != 1:
        return None, f"{name} is not declared exactly once where this code can see it"
    init = decl[0].get("init")
    simple = str(decl[0].get("type") or "").split(".")[-1]
    is_tvp = (isinstance(init, dict) and init.get("k") == "new"
              and (str(init.get("type") or "").split(".")[-1] == _TVP
                   or (not init.get("type") and simple == _TVP)))
    if not is_tvp:
        return None, f"{name} is not a plain new {_TVP}"
    if init.get("args"):
        return None, f"{name} is built with constructor arguments (a copy of another {_TVP}?)"
    ok: set = set()
    out = list(assignments(init))
    for n, cond in walk_conditional(root):
        if n.get("k") == "member":
            r = n
            while isinstance(r, dict) and r.get("k") == "member":
                r = r.get("obj")
            if isinstance(r, dict) and r.get("k") == "name" and r.get("id") == name:
                ok.add(id(r))
        elif n.get("k") == "assign" and n.get("op") == "=":
            rname, path = _chain_root(n.get("target"))
            v = n.get("value")
            if isinstance(v, dict) and v.get("k") == "name" and v.get("id") == name:
                ok.add(id(v))
            if rname == name and path:
                out.append(Opt(path, v, n.get("line") or 0, cond))
    if param_escapes(root, name, ok):
        return None, f"{name} is passed to another call, copied or reassigned, so it is changed where this code cannot see"
    return out, ""


def _tvp_settings(ctx: Ctx, c: PipeCall, node: dict, opts: list[Opt]) -> tuple[list[Opt], list[tuple[str, int]]]:
    """([settings of the TokenValidationParameters, paths relative to it], [(why unreadable, line)]). It reads
    `o.TokenValidationParameters = new ... { }`, `o.TokenValidationParameters.X = v` and a local initialised
    with `new TokenValidationParameters` (one level). Anything else assigned to it (a helper call, a field,
    a parameter, a derived type) is unreadable."""
    out = [Opt(o.path[len(_TVP_PREFIX):], o.value, o.line, o.conditional)
           for o in opts if o.path.lower().startswith(_TVP_PREFIX)]
    unreadable: list[tuple[str, int]] = []
    for o in opts:
        if o.path.lower() != _TVP.lower():
            continue
        v = o.value
        if isinstance(v, dict) and v.get("k") == "new":
            t = str(v.get("type") or "").split(".")[-1]
            if t not in ("", _TVP):
                unreadable.append((f"it is built as {v.get('type')}, a type this code does not read", o.line))
            elif v.get("args"):
                unreadable.append(("it is built with constructor arguments (a copy of another "
                                   f"{_TVP}?), whose settings are not read", o.line))
        elif isinstance(v, dict) and v.get("k") == "name":
            extra, why = _resolve_local(ctx, c, node, v.get("id") or "")
            if extra is None:
                unreadable.append((why, o.line))
            else:
                out += extra
        else:
            unreadable.append((f"it is set from {_text(v)}", o.line))
    return out, unreadable


def _skew_kind(o: Opt) -> str:
    """"bad" (over ten minutes), "good" or "unknown" for a ClockSkew value."""
    text = receiver_text(o.value) if isinstance(o.value, dict) and o.value.get("k") == "member" else ""
    if text.endswith(("TimeSpan.Zero", "DefaultClockSkew")):
        return "good"
    if text.endswith("TimeSpan.MaxValue"):
        return "bad"
    m = timespan_minutes(o.value)
    if m is None:
        return "unknown"
    return "bad" if m > _MAX_SKEW_MINUTES else "good"


def _flag_kind(o: Opt) -> str:
    """"bad" (literal false), "good" (literal true) or "unknown" for a validation switch."""
    v = const(o.value)
    return "unknown" if not isinstance(v, bool) else "good" if v else "bad"


def _signature_kind(o: Opt) -> str:
    """"unchecked" (a lambda that wraps its token argument without checking it), "good" (literal null) or
    "custom" (any other validator: it replaces the signature check and its body is not proven sound)."""
    v = o.value
    if isinstance(v, dict) and v.get("k") == "lit" and v.get("v") is None:
        return "good"
    if not (isinstance(v, dict) and v.get("k") == "lambda"):
        return "custom"
    params = [p for p in v.get("params") or [] if isinstance(p, str)]
    body = v.get("body")
    if isinstance(body, list) and not all(isinstance(x, dict) and x.get("k") == "return" for x in body):
        return "custom"      # a block that does anything besides return may verify the token first
    rets = [body] if isinstance(body, dict) else [n.get("value") for n in walk(body) if n.get("k") == "return"]
    if not params or not rets:
        return "custom"

    def wraps(r) -> bool:
        return (isinstance(r, dict) and r.get("k") == "new"
                and str(r.get("type") or "").split(".")[-1] in _UNCHECKED_TOKEN_TYPES
                and len(r.get("args") or []) == 1 and isinstance(r["args"][0], dict)
                and r["args"][0].get("k") == "name" and r["args"][0].get("id") == params[0])
    return "unchecked" if all(wraps(r) for r in rets) else "custom"


def _validation(opts: list[Opt], c: PipeCall, conf, add) -> None:
    """DNL-SESS-010 and DNL-SESS-011 over the settings of one TokenValidationParameters."""
    title = "Token validation switched off"
    for leaf, sev, what in _VALIDATE_FLAGS:
        o, uncertain = verdict(opts, leaf, bad=lambda x: _flag_kind(x) != "good")
        if o is None or _flag_kind(o) == "good":
            continue
        name = next((x.path for x in opts if x.path.lower() == leaf), leaf)
        if _flag_kind(o) == "bad" and not uncertain:
            add("DNL-SESS-010", sev, title,
                f"{_TVP}.{name} is false, so {what}. Leave it at its default (true).", c, o.line, conf)
        elif _flag_kind(o) == "bad":
            add("DNL-SESS-010", sev, title,
                f"{_TVP}.{name} is false, so {what}, but some assignment to it sits under a condition, so it "
                "may not apply in Production; confirm.", c, o.line, "REVIEW")
        else:
            add("DNL-SESS-010", sev, title,
                f"{_TVP}.{name} is set from {_text(o.value)}, which is not a compile-time value, so it may be "
                f"false in Production (then {what}); confirm it is true.", c, o.line, "REVIEW")
    o, uncertain = verdict(opts, "signaturevalidator", bad=lambda x: _signature_kind(x) != "good")
    if o is not None and _signature_kind(o) != "good":
        if _signature_kind(o) == "unchecked" and not uncertain:
            add("DNL-SESS-010", "high", title,
                f"{_TVP}.SignatureValidator returns the token it is given without checking its signature, so a "
                "forged token passes. Remove it, or verify the signature before returning.", c, o.line, conf)
        else:
            add("DNL-SESS-010", "high", title,
                f"{_TVP}.SignatureValidator replaces the signature check with code this rule cannot prove "
                "verifies the token (or assigns it only under a condition); confirm it does.", c, o.line, "REVIEW")
    o, uncertain = verdict(opts, "clockskew", bad=lambda x: _skew_kind(x) != "good")
    if o is not None and _skew_kind(o) != "good":
        low = "Token clock skew over ten minutes"
        if _skew_kind(o) == "bad" and not uncertain:
            m = timespan_minutes(o.value)
            span = f"{m:g} minutes" if m is not None else _text(o.value)
            add("DNL-SESS-011", "low", low,
                f"{_TVP}.ClockSkew is {span}, so a token stays valid for that long after it expires. Keep it "
                f"to {_MAX_SKEW_MINUTES} minutes or less.", c, o.line, conf)
        else:
            add("DNL-SESS-011", "low", low,
                f"{_TVP}.ClockSkew is {_text(o.value)}, which is not a compile-time span of {_MAX_SKEW_MINUTES} "
                "minutes or less (or is set under a condition); confirm it is short.", c, o.line, "REVIEW")


def _https_metadata(opts: list[Opt], c: PipeCall, conf, add) -> None:
    o, uncertain = verdict(opts, "requirehttpsmetadata", bad=lambda x: _flag_kind(x) != "good")
    if o is None or _flag_kind(o) == "good":
        return
    title = "OIDC metadata may be fetched over HTTP"
    if _flag_kind(o) == "bad" and not uncertain:
        add("DNL-CFG-012", "medium", title,
            "RequireHttpsMetadata is false, so the signing keys and issuer metadata can be fetched over plain "
            "HTTP and swapped by anyone on the network path. Leave it true outside Development.",
            c, o.line, conf)
    else:
        why = (" but some assignment to it sits under a condition" if _flag_kind(o) == "bad"
               else f" from {_text(o.value)}, which is not a compile-time value")
        add("DNL-CFG-012", "medium", title,
            f"RequireHttpsMetadata is set{why}, so it may be false in Production; confirm it is true.",
            c, o.line, "REVIEW")


def _token_options(ctx: Ctx, c: PipeCall, conf, add) -> None:
    node = _prune(c.node)
    probe = _without_config_sections(node) if c.name in _MS_IDENTITY_CALLS else node
    reason = None if c.name == "AddCookie" else opaque_reason(probe)
    if reason is not None:
        for cid, sev, title, what in (
                ("DNL-SESS-010", "medium", "Token validation could not be read", "validation switches"),
                ("DNL-SESS-011", "low", "Token clock skew could not be read", "ClockSkew"),
                ("DNL-CFG-012", "medium", "OIDC metadata may be fetched over HTTP", "RequireHttpsMetadata")):
            add(cid, sev, title, f"The {what} of {c.name} could not be read: {reason}. Confirm token validation "
                                 "is fully on, ClockSkew is short and RequireHttpsMetadata is true.",
                c, c.line, "REVIEW")
    opts = options_of(node)
    _https_metadata(opts, c, conf, add)
    if c.name == "AddCookie":
        return
    tvp, unreadable = _tvp_settings(ctx, c, node, opts)
    for why, line in unreadable:
        for cid, sev in (("DNL-SESS-010", "medium"), ("DNL-SESS-011", "low")):
            add(cid, sev, "Token validation could not be read",
                f"{_TVP} of {c.name} could not be read: {why}. Confirm token validation is fully on and "
                "ClockSkew is ten minutes or less.", c, line, "REVIEW")
    _validation(tvp, c, conf, add)


def _settings_https(ctx: Ctx, pipe: Pipeline, add_cfg) -> None:
    """`RequireHttpsMetadata` (any section) in the effective Production settings of the pipeline's project."""
    scope = _scope_of(ctx, pipe)
    if scope is None:
        return
    for key, e in ctx.settings.effective("Production", scope).items():
        if key.split(":")[-1] != "requirehttpsmetadata" or e.value is None:
            continue
        text = str(e.value).strip().lower()
        if e.value is True or text == "true":
            continue
        firm = e.value is False or text == "false"
        desc = (f"{e.key} is false in the Production configuration, so signing keys and issuer metadata can be "
                "fetched over plain HTTP. Leave it true outside Development." if firm else
                f"{e.key} is {e.value!r} in the Production configuration, which could not be read as a boolean, "
                "so metadata may be fetched over plain HTTP; confirm it is true.")
        add_cfg(desc, e.file, e.line, None if firm else "REVIEW")


# -- DNL-SEC-004: a symmetric signing key written in code -----------------------------------------------

_BYTE_SOURCES = {"getbytes": "encoding", "frombase64string": "convert", "fromhexstring": "convert",
                 "decodebytes": "any", "base64urldecode": "any"}


def _env_walk(node, state: str = "run"):
    """Pre-order (node, state) with state "run" (runs in Production), "skip" (Development only) or "review"
    (under an environment condition that could not be parsed). Conditions that read no environment keep the
    state: a key under an ordinary `if` still sits in the code."""
    if isinstance(node, list):
        for x in node:
            yield from _env_walk(x, state)
        return
    if not isinstance(node, dict):
        return
    yield node, state
    k = node.get("k")
    t_state = e_state = state
    t_key, e_key = ("then", "else") if k == "if" else ("t", "f")
    if k in ("if", "cond"):
        pred = _pred(node.get("cond" if k == "if" else "c"), {}, _Ctx())
        if pred is not None and state != "skip":
            t_runs, e_runs = _env_branches(pred)
            t_state = "review" if t_runs is None else "run" if t_runs else "skip"
            e_state = "review" if e_runs is None else "run" if e_runs else "skip"
    for key, v in node.items():
        if isinstance(v, (dict, list)):
            yield from _env_walk(v, t_state if key == t_key else e_state if key == e_key else state)


def _is_literal_key(text: str) -> bool:
    """A whole-value placeholder (empty, `<...>`, `{...}`, `$(...)`, `#{...}`, `__x__`, `***`) is not a key."""
    t = text.strip()
    return not (PLACEHOLDER.match(t) or re.fullmatch(r"<[^>]*>|\{[^}]*\}", t))


def _local_literal(body, name: str) -> tuple[str | None, bool]:
    """(literal, reassigned): the literal a local is initialised with, when every declaration of it is a
    literal; `reassigned` when something also assigns it a non-literal (the key may come from elsewhere)."""
    vals, reassigned = [], False
    for n in walk(body):
        if n.get("k") == "local" and n.get("name") == name:
            vals.append(const_str(n.get("init")))
        elif (n.get("k") == "assign" and isinstance(n.get("target"), dict) and n["target"].get("k") == "name"
              and n["target"].get("id") == name and const_str(n.get("value")) is None):
            reassigned = True
    return (vals[0], reassigned) if vals and all(v is not None for v in vals) else (None, False)


def _assigned_elsewhere(model, t, name: str) -> bool:
    """True when a non-literal is assigned to the field `name` of `t`: a bare `name = v` in a method,
    constructor or accessor of the type, or any `x.name = v` member assignment in the solution. (The IR
    does not say `readonly`, so a reassignment is the only sign the field is not constant.)"""
    own = t.name.split(".")[-1]
    for f in model.files.values():
        for ot in f.types:
            bodies = [m.body for m in ot.methods]
            for p in ot.properties:
                bodies += [b for b in (p.get, p.set) if b]
            for body in bodies:
                for n in walk(body):
                    if n.get("k") != "assign" or n.get("op") != "=" or const_str(n.get("value")) is not None:
                        continue
                    tgt = n.get("target")
                    if not isinstance(tgt, dict):
                        continue
                    if tgt.get("k") == "member" and tgt.get("name") == name:
                        return True
                    if tgt.get("k") == "name" and tgt.get("id") == name and ot.name.split(".")[-1] == own:
                        return True
    return False


def _field_literal(model, t, name: str) -> tuple[str | None, bool]:
    """(literal, reassigned) for a field of type `t` initialised with a literal."""
    f = next((x for x in t.fields if x.name == name), None)
    lit = const_str(f.init) if f is not None else None
    if lit is None:
        return None, False
    return lit, _assigned_elsewhere(model, t, name)


def _literal_of(model, t, body, e) -> tuple[str | None, bool]:
    """(literal, maybe-not-constant) an expression stands for, resolved one level: a literal, a local or
    field of the enclosing type, or `Type.Member`. (None, False) when it is not a literal source."""
    lit = const_str(e)
    if lit is not None or not isinstance(e, dict):
        return lit, False
    if e.get("k") == "name":
        got = _local_literal(body, e.get("id") or "")
        return got if got[0] is not None else _field_literal(model, t, e.get("id") or "")
    if e.get("k") == "member":
        parts = receiver_text(e).split(".")
        if len(parts) >= 2:
            owner = t.name.split(".")[-1] if parts[-2] == "this" else parts[-2]
            for ot in ([t] if owner == t.name.split(".")[-1] else []) + list(model.find_types(owner)):
                got = _field_literal(model, ot, parts[-1])
                if got[0] is not None:
                    return got
    return None, False


def _partial_literal(e) -> str | None:
    """The first string fragment of an expression that mixes a literal with something unknown: a `+`
    concatenation or an interpolated string. None for anything else (an index key such as config["K"] is
    not a fragment of the value)."""
    if not isinstance(e, dict):
        return None
    if e.get("k") == "bin" and e.get("op") in ("+", "&", "concat"):
        for side in (e.get("l"), e.get("r")):
            got = literal_str(side) or _partial_literal(side)
            if got:
                return got
        return None
    if e.get("k") == "interp":
        for part in e.get("parts") or []:
            got = literal_str(part)
            if got:
                return got
    return None


def _bytes_literal(model, t, body, call) -> tuple[str | None, bool | str]:
    """(literal, maybe) behind `Encoding.*.GetBytes(x)` / `Convert.From*String(x)`; maybe is "partial" when
    x only has a literal part. (None, False) for any other call."""
    kind = _BYTE_SOURCES.get((call_name(call) or "").lower())
    fn = call.get("fn") if isinstance(call.get("fn"), dict) else {}
    recv = receiver_text(fn.get("obj")) or str((fn.get("obj") or {}).get("type") or "")
    if kind is None or not call.get("args"):
        return None, False
    if (kind == "encoding" and "Encoding" not in recv) or (kind == "convert" and not recv.endswith("Convert")):
        return None, False
    lit, maybe = _literal_of(model, t, body, call["args"][0])
    if lit is None:
        part = _partial_literal(call["args"][0])
        return (part, "partial") if part else (None, False)
    return lit, maybe


def _byte_holder(model, t, body, name: str) -> tuple[str | None, bool | str]:
    """The byte[] local or field `name` resolved to the call that initialises it. A local also assigned
    something that is not a byte-source literal, or a field assigned elsewhere, is "maybe" (REVIEW)."""
    inits = [n.get("init") for n in walk(body) if n.get("k") == "local" and n.get("name") == name]
    if not inits:
        f = next((x for x in t.fields if x.name == name), None)
        inits = [f.init] if f is not None and f.init is not None else []
        is_field = True
    else:
        is_field = False
    got = [_bytes_literal(model, t, body, i) if isinstance(i, dict) and i.get("k") == "call" else (None, False)
           for i in inits]
    if not got or any(g[0] is None for g in got):
        return None, False
    lit, maybe = got[0]
    for n in walk(body):
        if (n.get("k") == "assign" and isinstance(n.get("target"), dict) and n["target"].get("k") == "name"
                and n["target"].get("id") == name):
            v = n.get("value")
            if not (isinstance(v, dict) and v.get("k") == "call" and _bytes_literal(model, t, body, v)[0] is not None):
                maybe = maybe or True
    if is_field and not maybe and _assigned_elsewhere(model, t, name):
        maybe = True
    return lit, maybe


def _key_literal(model, t, body, new: dict) -> tuple[str | None, bool | str]:
    """(literal, maybe-not-constant) behind `new SymmetricSecurityKey(<bytes>)`: Encoding.*.GetBytes(x),
    Convert.FromBase64String(x) and the like, directly or through a byte[] local or field. (None, False)
    for any other source (configuration, environment, Key Vault, a parameter)."""
    args = new.get("args") or []
    if len(args) != 1 or not isinstance(args[0], dict):
        return None, False
    if args[0].get("k") == "name":
        return _byte_holder(model, t, body, args[0].get("id") or "")
    if args[0].get("k") != "call":
        return None, False
    return _bytes_literal(model, t, body, args[0])


def _symmetric_news(root):
    """((new node, state), ...) of every `new SymmetricSecurityKey(...)` under root, including the target-typed
    `new(...)` of a local declared SymmetricSecurityKey or assigned to IssuerSigningKey."""
    seen: set = set()
    for n, state in _env_walk(root):
        found = []
        k = n.get("k")
        if k == "new" and str(n.get("type") or "").split(".")[-1] == "SymmetricSecurityKey":
            found.append(n)
        elif k == "local" and str(n.get("type") or "").split(".")[-1] == "SymmetricSecurityKey":
            found.append(n.get("init"))
        elif k == "assign" and isinstance(n.get("target"), dict) and n["target"].get("name") == "IssuerSigningKey":
            found.append(n.get("value"))
        if k == "new":
            found += [e.get("value") for e in n.get("init") or []
                      if isinstance(e, dict) and e.get("name") == "IssuerSigningKey"]
        for f in found:
            typed = not f.get("type") or str(f["type"]).split(".")[-1] == "SymmetricSecurityKey" if isinstance(f, dict) else False
            if typed and f.get("k") == "new" and id(f) not in seen:
                seen.add(id(f))
                yield f, state


def _signing_keys(ctx: Ctx) -> None:
    seen: set = set()
    for f in ctx.model.files.values():
        for t in f.types:
            roots = [(m.body, m.body) for m in t.methods]
            for p in t.properties:
                roots += [(b, b) for b in (p.get, p.set) if b]
                if p.init is not None:
                    roots.append((p.init, []))
            roots += [(fl.init, []) for fl in t.fields if fl.init is not None]
            for root, body in roots:
                for new, state in _symmetric_news(root):
                    lit, maybe = _key_literal(ctx.model, t, body, new)
                    key = (t.file, new.get("line"))
                    if lit is None or not _is_literal_key(lit) or state == "skip" or key in seen:
                        continue
                    seen.add(key)
                    desc = ("The symmetric key that signs and verifies tokens is a string written in the source, "
                            "so anyone with the code (or the compiled assembly) can forge tokens. Load the key "
                            "from configuration, an environment variable or a key vault.")
                    if state == "review":
                        desc += " The code sits under an environment condition that could not be parsed."
                    if maybe == "partial":
                        desc += (" Only part of the key is a literal (the rest is concatenated or interpolated), "
                                 "so confirm what the rest of the key is.")
                    elif maybe:
                        desc += (" The string is also assigned a non-literal value elsewhere, so the key may be "
                                 "loaded from configuration at run time; confirm which value is used.")
                    ctx.add("DNL-SEC-004", "high", _SEC004_TITLE, desc, t.file, new.get("line") or t.line,
                            confidence="REVIEW" if state == "review" or maybe else None)


def check_tokens(ctx: Ctx) -> None:
    seen: set = set()

    def add(cid: str, sev: str, title: str, desc: str, c: PipeCall, line: int, conf: str | None) -> None:
        if c.runs_in("Production") is None:
            conf = "REVIEW"
            desc += " The call sits under an environment condition that could not be parsed."
        key = (cid, c.file, line, conf, title, desc)
        if key not in seen:
            seen.add(key)
            ctx.add(cid, sev, title, desc, c.file, line, confidence=conf)

    for pipe in ctx.pipes:
        for c, conf in _token_calls(ctx, pipe):
            _token_options(ctx, c, conf, add)

        def add_cfg(desc, file, line, conf) -> None:
            key = ("DNL-CFG-012", file, line)
            if key not in seen:
                seen.add(key)
                ctx.add("DNL-CFG-012", "medium", "OIDC metadata may be fetched over HTTP", desc, file, line,
                        confidence=conf)
        _settings_https(ctx, pipe, add_cfg)
    _signing_keys(ctx)


# -- Identity options (DNL-SEC-005, DNL-SEC-006, DNL-SEC-007) -------------------------------------------

# Calls whose options lambda carries IdentityOptions; `Configure<T>` / `PostConfigure<T>` count only for it.
_IDENTITY_CALLS = ("AddIdentity", "AddDefaultIdentity", "AddIdentityCore", "Configure", "PostConfigure")
_MIN_PASSWORD_LENGTH = 8       # the framework default is 6: an unset RequiredLength is not reported
_MAX_LOCKOUT_ATTEMPTS = 20
_COMPLEXITY = {"password.requiredigit": "a digit", "password.requirelowercase": "a lower-case letter",
               "password.requireuppercase": "an upper-case letter",
               "password.requirenonalphanumeric": "a non-alphanumeric character"}
_CONFIRMED = {"signin.requireconfirmedaccount": "RequireConfirmedAccount",
              "signin.requireconfirmedemail": "RequireConfirmedEmail"}
# The sub-objects of IdentityOptions the rules read, and the id each one feeds.
_IDENTITY_PARTS = {"password": "DNL-SEC-005", "lockout": "DNL-SEC-006", "signin": "DNL-SEC-007"}
_IDENTITY_META = {"DNL-SEC-005": ("medium", "Weak Identity password policy", "password options"),
                  "DNL-SEC-006": ("medium", "Account lockout disabled or too lenient", "lockout options"),
                  "DNL-SEC-007": ("low", "Identity does not require a confirmed account", "sign-in options")}
# Parameter position of `lockoutOnFailure` in SignInManager.PasswordSignInAsync(user|userName, password,
# isPersistent, lockoutOnFailure) and CheckPasswordSignInAsync(user, password, lockoutOnFailure).
_SIGNIN_LOCKOUT_INDEX = {"PasswordSignInAsync": 3, "CheckPasswordSignInAsync": 2}


def _identity_calls(ctx: Ctx, pipe: Pipeline) -> list[tuple[PipeCall, str | None]]:
    def wanted(c: PipeCall) -> bool:
        if c.name not in ("Configure", "PostConfigure"):
            return True
        targs = (c.node.get("fn") or {}).get("targs") or []
        if any(str(x).strip().split(".")[-1] == "IdentityOptions" for x in targs):
            return True
        # services.AddOptions<IdentityOptions>().Configure(o => ...): the type argument sits on the receiver.
        obj = (c.node.get("fn") or {}).get("obj")
        while isinstance(obj, dict) and obj.get("k") == "call":
            fn = obj.get("fn") if isinstance(obj.get("fn"), dict) else {}
            if call_name(obj) == "AddOptions" and any(
                    str(x).strip().split(".")[-1] == "IdentityOptions" for x in fn.get("targs") or []):
                return True
            obj = fn.get("obj")
        return False
    return [(c, conf) for c, conf in _calls(ctx, pipe, *_IDENTITY_CALLS) if wanted(c)]


def _int_kind(o: Opt, limit: int, bad_above: bool) -> str:
    """"bad" | "good" | "unknown" for an integer setting against a limit: below `limit` is bad (a minimum),
    or above it when `bad_above` (a maximum)."""
    v = const(o.value)
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return "unknown"
    return "bad" if (v > limit if bad_above else v < limit) else "good"


def _identity_options(c: PipeCall, conf, add) -> None:
    node = _prune(c.node)
    reason = opaque_reason(node)
    if reason is not None:
        for cid, (sev, title, what) in _IDENTITY_META.items():
            add(cid, sev, title, f"The {what} of {c.name} could not be read: {reason}. Confirm the password "
                                 "length and complexity, lockout and account confirmation are enforced.",
                c, c.line, "REVIEW")
    opts = options_of(node)
    for o in opts:        # o.Password = Build(); the whole sub-object comes from elsewhere
        cid = _IDENTITY_PARTS.get(o.path.lower())
        if cid is not None and not (isinstance(o.value, dict) and o.value.get("k") == "new"):
            sev, title, what = _IDENTITY_META[cid]
            add(cid, sev, title, f"o.{o.path} is assigned {_text(o.value)}, so its settings cannot be read; "
                                 f"confirm the {what} are safe.", c, o.line, "REVIEW")
    _password(opts, c, conf, add)
    _lockout(opts, c, conf, add)
    _confirmed(opts, c, conf, add)


def _password(opts: list[Opt], c: PipeCall, conf, add) -> None:
    sev, title, _ = _IDENTITY_META["DNL-SEC-005"]
    o, uncertain = verdict(opts, "password.requiredlength",
                           bad=lambda x: _int_kind(x, _MIN_PASSWORD_LENGTH, False) != "good")
    if o is not None and _int_kind(o, _MIN_PASSWORD_LENGTH, False) != "good":
        if _int_kind(o, _MIN_PASSWORD_LENGTH, False) == "bad" and not uncertain:
            add("DNL-SEC-005", sev, title,
                f"Password.RequiredLength is {const(o.value)}, below {_MIN_PASSWORD_LENGTH}, so short passwords "
                f"are accepted and fall quickly to guessing. Require at least {_MIN_PASSWORD_LENGTH}.",
                c, o.line, conf)
        else:
            why = ("is set under a condition" if _int_kind(o, _MIN_PASSWORD_LENGTH, False) == "bad"
                   else f"is set from {_text(o.value)}, which is not a compile-time value")
            add("DNL-SEC-005", sev, title,
                f"Password.RequiredLength {why}, so it may be below {_MIN_PASSWORD_LENGTH} in Production; "
                "confirm it is not.", c, o.line, "REVIEW")
    for path, what in _COMPLEXITY.items():
        same = [x for x in opts if x.path.lower() == path]
        for i, x in enumerate(same):
            kind = _flag_kind(x)
            if kind == "good":
                continue
            later = same[i + 1:]
            if any(_flag_kind(y) == "good" and not y.conditional for y in later):
                continue        # switched on again unconditionally
            if kind == "unknown":
                # Not a compile-time value: unknown is never clean, so it is REVIEW (a literal false
                # assigned earlier is reported on its own line).
                add("DNL-SEC-005", "low", title,
                    f"{x.path} is set from {_text(x.value)}, which is not a compile-time value, so passwords "
                    f"may not need {what} in Production; confirm it is true.", c, x.line, "REVIEW")
                continue
            firm = not x.conditional and not any(_flag_kind(y) == "good" for y in later)
            desc = f"{x.path} is false, so passwords need not contain {what}."
            if not firm:
                desc += " Some assignment to it sits under a condition, so it may not apply; confirm."
            add("DNL-SEC-005", "low", title, desc, c, x.line, conf if firm else "REVIEW")


def _lockout(opts: list[Opt], c: PipeCall, conf, add) -> None:
    sev, title, _ = _IDENTITY_META["DNL-SEC-006"]
    o, uncertain = verdict(opts, "lockout.allowedfornewusers", bad=lambda x: _flag_kind(x) != "good")
    if o is not None and _flag_kind(o) != "good":
        if _flag_kind(o) == "bad" and not uncertain:
            add("DNL-SEC-006", sev, title,
                "Lockout.AllowedForNewUsers is false, so new accounts are never locked out and a password can be "
                "guessed without limit. Leave it true.", c, o.line, conf)
        else:
            why = ("is false under a condition" if _flag_kind(o) == "bad"
                   else f"is set from {_text(o.value)}, which is not a compile-time value")
            add("DNL-SEC-006", sev, title,
                f"Lockout.AllowedForNewUsers {why}, so lockout may be off in Production; confirm it is true.",
                c, o.line, "REVIEW")
    o, uncertain = verdict(opts, "lockout.maxfailedaccessattempts",
                           bad=lambda x: _int_kind(x, _MAX_LOCKOUT_ATTEMPTS, True) != "good")
    if o is not None and _int_kind(o, _MAX_LOCKOUT_ATTEMPTS, True) != "good":
        if _int_kind(o, _MAX_LOCKOUT_ATTEMPTS, True) == "bad" and not uncertain:
            add("DNL-SEC-006", sev, title,
                f"Lockout.MaxFailedAccessAttempts is {const(o.value)}, so an attacker gets that many guesses per "
                f"account before the lockout (over {_MAX_LOCKOUT_ATTEMPTS}). Keep it at {_MAX_LOCKOUT_ATTEMPTS} or "
                "fewer.", c, o.line, conf)
        else:
            why = ("is set under a condition" if _int_kind(o, _MAX_LOCKOUT_ATTEMPTS, True) == "bad"
                   else f"is set from {_text(o.value)}, which is not a compile-time value")
            add("DNL-SEC-006", sev, title,
                f"Lockout.MaxFailedAccessAttempts {why}, so it may be over {_MAX_LOCKOUT_ATTEMPTS} in Production; "
                "confirm it is not.", c, o.line, "REVIEW")


def _confirmed(opts: list[Opt], c: PipeCall, conf, add) -> None:
    sev, title, _ = _IDENTITY_META["DNL-SEC-007"]
    for path, name in _CONFIRMED.items():
        # A conditional good value never clears a bad one; a known false followed by an unknown value
        # leaves the unknown as the effective one, which is REVIEW (unknown is never clean).
        o, uncertain = verdict(opts, path, bad=lambda x: _flag_kind(x) != "good")
        if o is None or _flag_kind(o) == "good":
            continue            # absent (not reported) or true
        if _flag_kind(o) == "unknown":
            add("DNL-SEC-007", sev, title,
                f"SignIn.{name} is set from {_text(o.value)}, which is not a compile-time value, so it may be "
                "false in Production; confirm it is true.", c, o.line, "REVIEW")
            continue
        desc = (f"SignIn.{name} is false, so an account can sign in before its owner proves control of the "
                "address. Set it true.")
        if uncertain:
            desc += " Some assignment to it sits under a condition, so it may not apply; confirm."
        add("DNL-SEC-007", sev, title, desc, c, o.line, "REVIEW" if uncertain else conf)


def _signin_calls(ctx: Ctx, add_code) -> None:
    """PasswordSignInAsync / CheckPasswordSignInAsync calls (any receiver) anywhere in the solution's code."""
    for f in ctx.model.files.values():
        for t in f.types:
            roots = [m.body for m in t.methods]
            for p in t.properties:
                roots += [b for b in (p.get, p.set) if b]
                if p.init is not None:
                    roots.append(p.init)
            roots += [fl.init for fl in t.fields if fl.init is not None]
            for root in roots:
                for n, state in _env_walk(root):
                    idx = _SIGNIN_LOCKOUT_INDEX.get(call_name(n) or "") if n.get("k") == "call" else None
                    if idx is None or state == "skip":
                        continue
                    args, named = n.get("args") or [], n.get("named") or {}
                    arg = named["lockoutOnFailure"] if "lockoutOnFailure" in named else (
                        args[idx] if len(args) > idx else None)
                    name = call_name(n)
                    if arg is None:
                        if len(args) + len(named) < 2:
                            continue        # not the Identity shape (user, password, ...)
                        # The framework overloads take lockoutOnFailure with no default, so a call without it
                        # is a wrapper or extension whose default (often false) this rule cannot see.
                        add_code(t, n, state, "REVIEW", f"{name} is called without a lockoutOnFailure argument; "
                                 "the Identity methods require one, so this is a wrapper whose default is not "
                                 "visible here. Confirm it passes lockoutOnFailure: true.")
                        continue
                    v = const(arg)
                    if v is True:
                        continue
                    if v is False:
                        add_code(t, n, state, None, f"{name} passes lockoutOnFailure: false, so failed password "
                                 "attempts are never counted and the account is never locked out, which allows "
                                 "unlimited password guessing. Pass true.")
                    else:
                        add_code(t, n, state, "REVIEW", f"{name} passes lockoutOnFailure from {_text(arg)}, which "
                                 "is not a compile-time value, so lockout may be off; confirm it is true.")


def check_identity(ctx: Ctx) -> None:
    seen: set = set()

    def add(cid: str, sev: str, title: str, desc: str, c: PipeCall, line: int, conf: str | None) -> None:
        if c.runs_in("Production") is None:
            conf = "REVIEW"
            desc += " The call sits under an environment condition that could not be parsed."
        key = (cid, c.file, line, conf, desc)
        if key not in seen:
            seen.add(key)
            ctx.add(cid, sev, title, desc, c.file, line, confidence=conf)

    for pipe in ctx.pipes:
        for c, conf in _identity_calls(ctx, pipe):
            _identity_options(c, conf, add)

    def add_code(t, n: dict, state: str, conf: str | None, desc: str) -> None:
        if state == "review":
            conf = "REVIEW"
            desc += " The call sits under an environment condition that could not be parsed."
        line = n.get("line") or t.line
        key = ("DNL-SEC-006", t.file, line, desc)
        if key not in seen:
            seen.add(key)
            sev, title, _ = _IDENTITY_META["DNL-SEC-006"]
            ctx.add("DNL-SEC-006", sev, title, desc, t.file, line, confidence=conf)
    _signin_calls(ctx, add_code)
