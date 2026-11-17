"""Authentication-related ASP.NET Core configuration rules, called from the rules_pipeline aggregator.

Groups: cookies and session (DNL-SESS-001/002/003 reused, DNL-SESS-009). Later tasks add antiforgery,
token validation and Identity groups to this module.

Like the other rules_pipeline* modules it must not import rules_auth_core (static inventory test);
shared helpers live in auth_core.py.
"""
from __future__ import annotations

from checks.dnl.cfgctx import Ctx
from checks.dnl.options import Opt, const, opaque_reason, options_of, timespan_minutes, verdict
from checks.dnl.pipeline import PipeCall, Pipeline

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
