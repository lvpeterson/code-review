"""web.config rules for the legacy .NET analyzer.

Every rule is evaluated on the base config and on each transformed variant
(Web.Release.config etc.); the merge step then decides the severity: a risky
setting that a release transform removes is only a local/debug concern.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from checks.dnl.findings import dnl_finding
from checks.dnl.webconfig import LINE, NOTES, ORIGIN, WebConfig, anonymous_denied, config_chain, effective
from core.models import Finding

# A placeholder is a whole-value token. `{...}` only counts as a single `{identifier}`:
# ADO.NET lets a braced value hold anything (`Password={Secr3t;x}`).
_PLACEHOLDER = re.compile(r"(?i)^(\$\(.*\)|\{[a-z_]\w*\}|#\{.*\}|__.*__|\*+|x+|)$")
# Value is a braced or single-quoted ADO.NET token, else it runs to the next `;`.
_CONN_PW = re.compile(r"(?i)\b(password|pwd)\s*=\s*(\{[^}]*\}?|'[^']*'?|[^;\"]+)")
_SECRET_KEY = re.compile(r"(?i)password|pwd|secret|apikey|api_key|token|privatekey|clientsecret")
# Keys that name a secret but hold a setting about it (PasswordResetUrl, TokenExpiration...).
_SETTING_WORDS = {"url", "regex", "length", "format", "minimum", "required", "attempts", "window", "policy"}
_WORD_SPLIT = re.compile(r"[_\-. ]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _is_setting_key(key: str) -> bool:
    """True when a word of the key (split on camelCase, `_`, `-`, `.`) names a setting:
    `Password_Format`, `PasswordResetUrl` -- but not `InformationApiKey` ("Information"
    merely contains "format")."""
    return any(w.lower() in _SETTING_WORDS or w.lower().startswith("expir")
               for w in _WORD_SPLIT.split(key) if w)


# Response-wide settings: reported on app-root configs only, not on every
# subfolder Web.config that just carries an <authorization> block.
_ROOT_ONLY = {"DNL-CFG-005", "DNL-CFG-006", "DNL-SESS-002"}
# Exempt from the R3 info downgrade: removing them in a release transform leaves them in source control.
_COMMITTED_SECRETS = {"DNL-SEC-001", "DNL-SEC-002"}
_SEC_HEADERS = ("X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security", "Content-Security-Policy")

# (rule id, severity, title, description, anchor element)
Hit = tuple[str, str, str, str, ET.Element]


def _low(el: ET.Element | None, attr: str) -> str:
    return (el.get(attr, "") if el is not None else "").strip().lower()


def _int(v: str | None) -> int | None:
    try:
        return int((v or "").strip())
    except ValueError:
        return None


def _eval(root: ET.Element, variant: str, cfg: WebConfig, configs: list[WebConfig],
          aspx_here: bool) -> list[Hit]:
    out: list[Hit] = []

    def add(cid, sev, title, desc, el):
        out.append((cid, sev, title, desc, el))

    sw = root.find("system.web")

    comp = root.find("system.web/compilation")
    if _low(comp, "debug") == "true":
        add("DNL-CFG-001", "medium", "Compilation debug mode enabled",
            "compilation debug=\"true\" disables optimizations and request timeouts and leaks diagnostics; "
            "make sure production builds set it to false.", comp)

    ce = root.find("system.web/customErrors")
    if _low(ce, "mode") == "off":
        add("DNL-CFG-002", "medium", "Custom errors disabled",
            "customErrors mode=\"Off\" returns stack traces and server details to remote users.", ce)
    he = root.find("system.webServer/httpErrors")
    if _low(he, "errorMode") == "detailed":
        add("DNL-CFG-002", "medium", "Detailed IIS error pages enabled",
            "httpErrors errorMode=\"Detailed\" returns detailed error information to remote users.", he)

    tr = root.find("system.web/trace")
    if _low(tr, "enabled") == "true":
        remote = _low(tr, "localOnly") == "false"
        add("DNL-CFG-003", "high" if remote else "medium", "ASP.NET tracing enabled",
            "trace enabled=\"true\" exposes request, session and server variables via trace.axd"
            + (" and localOnly=\"false\" makes them reachable remotely." if remote else "."), tr)

    es = root.find("elmah/security")
    if _low(es, "allowRemoteAccess") in ("true", "yes", "1"):
        add("DNL-CFG-004", "high", "ELMAH remote access enabled",
            "elmah/security allowRemoteAccess lets any remote user read the error log, which contains "
            "request data, cookies and stack traces.", es)

    hr = root.find("system.web/httpRuntime")
    if sw is not None and _low(hr, "enableVersionHeader") != "false":
        add("DNL-CFG-005", "low", "ASP.NET version header not disabled",
            "httpRuntime enableVersionHeader is not \"false\", so responses carry X-AspNet-Version.",
            hr if hr is not None else sw)

    ch = root.find("system.webServer/httpProtocol/customHeaders")
    names = {(a.get("name") or "").strip().lower() for a in (ch.findall("add") if ch is not None else [])}
    missing = [h for h in _SEC_HEADERS if h.lower() not in names]
    if sw is not None and missing:
        add("DNL-CFG-006", "low", "Security response headers missing",
            "customHeaders does not set: " + ", ".join(missing) + ".", sw)
    if ch is not None:
        for a in ch.findall("add"):
            if _low(a, "name") == "access-control-allow-origin" and (a.get("value") or "").strip() == "*":
                add("DNL-CFG-007", "medium", "Wildcard CORS origin",
                    "Access-Control-Allow-Origin is \"*\", so any site can read responses.", a)

    pages = root.find("system.web/pages")
    if _low(pages, "validateRequest") == "false" and aspx_here:
        add("DNL-XSS-002", "medium", "Request validation disabled",
            "pages validateRequest=\"false\" turns off ASP.NET request validation for web forms pages.", pages)
    if _low(hr, "requestValidationMode").startswith("2."):
        add("DNL-XSS-002", "medium", "Legacy request validation mode",
            "httpRuntime requestValidationMode 2.x restricts validation to .aspx pages only.", hr)

    auth = root.find("system.web/authentication")
    forms = root.find("system.web/authentication/forms")
    if _low(auth, "mode") == "forms" and _low(forms, "requireSSL") != "true":
        add("DNL-SESS-001", "medium", "Forms authentication cookie not SSL-only",
            "forms requireSSL is not \"true\", so the auth cookie can be sent over HTTP.",
            forms if forms is not None else auth)

    hc = root.find("system.web/httpCookies")
    if sw is not None and (hc is None or _low(hc, "httpOnlyCookies") != "true"):
        add("DNL-SESS-002", "low", "HttpOnly cookies not enforced",
            "httpCookies httpOnlyCookies is not \"true\", so script can read cookies.",
            hc if hc is not None else sw)

    t = _int(forms.get("timeout")) if forms is not None else None
    if t is not None and t > 60:
        add("DNL-SESS-003", "low", "Long forms authentication timeout",
            f"forms timeout is {t} minutes; long-lived auth tickets widen the window for session theft.", forms)

    ss = root.find("system.web/sessionState")
    if _low(forms, "cookieless") in ("useuri", "autodetect"):
        add("DNL-SESS-004", "medium", "Cookieless forms authentication",
            "forms cookieless puts the auth ticket in the URL, where it leaks via logs and Referer.", forms)
    if _low(ss, "cookieless") in ("true", "useuri", "autodetect"):
        add("DNL-SESS-004", "medium", "Cookieless session state",
            "sessionState cookieless puts the session id in the URL, enabling fixation and leakage.", ss)

    for p in root.findall("system.web/membership/providers/add"):
        fmt = _low(p, "passwordFormat")
        if fmt in ("clear", "encrypted"):
            add("DNL-SESS-005", "high" if fmt == "clear" else "medium", "Weak membership password storage",
                f"Membership provider passwordFormat=\"{p.get('passwordFormat')}\" stores recoverable passwords; use Hashed.", p)

    if _low(pages, "enableViewStateMac") == "false":
        add("DNL-INT-001", "high", "ViewState MAC disabled",
            "pages enableViewStateMac=\"false\" allows tampering with (and deserialization attacks via) ViewState.", pages)

    mk = root.find("system.web/machineKey")
    if mk is not None and any(
            (mk.get(a) or "").strip() and not (mk.get(a) or "").strip().lower().startswith("autogenerate")
            for a in ("validationKey", "decryptionKey")):
        add("DNL-INT-002", "medium", "Hard-coded machineKey",
            "machineKey keys are fixed in the config; anyone with the file can forge ViewState and auth tickets.", mk)

    for a in root.findall("connectionStrings/add"):
        m = _CONN_PW.search(a.get("connectionString") or "")
        if m and not _PLACEHOLDER.match(m.group(2).strip()):
            add("DNL-SEC-001", "high", "Password in connection string",
                f"Connection string \"{a.get('name', '')}\" embeds a database password.", a)

    for a in root.findall("appSettings/add"):
        v = (a.get("value") or "").strip()
        key = a.get("key") or ""
        if (_SECRET_KEY.search(key) and not _is_setting_key(key)
                and len(v) >= 4 and not _PLACEHOLDER.match(v)):
            add("DNL-SEC-002", "medium", "Secret in appSettings",
                f"appSettings key \"{a.get('key')}\" holds a hard-coded secret value.", a)

    for h in root.findall("system.web/httpHandlers/add") + root.findall("system.webServer/handlers/add"):
        path = (h.get("path") or "").strip()
        if path.lower().endswith(("elmah.axd", "trace.axd")):
            url = "/" + re.sub(r"^(~?/)+", "", path.replace("\\", "/"))
            denied, _ = anonymous_denied(config_chain(configs, cfg.path.parent, cfg.path.parent, variant), url)
            add("DNL-INV-001", "low" if denied else "medium", "Diagnostic handler exposed",
                f"Handler \"{path}\" exposes diagnostics"
                + ("; anonymous access is denied by authorization rules." if denied
                   else " and no authorization rule denies anonymous users."), h)

    mrl = _int(hr.get("maxRequestLength")) if hr is not None else None
    lim = root.find("system.webServer/security/requestFiltering/requestLimits")
    mac = _int(lim.get("maxAllowedContentLength")) if lim is not None else None
    if mrl is not None and mrl > 102400:
        add("DNL-RES-001", "low", "Very large request limit",
            f"httpRuntime maxRequestLength is {mrl} KB (over 100 MB), easing resource exhaustion.", hr)
    if mac is not None and mac > 104857600:
        add("DNL-RES-001", "low", "Very large request limit",
            f"maxAllowedContentLength is {mac} bytes (over 100 MB), easing resource exhaustion.", lim)
    return out


def _within(d: Path, dirs: set[Path]) -> bool:
    d = d.resolve()
    return any(d == x or x in d.parents for x in (p.resolve() for p in dirs))


def _app_roots(configs: list[WebConfig], project_dirs: set[Path] | None) -> set[Path]:
    """Dirs of app-root configs: a config in a project dir, or -- outside every
    project dir (all of them when none are given) -- the shallowest config of its tree."""
    pdirs = {p.resolve() for p in project_dirs or ()}
    dirs = {c.path.parent.resolve() for c in configs if not c.is_views and c.root is not None}
    out = set()
    for d in dirs:
        if d in pdirs:
            out.add(d)
        elif not _within(d, pdirs) and not any(o in d.parents for o in dirs):
            out.add(d)
    return out


def check_configs(configs: list[WebConfig], api_surface_dirs: set[Path],
                  has_aspx_dirs: set[Path], *,
                  project_dirs: set[Path] | None = None) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    aspx = {p.resolve() for p in has_aspx_dirs}
    roots = _app_roots(configs, project_dirs)
    for cfg in configs:
        if cfg.is_views:
            continue
        if cfg.root is None:
            notes.append(f"{cfg.rel}: could not parse web.config ({cfg.error})")
            continue
        notes += [f"{cfg.rel}: transform skipped ({e})" for e in cfg.transform_errors]
        api = _within(cfg.path.parent, api_surface_dirs)
        app_root = cfg.path.parent.resolve() in roots
        variants = effective(cfg)
        for name, root in variants[1:]:
            if root.get(NOTES):
                notes.append(f"{cfg.rel}: Web.{name}.config: {root.get(NOTES)}")
        per: dict[str, dict[tuple, Hit]] = {}
        for name, root in variants:
            d: dict[tuple, Hit] = {}
            for h in _eval(root, name, cfg, configs, cfg.path.parent.resolve() in aspx):
                if h[0] in _ROOT_ONLY and not app_root:
                    continue
                d.setdefault((h[0], h[4].get(ORIGIN), h[4].get(LINE)), h)
            per[name] = d
        # R3: a Debug transform is local-only, so it never counts as removing
        # or keeping a setting for the release decision.
        released = [n for n, _ in variants[1:] if n.lower() != "debug"]
        emitted: dict[tuple, tuple[Hit, list[str]]] = {}
        for key, h in per["base"].items():
            emitted[key] = (h, [])
        for name, _ in variants[1:]:
            for key, h in per[name].items():
                if key not in per["base"]:
                    emitted.setdefault(key, (h, []))[1].append(name)
        for key, (h, intro) in emitted.items():
            cid, sev, title, desc, el = h
            if intro:
                desc += " Introduced by " + ", ".join(f"Web.{n}.config" for n in intro) + "."
            elif released:
                gone = [n for n in released if key not in per[n]]
                if len(gone) == len(released) and cid in _COMMITTED_SECRETS:
                    # A transform does not un-commit a secret: the base file still holds it.
                    desc += (" Overridden by the Web." + ", ".join(gone) +
                             ".config transform(s), but the value is still committed in the base Web.config.")
                elif len(gone) == len(released):
                    sev = "info"
                    desc += (" Removed by the Web." + ", ".join(gone) +
                             ".config transform(s); still present in the base Web.config used by local/debug builds.")
                elif gone:
                    desc += " Still present in: " + ", ".join(n for n in released if key in per[n]) + "."
            findings.append(dnl_finding(cid, sev, title, desc, el.get(ORIGIN, cfg.rel),
                                        int(el.get(LINE) or 0), api_surface=api))
    return findings, notes
