"""WCF binding and behavior configuration rules (DNL-WCF-001..004).

Evaluated on the base config and on each transformed variant, then merged by the same
transform-aware step as the web.config rules (`rules_config.merge_variants`), so a release
transform that turns `includeExceptionDetailInFaults` off leaves only an info finding.
Binding / behavior lookup reuses the helpers `auth` built for WCF operation auth.
"""
from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NamedTuple

from checks.dnl.auth import _BINDING_DEFAULTS, _binding_security, _sm
from checks.dnl.files import iter_dnl_files, read_source
from checks.dnl.rules_config import Hit, merge_variants
from checks.dnl.findings import dnl_finding
from checks.dnl.webconfig import LINE, ORIGIN, WebConfig, config_chain, effective
from core.models import Finding

_LIMIT = 10485760  # 10 MiB: above this a single message can exhaust memory
_SIZE_ATTRS = ("maxReceivedMessageSize", "maxBufferSize")
_QUOTA_ATTRS = ("maxStringContentLength", "maxArrayLength")
_LOCALHOST = {"localhost", "127.0.0.1", "[::1]", "::1"}
# Framework protocolMapping defaults (WCF 4+), used when <protocolMapping> has no entry for a scheme.
_DEFAULT_EP = "dnl_default_endpoint"  # marks an endpoint WCF 4+ synthesizes because the service configures none
_HTTP_ASSUMPTION = ("Assumes the site is served over plain http; confirm the IIS bindings (https-only sites use "
                    "basicHttpsBinding with Transport security).")
_DEFAULT_MAP = {"http": "basicHttpBinding", "https": "basicHttpsBinding",
                "net.tcp": "netTcpBinding", "net.pipe": "netNamedPipeBinding"}


def _low(el: ET.Element | None, attr: str) -> str:
    return (el.get(attr, "") if el is not None else "").strip().lower()


def _int(v: str | None) -> int | None:
    try:
        return int((v or "").strip())
    except ValueError:
        return None


def _is_mex(ep: ET.Element) -> bool:
    return (_low(ep, "contract").split(".")[-1] == "imetadataexchange"
            or _low(ep, "kind") == "mexendpoint" or _low(ep, "binding").startswith("mex"))


def _scheme(addr: str) -> str | None:
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", addr)
    return m.group(1) if m else None


def _is_local(ep: ET.Element) -> bool:
    """net.pipe, or an absolute address on the loopback host. Named pipes never leave the machine.
    A relative address (no scheme) inherits the host base address, so it is never exempt."""
    addr = _low(ep, "address")
    if addr.startswith("net.pipe://") or _low(ep, "binding") == "netnamedpipebinding":
        return True
    m = re.match(r"^[a-z][a-z0-9+.-]*://(\[[^\]]*\]|[^/:]*)", addr)
    return bool(m) and m.group(1) in _LOCALHOST


def _is_https(ep: ET.Element) -> bool:
    return _low(ep, "address").startswith("https://") or _low(ep, "binding") == "basichttpsbinding"


def _behavior(chain: list[ET.Element], name: str | None) -> ET.Element | None:
    """service@behaviorConfiguration -> the named serviceBehaviors behavior (nearest config wins);
    None -> the unnamed default."""
    for root in reversed(chain):
        for b in _sm(root, "behaviors/serviceBehaviors/behavior"):
            if (b.get("name") or None) == name:
                return b
    return None


def _synth(binding: str, cfg: str | None, address: str) -> ET.Element:
    ep = ET.Element("endpoint", {"binding": binding, "address": address})
    if cfg:
        ep.set("bindingConfiguration", cfg)
    return ep


def _mapped(chain: list[ET.Element], scheme: str, bases: list[str]) -> ET.Element | None:
    """Synthetic endpoint for a scheme: the <protocolMapping> entry (nearest config wins), else the
    framework default."""
    binding, cfg = _DEFAULT_MAP.get(scheme, ""), None
    for root in chain:  # farthest first, so a nearer entry overrides
        for pm in _sm(root, "protocolMapping/add"):
            if _low(pm, "scheme") == scheme and pm.get("binding"):
                binding, cfg = pm.get("binding"), pm.get("bindingConfiguration") or None
    if not binding:
        return None
    addr = next((b.strip() for b in bases if _scheme(b.strip().lower()) == scheme), f"{scheme}://default")
    return _synth(binding, cfg, addr)


def _default_endpoints(chain: list[ET.Element], bases: list[str]) -> list[ET.Element]:
    """The endpoints WCF 4+ adds to a service that configures none: one per base address scheme (http if none)."""
    schemes = list(dict.fromkeys(filter(None, (_scheme(b.strip().lower()) for b in bases)))) or ["http"]
    eps = [e for e in (_mapped(chain, sc, bases) for sc in schemes) if e is not None]
    for e in eps:
        e.set(_DEFAULT_EP, "1")
    return eps


def _effective(chain: list[ET.Element], ep: ET.Element, bases: list[str], notes: set[str],
               svc: str) -> list[ET.Element]:
    """The endpoint to analyze: itself when it names a binding (`kind=` only matters when the
    binding is absent), else the binding a standard `kind=` endpoint or the protocolMapping gives
    it (a missing binding is not a safe default). Anything unresolvable is noted."""
    if _is_mex(ep):
        return []
    what = f"endpoint \"{ep.get('address') or ''}\" of service \"{svc}\""
    if ep.get("binding"):
        if not ep.get("kind"):
            return [ep]
        explicit = copy.copy(ep)  # keeps ORIGIN/LINE for anchoring; the kind no longer hides the binding
        explicit.attrib = {k: v for k, v in ep.attrib.items() if k != "kind"}
        return [explicit]
    kind = _low(ep, "kind")
    if kind.endswith("endpoint") and kind[: -len("endpoint")] + "binding" in _BINDING_DEFAULTS:
        return [_synth(kind[: -len("endpoint")] + "binding", None, ep.get("address") or "")]
    if kind:
        notes.add(f"WCF {what} has unknown kind \"{ep.get('kind')}\": its binding was not analyzed (DNL-WCF-001)")
        return []
    scheme = _scheme(_low(ep, "address")) or (_scheme(bases[0].strip().lower()) if bases else None) or "http"
    e = _mapped(chain, scheme, bases)
    if e is None:
        notes.add(f"WCF {what} uses scheme \"{scheme}\" with no protocolMapping or framework default: "
                  "its binding was not analyzed (DNL-WCF-001)")
        return []
    if ep.get("address"):
        e.set("address", ep.get("address"))
    return [e]


class Hosted(NamedTuple):
    """A service hosted by a .svc file or a serviceActivations entry."""
    name: str          # service type name
    dir: Path          # directory it is hosted from: the .svc file's own, or the declaring config's
    stop: Path         # project dir: the nearest config is searched up to here, never above
    src: str = ""      # rel path of the .svc file / declaring config
    line: int = 0      # line of the ServiceHost directive (0 for an activation entry)


def hosted_services(model) -> list[Hosted]:
    """Every .svc / serviceActivations service, from the route discovery list, so services with
    no <service> element still get their default endpoints."""
    from checks.dnl.routes import _wcf_services  # noqa: PLC0415
    out = []
    for _svc, service, _f, src, proj in _wcf_services(model):
        if not service:
            continue
        path, line = model.root / src, 0
        if src.lower().endswith(".svc"):
            try:
                text = path.read_text(encoding="utf-8-sig", errors="replace")
            except OSError:
                text = ""
            line = next((i + 1 for i, ln in enumerate(text.splitlines()) if "servicehost" in ln.lower()), 1)
        out.append(Hosted(service, path.parent.resolve(), proj.dir.resolve(), src, line))
    return out


def _eval(root: ET.Element, hosted: list[str], notes: set[str], parents: list[ET.Element] = ()) -> list[Hit]:
    """Hits for one config. `parents` are the effective roots of the configs above it (farthest
    first): bindings, behaviors and protocolMapping entries resolve through them, nearest wins."""
    out: list[Hit] = []
    chain = [*parents, root]
    parent_files = {p.get(ORIGIN) for p in parents} - {None, root.get(ORIGIN)}

    def add(cid, sev, title, desc, el):
        out.append((cid, sev, title, desc, el))

    # Hosting units: every <service>, plus hosted services with no <service> element. Each carries
    # its behavior name, an anchor for findings with no element of their own, and its endpoints
    # (explicit, or the default endpoints WCF 4+ adds when none are configured).
    units: list[tuple[str, str | None, ET.Element, list[ET.Element], bool]] = []
    declared: set[str] = set()
    sm_root = root.find("system.serviceModel")
    for svc in _sm(root, "services/service"):
        name = svc.get("name") or ""
        declared.add(name.lower())
        bases = [(a.get("baseAddress") or "") for a in svc.findall("host/baseAddresses/add")]
        raw = svc.findall("endpoint")
        eps = [e for r in raw for e in _effective(chain, r, bases, notes, name)] if raw else _default_endpoints(chain, bases)
        has_ep = (not raw) or any(not _is_mex(r) for r in raw)
        units.append((name, svc.get("behaviorConfiguration") or None, svc, eps, has_ep))
    for name in dict.fromkeys(hosted):
        if name.lower() in declared:
            continue
        act = next((a for a in root.iter("add") if (a.get("service") or "").lower() == name.lower()
                    and a.get("relativeAddress") is not None), None)
        anchor = act if act is not None else (sm_root if sm_root is not None else root)
        units.append((name, None, anchor, _default_endpoints(chain, []), True))

    # WCF-001: endpoints a remote caller can reach with no transport / message protection. One
    # finding per anchor, so a binding shared by several endpoints lists them all.
    groups: dict[tuple, list] = {}
    for name, _beh, anchor_el, eps, _has in units:
        for ep in eps:
            if _is_local(ep):
                continue
            mode, cred, cfg, sec = _binding_security(chain, ep)
            if mode is None:
                notes.add(f"WCF binding \"{ep.get('binding')}\" of service \"{name}\" is custom or "
                          "unrecognized: its security settings were not analyzed (DNL-WCF-001)")
                continue
            explicit = sec is not None and bool(sec.get("mode"))
            fallback = ep if ep.get(LINE) else anchor_el
            anchor = sec if explicit else (cfg if cfg is not None else fallback)
            if anchor.get(ORIGIN) in parent_files:
                anchor = fallback  # inherited binding: report where the service uses it, not in the parent
            if mode == "none":
                kind, title = "none", "WCF endpoint without transport or message security"
                how = "security mode=\"None\"" if explicit else "the binding default (security mode None)"
            elif mode == "transportcredentialonly" and not _is_https(ep):
                kind, title = "cred", "WCF endpoint sends credentials without transport security"
                how = "security mode=\"TransportCredentialOnly\" on a non-https address (credentials travel in clear)"
            elif mode in ("transport", "message") and cred == "none" and not _is_https(ep):
                if "http" in (ep.get("binding") or "").lower():
                    kind, title = "anon", "WCF endpoint accepts anonymous callers without HTTPS"
                    how = (f"security mode=\"{mode.capitalize()}\" and clientCredentialType=\"None\" "
                           "on a non-https address")
                else:
                    # net.tcp / named pipes: the transport is protected, but any caller is accepted.
                    kind, title = "anon", "WCF endpoint accepts anonymous callers (no client credential)"
                    how = (f"security mode=\"{mode.capitalize()}\" and clientCredentialType=\"None\", "
                           "so it accepts anonymous callers (no client credential)")
            else:
                continue
            # One finding per anchor position: the merge keys hits by (file, line), so endpoints that
            # resolve to different bindings or kinds under one anchor (or anchors on one line) share
            # the finding, each reason listed with its own text.
            pos = (anchor.get(ORIGIN), anchor.get(LINE)) if anchor.get(LINE) else id(anchor)
            g = groups.setdefault(pos, [anchor, set(), {}, []])
            g[1].add(title)
            g[3].append(bool(ep.get(_DEFAULT_EP)) and _scheme((ep.get("address") or "").lower()) == "http")
            g[2].setdefault((ep.get("binding"), how), []).append(
                f"\"{ep.get('address') or '(default endpoint)'}\" of service \"{name}\"")
    for anchor, titles, by_binding, plain_default in groups.values():
        desc = " ".join(f"Endpoint(s) {', '.join(dict.fromkeys(w))} use {binding} with {how}."
                        for (binding, how), w in by_binding.items())
        add("DNL-WCF-001", "high",
            next(iter(titles)) if len(titles) == 1 else "WCF endpoint without adequate transport or message security",
            desc + " Traffic and caller identity are not protected, so anyone on the network path can read "
            "or alter messages." + (f" {_HTTP_ASSUMPTION}" if all(plain_default) else ""), anchor)

    # WCF-002: debug faults leak stack traces.
    for sd in _sm(root, "behaviors/serviceBehaviors/behavior/serviceDebug"):
        if _low(sd, "includeExceptionDetailInFaults") == "true":
            add("DNL-WCF-002", "medium", "WCF exception details returned in faults",
                "serviceDebug includeExceptionDetailInFaults=\"true\" sends stack traces and internal "
                "details to clients.", sd)

    # WCF-003: service description reachable by anyone who can reach the service.
    for sm in _sm(root, "behaviors/serviceBehaviors/behavior/serviceMetadata"):
        if _low(sm, "httpGetEnabled") == "true" or _low(sm, "httpsGetEnabled") == "true":
            add("DNL-WCF-003", "low", "WCF metadata exposed",
                "serviceMetadata httpGetEnabled/httpsGetEnabled=\"true\" publishes the WSDL (operations, "
                "types, endpoints) to any caller.", sm)
    for svc in _sm(root, "services/service"):
        for ep in svc.findall("endpoint"):
            if _is_mex(ep):
                add("DNL-WCF-003", "low", "WCF metadata exchange endpoint",
                    f"Service \"{svc.get('name') or ''}\" exposes a metadata exchange (mex) endpoint.", ep)

    # WCF-004: size quotas and throttling; one finding per offending binding or behavior. Every
    # descendant is checked, so customBinding transports/encoders (httpTransport, binaryMessageEncoding
    # readerQuotas...) count as well as the standard bindings' own attributes.
    for b in _sm(root, "bindings/*/binding"):
        why = [f"{a}={v}" if el is b else f"{el.tag} {a}={v}"
               for el in b.iter() for a in _SIZE_ATTRS if (v := _int(el.get(a))) is not None and v > _LIMIT]
        why += [f"readerQuotas {a}={v}" for rq in b.iter("readerQuotas") for a in _QUOTA_ATTRS
                if (v := _int(rq.get(a))) is not None and v > _LIMIT]
        if why:
            add("DNL-WCF-004", "low", "WCF message size quota too large",
                f"Binding \"{b.get('name') or ''}\" allows very large messages (" + ", ".join(why) +
                f"; limit {_LIMIT} bytes), easing resource exhaustion.", b)
    seen: set[int] = set()
    for name, beh_name, _a, _eps, has_ep in units:
        if not has_ep:
            continue
        beh = _behavior(chain, beh_name)
        if beh is not None and id(beh) not in seen and beh.find("serviceThrottling") is None:
            seen.add(id(beh))
            add("DNL-WCF-004", "low", "WCF service throttling not configured",
                f"Service behavior \"{beh.get('name') or ''}\" (used by \"{name}\") has no "
                "serviceThrottling element, so concurrency limits stay at framework defaults.", beh)
    return out


def _owner_config(configs: list[WebConfig], d: Path, stop: Path) -> WebConfig | None:
    """Nearest non-Views config (parsed or not) at or above directory `d`, not above the project
    dir `stop`; an unparsable nearest config must not be skipped in favor of a parent."""
    best = None
    for c in configs:
        if c.is_views:
            continue
        cd = c.path.parent.resolve()
        if (cd == d or cd in d.parents) and (cd == stop or stop in cd.parents):
            if best is None or len(cd.parts) > len(best.path.parent.resolve().parts):
                best = c
    return best


def _top_dir(configs: list[WebConfig], d: Path) -> Path:
    """Directory of the topmost parsed non-Views config at or above `d` (the config chain's start when
    no hosted service names a project dir)."""
    best = d
    for c in configs:
        cd = c.path.parent.resolve()
        if not c.is_views and c.root is not None and cd in d.parents and len(cd.parts) < len(best.parts):
            best = cd
    return best


def check_configs(configs: list[WebConfig], hosted: list[Hosted | tuple] | None = None
                  ) -> tuple[list[Finding], list[str]]:
    """WCF findings and scan notes for every parsed non-Views config. `hosted` lists the services
    hosted by .svc files / serviceActivations (see `hosted_services`); those with no <service>
    element are analyzed through their default endpoints, using the nearest config at or above the
    hosting dir. With no config there, the framework default (unsecured basicHttpBinding) is
    reported at the .svc file; when that config does not parse a note is added instead. Parse
    failures and transform errors of the configs themselves are noted by rules_config."""
    findings: list[Finding] = []
    notes: set[str] = set()
    owned: dict[int, list[str]] = {}
    stops: dict[int, Path] = {}
    for h in map(lambda h: Hosted(*h), hosted or ()):
        c = _owner_config(configs, h.dir, h.stop)
        if c is None and h.src.lower().endswith(".svc"):
            # No web.config: WCF falls back to its defaults, i.e. http -> basicHttpBinding, security None.
            anchor = ET.Element("configuration", {ORIGIN: h.src, LINE: str(h.line or 1)})
            for cid, sev, title, desc, _el in _eval(anchor, [h.name], notes):
                findings.append(dnl_finding(
                    cid, sev, title, desc + " No web.config/serviceModel was found for this service, so the "
                    "default unsecured basicHttpBinding applies.", h.src, h.line or 1, api_surface=True))
            _mark_review(findings)
        elif c is None:
            continue
        elif c.root is None:
            notes.add(f"{h.src}: owning web.config could not be parsed; WCF security not evaluated")
        else:
            owned.setdefault(id(c), []).append(h.name)
            stops.setdefault(id(c), h.stop)
    for cfg in configs:
        if cfg.is_views or cfg.root is None:
            continue
        here = owned.get(id(cfg), [])
        variants = effective(cfg)
        per: dict[str, dict[tuple, Hit]] = {}
        cfg_notes: set[str] = set()
        here_dir = cfg.path.parent.resolve()
        top = stops.get(id(cfg)) or _top_dir(configs, here_dir)
        for name, root in variants:
            d: dict[tuple, Hit] = {}
            # Effective roots of the configs above this one, in the same variant (farthest first).
            parents = config_chain(configs, top, here_dir, name)[:-1] if here_dir != top else []
            for h in _eval(root, here, cfg_notes, parents):
                d.setdefault((h[0], h[4].get(ORIGIN), h[4].get(LINE)), h)
            per[name] = d
        notes |= {f"{cfg.rel}: {n}" for n in cfg_notes}
        # Service-model configs host services: API-surface tagging applies.
        findings += _mark_review(merge_variants(cfg, variants, per, True, frozenset()))
    return findings, sorted(notes)


def _mark_review(findings: list[Finding]) -> list[Finding]:
    """A default-endpoint finding rests on an assumption about the site bindings: REVIEW."""
    for f in findings:
        if f.check_id == "DNL-WCF-001" and _HTTP_ASSUMPTION in f.description:
            f.confidence = "REVIEW"
    return findings


def non_web_config_notes(root: Path) -> list[str]:
    """Notes for non-web `.config` files (App.config...) that declare `<service>` elements: WCF hosting
    is only discovered through .svc files and web.config serviceActivations, so those services are
    not analyzed."""
    out: list[str] = []
    for p in iter_dnl_files(root, (".config",)):
        if re.fullmatch(r"web(\..+)?\.config", p.name, re.I):
            continue
        try:
            tree = ET.fromstring(read_source(p).encode("utf-8"))
        except (ET.ParseError, ValueError, OSError):
            continue
        if tree.findall("system.serviceModel/services/service"):
            out.append(f"{p.relative_to(root).as_posix()}: WCF services declared outside web.config hosting "
                       "are not discovered")
    return out
