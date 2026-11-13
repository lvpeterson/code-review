"""Language + framework detection for legacy .NET Framework targets
(MVC 5, Web API 2, WebForms, WCF, Web.config-only apps)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from checks.dnl.files import is_legacy_project, iter_dnl_files, read_source

_FRAMEWORK_ORDER = ["mvc", "webapi", "webforms", "wcf", "config"]


def _safe_read(path: Path) -> str:
    try:
        return read_source(path)
    except OSError:
        return ""


def _is_main_config(path: Path) -> bool:
    """A Web.config outside any Views dir that carries system.web/webServer."""
    if any(p.lower() == "views" for p in path.parent.parts):
        return False
    text = _safe_read(path).lower()
    return "<system.web" in text or "<system.webserver" in text


def _hosts_wcf(text: str) -> bool:
    """A real <system.serviceModel> element holding <services> or <serviceActivations>
    (parsed, so comments and client-only configs do not count)."""
    if "system.servicemodel" not in text.lower():
        return False
    try:
        root = ET.fromstring(text.encode("utf-8", "replace"))
    except ET.ParseError:
        # Malformed config: the old textual check, so the services are still scanned.
        low = text.lower()
        return "<system.servicemodel" in low and ("<services" in low or "<serviceactivations" in low)
    return any(sm.find(".//services") is not None or sm.find(".//serviceActivations") is not None
               for sm in root.iter("system.serviceModel"))


def _scan(target: Path) -> tuple[bool, set[str]]:
    """Walk once; return (language_detected, frameworks_found)."""
    lang = False
    fw: set[str] = set()
    exts = (".csproj", ".vbproj", ".config", ".aspx", ".ascx", ".svc", ".asmx")
    for path in iter_dnl_files(target, exts):
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix == ".config" and name != "packages.config" and _hosts_wcf(_safe_read(path)):
            # WCF described in config alone (services / serviceActivations, no .svc file).
            lang = True
            fw.add("wcf")
        if suffix in (".csproj", ".vbproj"):
            text = _safe_read(path)
            if is_legacy_project(text):
                lang = True
                if "System.Web.Mvc" in text:
                    fw.add("mvc")
                if "System.Web.Http" in text:
                    fw.add("webapi")
        elif name == "packages.config":
            lang = True
            text = _safe_read(path)
            if "Microsoft.AspNet.Mvc" in text:
                fw.add("mvc")
            if "Microsoft.AspNet.WebApi" in text:
                fw.add("webapi")
        elif name == "web.config":
            if _is_main_config(path):
                lang = True
                fw.add("config")
        elif suffix == ".aspx":
            lang = True
            fw.add("webforms")
        elif suffix == ".svc":
            lang = True
            fw.add("wcf")
        elif suffix in (".ascx", ".asmx"):
            lang = True
    return lang, fw


def detect_language(target_path: Path) -> bool:
    return _scan(target_path)[0]


def detect_frameworks(target_path: Path) -> list[str]:
    fw = _scan(target_path)[1]
    return [f for f in _FRAMEWORK_ORDER if f in fw]
