"""Shared context of the ASP.NET Core configuration rules: the pipeline of every web project, the
route refs, the findings collected so far, and the "is a missing middleware really missing?" test.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .appsettings import load_settings
from .auth_core import _NON_AUTHZ_EXTENSIONS
from .findings import dnl_finding
from .pipeline import Pipeline, PipeCall, pipeline_for
from .project import ProjectModel
from .routes_core import CoreRouteRef
from core.models import Finding


@dataclass
class Ctx:
    model: ProjectModel
    refs: list[CoreRouteRef]
    pipes: list[Pipeline]                  # one per netcore project with style != "none"
    settings: object | None = None         # appsettings.Settings, filled by the appsettings reader
    out: list[Finding] = field(default_factory=list)

    def add(self, check_id: str, severity: str, title: str, description: str, file: str, line: int, *,
            route=None, confidence: str | None = None, api_surface: bool = False) -> None:
        """Append a finding. A route-bound finding takes the API surface from its route."""
        if route is not None:
            api_surface = api_surface or bool(route.meta.get("api_surface", False))
        self.out.append(dnl_finding(check_id, severity, title, description, file, line,
                                    route=route, api_surface=api_surface, confidence=confidence))

    def absent_confidence(self, pipe: Pipeline) -> tuple[str | None, str]:
        """(None | "REVIEW", note) for an absence finding (no HSTS, no rate limiter, ...). None when the
        pipeline was read in full; REVIEW with a note naming the cause when a call under an environment
        condition that could not be parsed, an unresolved services / app call that could register the
        missing piece, or an ambiguous startup choice means the pipeline may not be what was read."""
        why: list[str] = []
        for c in pipe.uncertain():
            why.append(f"{c.name} at {c.file}:{c.line} is under an environment condition that could not be parsed")
        for c in pipe.unresolved():
            if (c.kind in ("services", "app") and c.name not in _NON_AUTHZ_EXTENSIONS
                    and c.runs_in("Production") is not False):
                why.append(f"{c.name} at {c.file}:{c.line} is not resolved and may register the missing piece")
        why += pipe.notes
        if not why:
            return None, ""
        return "REVIEW", "; ".join(why)

    def prod_calls(self, pipe: Pipeline, *names: str, kinds: tuple[str, ...] = ()) -> list[PipeCall]:
        """Calls that certainly run in Production, by name and kind."""
        return pipe.named(*names, kinds=kinds)

    def uncertain_calls(self, pipe: Pipeline, *names: str, kinds: tuple[str, ...] = ()) -> list[PipeCall]:
        """Calls under an unparseable environment condition, by name and kind."""
        return [c for c in pipe.uncertain()
                if (not names or c.name in names) and (not kinds or c.kind in kinds)]


def build_ctx(model: ProjectModel, refs: list[CoreRouteRef]) -> Ctx:
    """One pipeline per netcore project; a project with no entry point (a library) has none."""
    pipes = []
    for proj in model.projects:
        if proj.owner != "dotnet":
            continue
        pipe = pipeline_for(model, proj)
        if pipe.style != "none":
            pipes.append(pipe)
    # One settings load per model: it appends a note per malformed file, so it must not repeat.
    settings = model.cache.get("appsettings")
    if settings is None:
        settings = model.cache["appsettings"] = load_settings(model)
    return Ctx(model, refs, pipes, settings)
