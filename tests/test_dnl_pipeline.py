"""ASP.NET Core pipeline facts: ordered, environment-tagged service / middleware / endpoint calls."""
from pathlib import Path

import pytest

from checks.dnl import helper, ir, project
from checks.dnl.pipeline import _FRAMEWORK_CALLS, pipeline_for

FX = Path(__file__).parent / "fixtures" / "aspnetcore" / "pipelines"


@pytest.fixture(autouse=True)
def _fresh_cache():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


def _pipe(name: str, allow_degraded: bool = False):
    root = FX / name
    model = project.prepare(root, allow_degraded).view("dotnet")
    return pipeline_for(model, model.projects[0])


def _names(p):
    return [c.name for c in p.calls]


def _by(p, name):
    return next(c for c in p.calls if c.name == name)


def _call(fn: dict, args=None) -> dict:
    return {"k": "call", "fn": fn, "args": args or [], "named": {}}


def test_call_chain():
    app = {"k": "name", "id": "app"}
    c1 = _call({"k": "member", "obj": app, "name": "MapGroup"}, [{"k": "lit", "v": "/a", "t": "string"}])
    c2 = _call({"k": "member", "obj": c1, "name": "RequireAuthorization"})
    c3 = _call({"k": "member", "obj": c2, "name": "MapGet"})
    root, calls = ir.call_chain(c3)
    assert root == app
    assert [ir.call_name(c) for c in calls] == ["MapGroup", "RequireAuthorization", "MapGet"]
    # Not a chain: the expression itself, no calls.
    assert ir.call_chain(app) == (app, [])
    assert ir.call_chain({"k": "lit", "v": 1}) == ({"k": "lit", "v": 1}, [])


def test_minimal_pipeline_order_and_env(roslyn_helper):
    p = _pipe("minimal")
    assert p.style == "minimal"
    assert p.target_framework == "net8.0"
    names = _names(p)
    wanted = ["AddAuthentication", "AddAuthorization", "AddCors", "UseDeveloperExceptionPage",
              "UseExceptionHandler", "UseRouting", "UseAuthentication", "UseAuthorization"]
    pos = [names.index(n) for n in wanted]
    assert pos == sorted(pos)
    assert _by(p, "UseDeveloperExceptionPage").env == "Development"
    assert _by(p, "UseExceptionHandler").env == "!Development"
    assert _by(p, "UseRouting").env is None
    assert _by(p, "AddCors").file == "ServiceSetup.cs"
    assert _by(p, "AddCors").kind == "services"
    assert _by(p, "UseRouting").kind == "app"
    assert _by(p, "MapGet").kind == "endpoints"
    assert [c.order for c in p.calls] == sorted(c.order for c in p.calls)
    # Development-only calls are hidden unless asked for.
    assert [c.name for c in p.named("UseDeveloperExceptionPage")] == []
    assert [c.name for c in p.named("UseDeveloperExceptionPage", include_dev=True)] == ["UseDeveloperExceptionPage"]
    assert [c.name for c in p.named(kinds=("services",))][:2] == ["AddAuthentication", "AddAuthorization"]
    assert p.unresolved() == []


def test_startup_pipeline_partial_and_order(roslyn_helper):
    p = _pipe("startup")
    assert p.style == "startup"
    names = _names(p)
    assert names.index("AddControllers") < names.index("UseAuthorization") < names.index("UseRouting")
    assert [c.name for c in p.unresolved()] == ["AddCompanyAuth"]
    assert p.unresolved()[0].kind == "services"
    assert _by(p, "UseEndpoints").kind == "app"
    # Both partial halves of Startup contribute (different files).
    assert {_by(p, "AddControllers").file, _by(p, "UseRouting").file} == {"Startup.Services.cs", "Startup.Pipeline.cs"}


def test_degraded_pipeline_same_facts(roslyn_helper, monkeypatch):
    full = _pipe("minimal")
    project._CACHE.clear()
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    deg = _pipe("minimal", True)
    assert _names(deg) == _names(full)
    assert [c.env for c in deg.calls] == [c.env for c in full.calls]
    assert [c.kind for c in deg.calls] == [c.kind for c in full.calls]
    assert _by(deg, "AddAuthorization").resolved is True
    assert "AddAuthorization" in _FRAMEWORK_CALLS
    assert _by(deg, "AddCors").file == "ServiceSetup.cs"


def test_degraded_startup_unresolved(roslyn_helper, monkeypatch):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    p = _pipe("startup", True)
    assert p.style == "startup"
    assert [c.name for c in p.unresolved()] == ["AddCompanyAuth"]
    assert p.unresolved()[0].kind == "services"


def test_follow_depth_and_cycles(roslyn_helper):
    p = _pipe("cycle")
    names = _names(p)
    # Two extension methods call each other: terminates, every call appears once.
    assert sorted(names) == sorted(set(names))
    assert {"AddFirst", "AddSecond", "AddCors", "AddSession"} <= set(names)
    assert names.index("AddCors") < names.index("AddSession")


def test_cached_on_model(roslyn_helper):
    model = project.prepare(FX / "minimal", False).view("dotnet")
    proj = model.projects[0]
    assert pipeline_for(model, proj) is pipeline_for(model, proj)
    assert "pipelines" in model.cache
