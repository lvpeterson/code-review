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


# -- fix round 1 ------------------------------------------------------------

def _runs(p, name, *envs):
    c = _by(p, name)
    return tuple(c.runs_in(e) for e in envs)


def test_chain_links_after_map_stay_endpoints_in_both_modes(roslyn_helper, monkeypatch):
    full = _pipe("envs")
    project._CACHE.clear()
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    deg = _pipe("envs", True)
    for p in (full, deg):
        kinds = {c.name: c.kind for c in p.calls}
        assert (kinds["MapGroup"], kinds["RequireAuthorization"], kinds["MapGet"], kinds["AllowAnonymous"]) == \
            ("endpoints",) * 4
    assert [c.kind for c in deg.calls] == [c.kind for c in full.calls]


def test_env_guards_compose_and_are_three_valued(roslyn_helper):
    p = _pipe("envs")
    dsp, prod = "Development", "Production"
    assert _runs(p, "UseDeveloperExceptionPage", dsp, "Staging", prod) == (True, False, False)
    # else-if chain: the outer tags are kept, not dropped.
    assert _runs(p, "UseHsts", dsp, "Staging", prod) == (False, True, False)
    assert _runs(p, "UseHttpsRedirection", dsp, "Staging", prod) == (False, False, True)
    assert _runs(p, "UseCors", dsp, "Staging", prod, "QA") == (False, False, False, True)
    # nested ifs, case-insensitive IsEnvironment("staging")
    assert _runs(p, "UseSession", dsp, "Staging", prod) == (False, True, False)
    assert _runs(p, "UseStaticFiles", dsp, "Staging", prod) == (False, False, True)
    # ||
    assert _runs(p, "UseRateLimiter", dsp, "Staging", prod) == (True, True, False)
    # && with a non-environment operand cannot be decided in Production
    assert _by(p, "UseAntiforgery").runs_in(prod) is None
    assert _by(p, "UseAntiforgery").runs_in(dsp) is False
    # bool local, EnvironmentName == Environments.X
    assert _runs(p, "UseExceptionHandler", dsp, prod) == (True, False)
    assert _runs(p, "UseAuthentication", "Staging", prod) == (True, False)
    # unparseable environment condition
    assert _by(p, "UseAuthorization").runs_in(prod) is None
    assert _by(p, "UseHttpsRedirection").env == "!Development & !Staging & Production"
    assert _by(p, "UseDeveloperExceptionPage").env == "Development"
    assert _by(p, "RequireAuthorization").runs_in(prod) is True and _by(p, "RequireAuthorization").env is None


def test_named_and_uncertain(roslyn_helper):
    p = _pipe("envs")
    prod_names = {c.name for c in p.named()}
    assert {"UseHttpsRedirection", "UseStaticFiles", "MapGet"} <= prod_names
    # Staging-only, Development-only and undecidable calls are not in the Production view.
    assert not prod_names & {"UseHsts", "UseSession", "UseDeveloperExceptionPage", "UseAntiforgery", "UseAuthorization"}
    assert {c.name for c in p.named(include_dev=True)} == set(_names(p))
    assert {c.name for c in p.uncertain()} == {"UseAntiforgery", "UseAuthorization"}


def test_startup_class_from_use_startup_targs(roslyn_helper):
    p = _pipe("startup_generic")
    assert p.style == "startup"
    assert _names(p) == ["AddRazorPages", "UseRouting"]
    assert p.notes == []


def test_startup_class_from_use_startup_targs_degraded(roslyn_helper, monkeypatch):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    p = _pipe("startup_generic", True)
    assert _names(p) == ["AddRazorPages", "UseRouting"]


def test_ambiguous_startup_fallback_records_note(roslyn_helper):
    p = _pipe("startup_ambiguous")
    assert p.style == "startup"
    assert len(p.notes) == 1 and "AppStartup" in p.notes[0] and "LegacyStartup" in p.notes[0]
    assert _names(p) == ["AddRazorPages", "UseRouting"]
