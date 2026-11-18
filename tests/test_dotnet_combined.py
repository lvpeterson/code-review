"""The ASP.NET Core analyzers call every rule module they import: a merge that keeps an import but drops
the call (or drops both) silently loses a whole rule family, which reads as "safe"."""
from __future__ import annotations

import ast
from pathlib import Path

ANALYZERS = Path(__file__).resolve().parent.parent / "languages" / "dotnet" / "analyzers.py"

# Rule modules the combined ASP.NET Core branch must run (taint/XSS/object, configuration, SCA and the
# carried-over families).
REQUIRED = {
    "rules_auth_core", "rules_pipeline", "rules_taint", "rules_xss", "rules_object", "rules_crypto",
    "rules_deser_xml", "rules_integrity", "rules_session", "rules_errors", "rules_misc", "rules_sca_core",
}


def _imported_rule_modules(tree: ast.Module) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "checks.dnl":
            out |= {a.asname or a.name for a in node.names if a.name.startswith("rules_")}
    return out


def _called_modules(tree: ast.Module) -> set[str]:
    """Modules whose attribute is called somewhere (`rules_x.check(...)`)."""
    out = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)):
            out.add(node.func.value.id)
    return out


def _guarded_in_code_results(tree: ast.Module) -> set[str]:
    """Rule modules called inside _code_results (route-bound code findings)."""
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_code_results")
    return _called_modules(ast.Module(body=fn.body, type_ignores=[]))


def test_every_rule_module_is_wired():
    tree = ast.parse(ANALYZERS.read_text(encoding="utf-8"))
    imported = _imported_rule_modules(tree)
    assert REQUIRED <= imported, f"rule modules no longer imported: {sorted(REQUIRED - imported)}"
    called = _called_modules(tree)
    assert imported <= called, f"imported but never called: {sorted(imported - called)}"
    # Everything except SCA (which has its own analyzer, deps) runs in _code_results.
    in_code = _guarded_in_code_results(tree)
    missing = (imported - {"rules_sca_core"}) - in_code
    assert not missing, f"not called in _code_results: {sorted(missing)}"


def test_wiring_check_catches_a_dropped_call():
    src = ANALYZERS.read_text(encoding="utf-8").replace(
        'findings += guarded("rules_pipeline", lambda: rules_pipeline.check(model, refs))', "")
    tree = ast.parse(src)
    assert "rules_pipeline" not in _guarded_in_code_results(tree)
    assert "rules_pipeline" not in _called_modules(tree)
