from checks.auth import apply_global_auth_note, check_missing_auth_indicator
from core.models import Route, ScanResult


def _route(methods=None, auth_decorators=None):
    return Route(
        path="/x",
        methods=methods or ["GET"],
        handler_name="h",
        file="f.py",
        line=1,
        auth_decorators=auth_decorators or [],
    )


def test_flags_route_with_no_known_auth_indicator():
    findings = check_missing_auth_indicator([_route()], {"login_required"})
    assert len(findings) == 1
    assert findings[0].check_id == "AUTH-001"


def test_does_not_flag_route_with_known_auth_indicator():
    route = _route(auth_decorators=["login_required"])
    assert check_missing_auth_indicator([route], {"login_required"}) == []


def test_unrecognized_decorator_still_flags_route():
    # a decorator that happens to be present but isn't in the known set
    # (e.g. a caching decorator) must not be mistaken for auth
    route = _route(auth_decorators=["cache_result"])
    findings = check_missing_auth_indicator([route], {"login_required"})
    assert len(findings) == 1


def test_sensitive_methods_get_medium_severity():
    for method in ["POST", "PUT", "PATCH", "DELETE"]:
        findings = check_missing_auth_indicator([_route(methods=[method])], set())
        assert findings[0].severity == "medium", method


def test_get_gets_low_severity():
    findings = check_missing_auth_indicator([_route(methods=["GET"])], set())
    assert findings[0].severity == "low"


def test_apply_global_auth_note_sets_structured_source():
    result = ScanResult(language="python", framework="flask")
    apply_global_auth_note(result, "app.py", 7, "@before_request checks auth")
    assert result.global_auth_source == ("app.py", 7, "@before_request checks auth")


def test_apply_global_auth_note_appends_caveat_to_auth_findings_only():
    route = _route()
    auth_finding = check_missing_auth_indicator([route], set())[0]
    result = ScanResult(language="python", framework="flask", findings=[auth_finding])
    original_len = len(auth_finding.description)

    apply_global_auth_note(result, "app.py", 7, "something")

    assert len(auth_finding.description) > original_len
    assert "app.py:7" in auth_finding.description
