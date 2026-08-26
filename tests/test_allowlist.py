from checks.auth import check_missing_auth_indicator
from checks.idor import check_id_param_routes
from core.allowlist import apply_allowlist
from core.models import Route, ScanResult


def _result_with_public_route():
    route = Route(path="/healthz", methods=["GET"], handler_name="health", file="app.py", line=1)
    findings = check_missing_auth_indicator([route], set())
    return ScanResult(language="python", framework="flask", routes=[route], findings=findings)


def test_matching_pattern_suppresses_auth_finding():
    result = _result_with_public_route()
    assert len(result.findings) == 1
    apply_allowlist([result], ["/healthz"])
    assert result.findings == []


def test_glob_pattern_matches():
    result = _result_with_public_route()
    apply_allowlist([result], ["/health*"])
    assert result.findings == []


def test_non_matching_pattern_does_not_suppress():
    result = _result_with_public_route()
    apply_allowlist([result], ["/other"])
    assert len(result.findings) == 1


def test_empty_patterns_is_a_noop():
    result = _result_with_public_route()
    apply_allowlist([result], [])
    assert len(result.findings) == 1


def test_only_auth_findings_are_suppressed_not_idor():
    route = Route(path="/users/<int:user_id>", methods=["GET"], handler_name="h", file="app.py", line=1)
    auth_findings = check_missing_auth_indicator([route], set())
    idor_findings = check_id_param_routes([route])
    result = ScanResult(language="python", framework="flask", routes=[route], findings=auth_findings + idor_findings)

    apply_allowlist([result], ["/users/<int:user_id>"])

    remaining_check_ids = {f.check_id for f in result.findings}
    assert remaining_check_ids == {"IDOR-001"}
