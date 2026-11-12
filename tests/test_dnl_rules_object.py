"""Object-level authz findings: IDOR (AUTHZ-005), over-posting (006), over-exposure (007)."""
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_object

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def findings(model):
    return rules_object.check(model, routes.discover_mvc_webapi(model))


def on(findings, rule):
    return {f.route.handler_name for f in findings if f.check_id == rule}


def test_entity_types(model):
    assert rules_object.entity_types(model) == {"Order", "Note"}


def test_idor_positive_and_negative(findings):
    got = on(findings, "DNL-AUTHZ-005")
    assert {"ObjectsController.Get", "ObjectsController.Via", "ObjectsController.Raw",
            "ObjectsApiController.GetRaw"} <= got
    assert "ObjectsController.Mine" not in got      # compares OwnerId to the signed-in user
    assert "ObjectsController.Label" not in got     # id never reaches a data access
    f = next(f for f in findings if f.check_id == "DNL-AUTHZ-005" and f.route.handler_name == "ObjectsController.Get")
    assert f.severity == "low" and f.confidence == "REVIEW" and "in ObjectsController.Get" in f.description
    assert "api2023" not in f.owasp                  # MVC route: no API tag


def test_idor_raw_sql_in_the_action(findings):
    got = on(findings, "DNL-AUTHZ-005")
    assert {"ObjectsController.RawInline", "ObjectsController.EfRaw"} <= got


def test_user_reference_must_guard_the_access(findings):
    got = on(findings, "DNL-AUTHZ-005")
    # a log line, a helper off the path, a non-identity session key and IsAuthenticated do not suppress
    assert {"ObjectsController.Logged", "ObjectsController.Audited", "ObjectsController.Themed",
            "ObjectsController.AuthOnly", "ObjectsController.ViewBagOwner", "ObjectsController.NullCheckLog",
            "ObjectsController.MemberLookup", "ObjectsController.CacheKey", "ObjectsController.CartGate",
            "ObjectsController.SignedInOnly"} <= got
    # comparisons and user-scoped queries do
    assert not {"ObjectsController.Mine", "ObjectsController.SessionOwner", "ObjectsController.Scoped",
                "ObjectsController.FetchedOwner", "ObjectsController.TernaryOwner",
                "ObjectsController.AsyncOwner", "ObjectsController.SessionThis"} & got


def test_idor_ado_parameter_is_data_access(findings):
    got = on(findings, "DNL-AUTHZ-005")
    assert {"ObjectsController.AdoParam", "ObjectsController.AdoValue"} <= got


def test_exclude_only_bind_is_review(findings):
    f = next(f for f in findings if f.check_id == "DNL-AUTHZ-006" and f.route.handler_name == "ObjectsController.UpdateExcl")
    assert f.confidence == "REVIEW" and "Exclude" in f.description
    plain = next(f for f in findings if f.check_id == "DNL-AUTHZ-006" and f.route.handler_name == "ObjectsController.Update")
    assert plain.confidence is None


def test_idor_api_tag(findings):
    f = next(f for f in findings if f.check_id == "DNL-AUTHZ-005" and f.route.handler_name == "ObjectsApiController.GetRaw")
    assert f.owasp["api2023"].startswith("API1:2023")


def test_over_posting(findings):
    got = on(findings, "DNL-AUTHZ-006")
    # [Bind(Include)] on the param or class and GET are exempt on MVC; Web API ignores [Bind]; Prefix alone is no protection.
    assert got == {"ObjectsController.Update", "ObjectsController.UpdateMany", "ObjectsController.UpdatePrefix",
                   "ObjectsController.UpdateExcl", "ObjectsApiController.PostBound"}
    f = next(f for f in findings if f.check_id == "DNL-AUTHZ-006")
    assert f.severity == "medium"


def test_over_exposure(findings):
    got = on(findings, "DNL-AUTHZ-007")
    assert got == {"ObjectsApiController.GetRaw", "ObjectsApiController.GetAll", "ObjectsApiController.GetWrapped",
                   "ObjectsApiController.GetAsync", "ObjectsApiController.GetGrouped",
                   "ObjectsApiController.GetOfType", "ObjectsApiController.GetViaCall",
                   "ObjectsApiController.GetListNew"}     # Select into a DTO / anonymous type is excluded
    f = next(f for f in findings if f.check_id == "DNL-AUTHZ-007" and f.route.handler_name == "ObjectsApiController.GetRaw")
    assert f.severity == "low" and f.owasp["api2023"].startswith("API3:2023")


def test_one_finding_per_rule_and_route(findings):
    keys = [(f.check_id, f.route.handler_name, f.route.path) for f in findings]
    assert len(keys) == len(set(keys))
