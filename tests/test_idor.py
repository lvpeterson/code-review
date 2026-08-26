from checks.idor import check_id_param_routes, find_id_like_params
from core.models import Route


def _route(path="/x", extra_param_names=None):
    return Route(
        path=path,
        methods=["GET"],
        handler_name="h",
        file="f.py",
        line=1,
        extra_param_names=extra_param_names or [],
    )


def test_english_words_containing_id_substring_are_not_flagged():
    # regression: substring matching used to flag "valid", "width", etc.
    for word in ["valid", "width", "hidden", "provider", "guide", "avoid"]:
        assert find_id_like_params(_route(f"/x/<str:{word}>")) == []


def test_real_id_params_are_flagged():
    assert find_id_like_params(_route("/users/<int:user_id>")) == ["user_id"]
    assert find_id_like_params(_route("/items/{itemId}")) == ["itemId"]
    assert find_id_like_params(_route("/orders/:orderId")) == ["orderId"]
    assert find_id_like_params(_route("/x/{id}")) == ["id"]


def test_uuid_and_guid_whole_words_are_flagged():
    assert find_id_like_params(_route("/files/{fileGuid}")) == ["fileGuid"]
    assert find_id_like_params(_route("/records/<uuid:record_uuid>")) == ["record_uuid"]


def test_check_id_param_routes_flags_path_param():
    findings = check_id_param_routes([_route("/users/<int:user_id>")])
    assert len(findings) == 1
    assert findings[0].check_id == "IDOR-001"
    assert "user_id" in findings[0].title


def test_check_id_param_routes_flags_query_body_param():
    route = _route("/search", extra_param_names=["user_id"])
    findings = check_id_param_routes([route])
    assert len(findings) == 1
    assert "query/body field(s) user_id" in findings[0].title


def test_check_id_param_routes_reports_both_kinds_together():
    route = _route("/users/<int:user_id>/orders", extra_param_names=["order_id"])
    findings = check_id_param_routes([route])
    assert len(findings) == 1
    assert "path parameter(s) user_id" in findings[0].title
    assert "query/body field(s) order_id" in findings[0].title


def test_no_id_like_params_produces_no_finding():
    route = _route("/health", extra_param_names=["format"])
    assert check_id_param_routes([route]) == []


def test_finding_route_reference_is_the_same_object():
    route = _route("/x/{id}")
    findings = check_id_param_routes([route])
    assert findings[0].route is route
