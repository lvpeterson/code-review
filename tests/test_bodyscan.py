from core.bodyscan import extract_request_field_names


def test_flask_request_args_get():
    assert extract_request_field_names("request.args.get('user_id')") == ["user_id"]


def test_flask_request_args_bracket():
    assert extract_request_field_names("request.args['user_id']") == ["user_id"]


def test_flask_request_json():
    assert extract_request_field_names("request.json.get('order_id')") == ["order_id"]


def test_django_request_get_and_post():
    text = "request.GET.get('user_id')\nrequest.POST.get('order_id')"
    assert extract_request_field_names(text) == ["user_id", "order_id"]


def test_drf_request_data():
    assert extract_request_field_names("request.data.get('user_id')") == ["user_id"]


def test_express_req_query_dot_access():
    assert extract_request_field_names("req.query.userId") == ["userId"]


def test_express_req_body_bracket_access():
    assert extract_request_field_names("req.body['orderId']") == ["orderId"]


def test_no_matches_returns_empty_list():
    assert extract_request_field_names("x = 1 + 2") == []


def test_multiple_accessors_in_one_body():
    text = "const a = req.query.userId;\nconst b = req.body.orderId;"
    assert extract_request_field_names(text) == ["userId", "orderId"]
