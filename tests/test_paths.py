from core.paths import extract_path_param_names, join_path_segments, resolve_mount_prefix


def test_extract_flask_converter_syntax():
    assert extract_path_param_names("/users/<int:user_id>") == ["user_id"]


def test_extract_flask_bare_name():
    assert extract_path_param_names("/users/<id>") == ["id"]


def test_extract_does_not_double_count_converter():
    # regression: <uuid:record_uuid> used to yield ["uuid", "record_uuid"]
    assert extract_path_param_names("/records/<uuid:record_uuid>") == ["record_uuid"]


def test_extract_fastapi_spring_braces():
    assert extract_path_param_names("/items/{item_id}") == ["item_id"]


def test_extract_express_colon():
    assert extract_path_param_names("/orders/:orderId") == ["orderId"]


def test_extract_multiple_params():
    assert extract_path_param_names("/a/<int:x>/b/{y}/c/:z") == ["x", "y", "z"]


def test_extract_no_params():
    assert extract_path_param_names("/health") == []


def test_join_path_segments_normalizes_slashes():
    assert join_path_segments("/api/", "/v1/", "/items/{id}") == "/api/v1/items/{id}"


def test_join_path_segments_handles_empty_and_none():
    assert join_path_segments("", None, "/x") == "/x"


def test_join_path_segments_all_empty_returns_root():
    assert join_path_segments("", "") == "/"


def test_resolve_mount_prefix_single_level():
    mounts = {"bp": ("app", "/api")}
    assert resolve_mount_prefix("bp", mounts) == "/api"


def test_resolve_mount_prefix_multi_level_chain():
    # items_router -> v1_router -> app, prefixes /items and /v1
    mounts = {
        "items_router": ("v1_router", "/items"),
        "v1_router": ("app", "/v1"),
    }
    assert resolve_mount_prefix("items_router", mounts) == "/v1/items"


def test_resolve_mount_prefix_unresolved_name_returns_root():
    assert resolve_mount_prefix("app", {}) == "/"


def test_resolve_mount_prefix_ignores_cycles():
    # defensive: a self-referential or cyclic mount map must not infinite-loop
    mounts = {"a": ("b", "/a"), "b": ("a", "/b")}
    result = resolve_mount_prefix("a", mounts)
    assert isinstance(result, str)
