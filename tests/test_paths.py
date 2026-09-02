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


def test_extract_spring_regex_constrained_braces():
    # regression: Spring's {name:regex} syntax (e.g. to disambiguate a
    # numeric-id route from a static path, or restrict what a segment
    # matches) used to fail the whole {...} match and silently drop the
    # param from every downstream check (IDOR-001, the report's input-note,
    # code-view highlighting).
    assert extract_path_param_names("/orders/{orderId:[0-9]+}") == ["orderId"]
    assert extract_path_param_names("/files/{fileName:.+}") == ["fileName"]


def test_extract_starlette_converter_braces():
    # Starlette/FastAPI's {name:int}, {name:path}, etc -- same underlying
    # regex gap as the Spring case above.
    assert extract_path_param_names("/items/{item_id:int}") == ["item_id"]


def test_extract_mixed_bare_and_constrained_braces():
    assert extract_path_param_names("/orgs/{orgId}/items/{itemId:[0-9]+}") == ["orgId", "itemId"]


def test_extract_hyphenated_name_in_braces():
    # regression: kebab-case is the common convention for URL segments, even
    # though the bound variable name in code can't contain a hyphen (e.g.
    # Spring requires @PathVariable("order-id") Long orderId for this).
    assert extract_path_param_names("/orders/{order-id}") == ["order-id"]


def test_extract_hyphenated_name_with_constraint():
    assert extract_path_param_names("/orders/{order-id:[0-9]+}") == ["order-id"]


def test_extract_hyphenated_name_flask_and_express():
    assert extract_path_param_names("/orders/<order-id>") == ["order-id"]
    assert extract_path_param_names("/orders/:order-id") == ["order-id"]


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
