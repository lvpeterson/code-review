from languages.javascript.nextjs_analyzer import NextJSAnalyzer


def _write(tmp_path, rel_path, content):
    path = tmp_path / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_app_router_dynamic_segment_and_multiple_methods(tmp_path):
    _write(
        tmp_path,
        "app/api/users/[id]/route.ts",
        "export async function GET(request, { params }) {\n"
        "  return Response.json({});\n"
        "}\n\n"
        "export async function DELETE(request, { params }) {\n"
        "  return Response.json({});\n"
        "}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert len(routes) == 2
    paths_methods = sorted((r.path, r.methods[0]) for r in routes)
    assert paths_methods == [("/api/users/:id", "DELETE"), ("/api/users/:id", "GET")]


def test_app_router_route_group_is_stripped_from_path(tmp_path):
    _write(
        tmp_path,
        "app/(dashboard)/api/files/route.ts",
        "export async function GET(request) {\n  return Response.json({});\n}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/files"


def test_app_router_catch_all_segment(tmp_path):
    _write(
        tmp_path,
        "app/api/files/[...slug]/route.ts",
        "export async function GET(request) {\n  return Response.json({});\n}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/files/:slug"


def test_app_router_search_params_captured_as_extra_param(tmp_path):
    _write(
        tmp_path,
        "app/api/orders/route.ts",
        "export async function GET(request) {\n"
        "  const userId = request.nextUrl.searchParams.get('userId');\n"
        "  return Response.json({});\n"
        "}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["userId"]


def test_app_router_known_auth_call_is_detected(tmp_path):
    _write(
        tmp_path,
        "app/api/orders/route.ts",
        "export async function GET(request) {\n"
        "  const session = await getServerSession();\n"
        "  return Response.json({});\n"
        "}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert routes[0].auth_decorators == ["getServerSession"]


def test_pages_router_dynamic_segment_and_method_sniffing(tmp_path):
    _write(
        tmp_path,
        "pages/api/legacy/[userId].js",
        "export default function handler(req, res) {\n"
        "  if (req.method === 'GET') {\n"
        "    res.status(200).json({});\n"
        "  } else if (req.method === 'POST') {\n"
        "    res.status(201).json({});\n"
        "  }\n"
        "}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/legacy/:userId"
    assert routes[0].methods == ["GET", "POST"]


def test_pages_router_index_file_does_not_append_index_to_path(tmp_path):
    _write(
        tmp_path,
        "pages/api/users/index.js",
        "export default function handler(req, res) {\n  res.status(200).json({});\n}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/users"


def test_app_and_pages_router_coexist_without_cross_contamination(tmp_path):
    _write(
        tmp_path,
        "app/api/orders/route.ts",
        "export async function GET(request) {\n  return Response.json({});\n}\n",
    )
    _write(
        tmp_path,
        "pages/api/legacy.js",
        "export default function handler(req, res) {\n  res.status(200).json({});\n}\n",
    )
    routes = NextJSAnalyzer(tmp_path).find_routes()
    assert len(routes) == 2
    assert {r.path for r in routes} == {"/api/orders", "/legacy"}


def test_global_middleware_auth_is_detected(tmp_path):
    _write(
        tmp_path,
        "app/api/orders/route.ts",
        "export async function GET(request) {\n  return Response.json({});\n}\n",
    )
    _write(
        tmp_path,
        "middleware.ts",
        "export function middleware(request) {\n"
        "  const token = getToken(request);\n"
        "  if (!token) { return Response.redirect('/login'); }\n"
        "}\n",
    )
    analyzer = NextJSAnalyzer(tmp_path)
    result = analyzer.analyze()
    assert result.global_auth_source is not None
    assert "middleware.ts" in result.global_auth_source[0]
