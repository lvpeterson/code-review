from languages.javascript.hono_analyzer import HonoAnalyzer, _detect_global_use_middleware


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_basic_route_is_detected(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n\n"
        "const app = new Hono()\n\n"
        "app.get('/users/:userId', (c) => {\n"
        "  return c.json({})\n"
        "})\n\n"
        "export default app\n",
    )
    routes = HonoAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/users/:userId"
    assert routes[0].methods == ["GET"]


def test_route_mount_prefix_composition(tmp_path):
    _write(
        tmp_path,
        "itemsRoute.js",
        "import { Hono } from 'hono'\n\n"
        "const items = new Hono()\n\n"
        "items.get('/:itemId', (c) => c.json({}))\n\n"
        "export default items\n",
    )
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n"
        "import items from './itemsRoute'\n\n"
        "const app = new Hono()\n\n"
        "app.route('/api/v1', items)\n\n"
        "export default app\n",
    )
    routes = HonoAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/api/v1/:itemId"


def test_jwt_middleware_called_inline_is_recognized_as_auth(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n"
        "import { jwt } from 'hono/jwt'\n\n"
        "const app = new Hono()\n\n"
        "app.get('/orders/:orderId', jwt({ secret: 'x' }), (c) => c.json({}))\n\n"
        "export default app\n",
    )
    analyzer = HonoAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].auth_decorators == ["jwt"]
    findings = analyzer.run_baseline_checks(routes)
    assert not any(f.check_id == "AUTH-001" for f in findings)


def test_route_with_no_auth_middleware_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n\n"
        "const app = new Hono()\n\n"
        "app.get('/orders/:orderId', (c) => c.json({}))\n\n"
        "export default app\n",
    )
    analyzer = HonoAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "AUTH-001" for f in findings)


def test_bare_cors_call_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n"
        "import { cors } from 'hono/cors'\n\n"
        "const app = new Hono()\n\n"
        "app.use(cors())\n\n"
        "app.get('/x', (c) => c.text('ok'))\n",
    )
    analyzer = HonoAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "CONFIG-002" for f in findings)


def test_cors_with_specific_origin_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n"
        "import { cors } from 'hono/cors'\n\n"
        "const app = new Hono()\n\n"
        "app.use(cors({ origin: 'https://example.com' }))\n\n"
        "app.get('/x', (c) => c.text('ok'))\n",
    )
    analyzer = HonoAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "CONFIG-002" for f in findings)


def test_query_field_captured_as_extra_param(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n\n"
        "const app = new Hono()\n\n"
        "app.get('/search', (c) => {\n"
        "  const userId = c.req.query('userId')\n"
        "  return c.json({})\n"
        "})\n",
    )
    routes = HonoAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["userId"]


def test_global_jwt_middleware_use_is_detected(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n"
        "import { jwt } from 'hono/jwt'\n\n"
        "const app = new Hono()\n\n"
        "app.use('/api/*', jwt({ secret: 'x' }))\n\n"
        "app.get('/api/orders/:orderId', (c) => c.json({}))\n\n"
        "export default app\n",
    )
    detected = _detect_global_use_middleware(tmp_path)
    assert detected is not None
    file, line, description = detected
    assert file == "server.js"
    assert "jwt" in description


def test_route_covered_only_by_global_middleware_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "import { Hono } from 'hono'\n"
        "import { jwt } from 'hono/jwt'\n\n"
        "const app = new Hono()\n\n"
        "app.use('/api/*', jwt({ secret: 'x' }))\n\n"
        "app.get('/api/orders/:orderId', (c) => c.json({}))\n\n"
        "export default app\n",
    )
    analyzer = HonoAnalyzer(tmp_path)
    result = analyzer.analyze()
    assert result.global_auth_source is not None
    auth_findings = [f for f in result.findings if f.check_id == "AUTH-001"]
    assert len(auth_findings) == 1
    assert "global auth mechanism" in auth_findings[0].description
