from languages.javascript.express_analyzer import ExpressAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_router_mount_prefix_composition(tmp_path):
    _write(
        tmp_path,
        "itemsRouter.js",
        "const express = require('express');\n"
        "const router = express.Router();\n\n"
        "router.get('/:itemId', function (req, res) {\n"
        "  res.json({});\n"
        "});\n\n"
        "module.exports = router;\n",
    )
    _write(
        tmp_path,
        "server.js",
        "const express = require('express');\n"
        "const router = require('./itemsRouter');\n"
        "const app = express();\n\n"
        "app.use('/api/v1', router);\n\n"
        "module.exports = app;\n",
    )
    routes = ExpressAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/api/v1/:itemId"


def test_supertest_agent_named_app_is_not_a_route(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.get('/users/:userId', function (req, res) {\n"
        "  res.json({});\n"
        "});\n\n"
        "module.exports = app;\n",
    )
    _write(
        tmp_path,
        "server.test.js",
        "const supertest = require('supertest');\n"
        "const realServer = require('./server');\n\n"
        "const app = supertest.agent(realServer);\n"
        "app.get('/users/123');\n",
    )
    routes = ExpressAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].file == "server.js"


def test_query_and_body_field_captured_as_extra_params(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const express = require('express');\n"
        "const app = express();\n\n"
        "app.get('/search', function (req, res) {\n"
        "  const userId = req.query.userId;\n"
        "  res.json({});\n"
        "});\n",
    )
    routes = ExpressAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["userId"]


def test_bare_cors_call_is_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const express = require('express');\n"
        "const cors = require('cors');\n"
        "const app = express();\n\n"
        "app.use(cors());\n\n"
        "app.get('/x', function (req, res) { res.send('ok'); });\n",
    )
    analyzer = ExpressAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "CONFIG-002" for f in findings)


def test_cors_with_specific_origin_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "server.js",
        "const express = require('express');\n"
        "const cors = require('cors');\n"
        "const app = express();\n\n"
        "app.use(cors({ origin: 'https://example.com' }));\n\n"
        "app.get('/x', function (req, res) { res.send('ok'); });\n",
    )
    analyzer = ExpressAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "CONFIG-002" for f in findings)
