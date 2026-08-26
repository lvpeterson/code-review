from languages.python.flask_analyzer import FlaskAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_blueprint_url_prefix_is_applied(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import Flask, Blueprint\n"
        "app = Flask(__name__)\n"
        "bp = Blueprint('api', __name__)\n\n"
        "@bp.route('/users/<int:user_id>')\n"
        "def get_user(user_id):\n"
        "    return {}\n\n"
        "app.register_blueprint(bp, url_prefix='/api/v2')\n",
    )
    routes = FlaskAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/api/v2/users/<int:user_id>"


def test_mock_patch_decorator_is_not_a_route(tmp_path):
    _write(
        tmp_path,
        "test_app.py",
        "from unittest.mock import patch\n\n"
        "@patch('app.db.get_user')\n"
        "def test_something(mock_get_user):\n"
        "    assert True\n",
    )
    assert FlaskAnalyzer(tmp_path).find_routes() == []


def test_mock_dotted_patch_is_not_a_route(tmp_path):
    _write(
        tmp_path,
        "test_app.py",
        "from unittest import mock\n\n"
        "@mock.patch('app.db.save_user')\n"
        "def test_save(mock_save):\n"
        "    assert True\n",
    )
    assert FlaskAnalyzer(tmp_path).find_routes() == []


def test_real_patch_route_is_still_detected_alongside_mock(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.patch('/users/<int:user_id>')\n"
        "def update_user(user_id):\n"
        "    return {}\n",
    )
    routes = FlaskAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].methods == ["PATCH"]


def test_query_param_is_captured_as_extra_param(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    user_id = request.args.get('user_id')\n"
        "    return {}\n",
    )
    routes = FlaskAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["user_id"]


def test_debug_mode_is_flagged(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app.run(debug=True)\n",
    )
    analyzer = FlaskAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "CONFIG-001" for f in findings)


def test_no_debug_mode_no_finding(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app.run()\n",
    )
    analyzer = FlaskAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "CONFIG-001" for f in findings)
