from languages.python.fastapi_analyzer import FastAPIAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_nested_router_prefix_composition(tmp_path):
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI, APIRouter\n"
        "app = FastAPI()\n"
        "v1_router = APIRouter()\n"
        "items_router = APIRouter()\n\n"
        "@items_router.get('/{item_id}')\n"
        "def get_item(item_id: int):\n"
        "    return {}\n\n"
        "v1_router.include_router(items_router, prefix='/items')\n"
        "app.include_router(v1_router, prefix='/v1')\n",
    )
    routes = FastAPIAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/v1/items/{item_id}"


def test_depends_param_excluded_from_extra_params(tmp_path):
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n\n"
        "@app.get('/search')\n"
        "def search(user_id: int, current_user=Depends(get_current_user)):\n"
        "    return {}\n",
    )
    routes = FastAPIAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["user_id"]
    assert routes[0].auth_decorators == ["get_current_user"]


def test_path_param_excluded_from_extra_params(tmp_path):
    _write(
        tmp_path,
        "main.py",
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n\n"
        "@app.get('/items/{item_id}')\n"
        "def get_item(item_id: int, sort: str = 'asc'):\n"
        "    return {}\n",
    )
    routes = FastAPIAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["sort"]


def test_flask_shortcut_lookalike_not_claimed_when_confirmed_flask(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.get('/x')\n"
        "def handler():\n"
        "    return {}\n",
    )
    assert FastAPIAnalyzer(tmp_path).find_routes() == []
