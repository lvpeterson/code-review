from languages.python.django_analyzer import DjangoAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def _basic_project(tmp_path, view_body):
    _write(
        tmp_path,
        "urls.py",
        "from django.urls import path\n"
        "from . import views\n\n"
        "urlpatterns = [path('search/', views.search, name='search')]\n",
    )
    _write(tmp_path, "views.py", view_body)


def test_query_param_is_captured_from_view_body(tmp_path):
    _basic_project(
        tmp_path,
        "def search(request):\n"
        "    user_id = request.GET.get('user_id')\n"
        "    return None\n",
    )
    routes = DjangoAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["user_id"]


def test_debug_true_is_flagged(tmp_path):
    _basic_project(tmp_path, "def search(request):\n    return None\n")
    _write(tmp_path, "settings.py", "DEBUG = True\n")
    analyzer = DjangoAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "CONFIG-001" for f in findings)


def test_debug_false_is_not_flagged(tmp_path):
    _basic_project(tmp_path, "def search(request):\n    return None\n")
    _write(tmp_path, "settings.py", "DEBUG = False\n")
    analyzer = DjangoAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "CONFIG-001" for f in findings)


def test_view_defined_in_different_file_resolves_source_location(tmp_path):
    _basic_project(
        tmp_path,
        "def search(request):\n"
        "    return None\n",
    )
    routes = DjangoAnalyzer(tmp_path).find_routes()
    assert routes[0].file == "urls.py"
    assert routes[0].source_file == "views.py"
