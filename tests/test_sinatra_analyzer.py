from languages.ruby.sinatra_analyzer import SinatraAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_get_route_with_path_param(tmp_path):
    _write(tmp_path, "app.rb", "get '/users/:id' do\n  \"hello\"\nend\n")
    routes = SinatraAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/users/:id"
    assert routes[0].methods == ["GET"]


def test_auth_call_in_block_body_is_detected(tmp_path):
    _write(
        tmp_path,
        "app.rb",
        "post '/orders' do\n  authenticate!\n  \"created\"\nend\n",
    )
    routes = SinatraAnalyzer(tmp_path).find_routes()
    assert "authenticate!" in routes[0].auth_decorators


def test_multiple_verbs_extracted_independently(tmp_path):
    _write(
        tmp_path,
        "app.rb",
        "get '/x' do\nend\n\npost '/x' do\nend\n\ndelete '/x/:id' do\nend\n",
    )
    routes = SinatraAnalyzer(tmp_path).find_routes()
    assert sorted(r.methods[0] for r in routes) == ["DELETE", "GET", "POST"]
