from languages.go.net_http_analyzer import NetHTTPAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_go122_method_prefixed_path_is_split(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "net/http"\n\n'
        "func main() {\n"
        "\tmux := http.NewServeMux()\n"
        '\tmux.HandleFunc("GET /items/{itemId}", getItem)\n'
        "}\n\n"
        "func getItem(w http.ResponseWriter, r *http.Request) {}\n",
    )
    routes = NetHTTPAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/items/{itemId}"
    assert routes[0].methods == ["GET"]


def test_method_sniffed_from_handler_body_when_no_prefix(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "net/http"\n\n'
        "func main() {\n"
        "\tmux := http.NewServeMux()\n"
        '\tmux.HandleFunc("/health", healthHandler)\n'
        "}\n\n"
        "func healthHandler(w http.ResponseWriter, r *http.Request) {\n"
        '\tif r.Method == "GET" {\n'
        "\t\tw.Write([]byte(\"ok\"))\n"
        "\t}\n"
        "}\n",
    )
    routes = NetHTTPAnalyzer(tmp_path).find_routes()
    assert routes[0].methods == ["GET"]


def test_undetermined_methods_default_to_common_list(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "net/http"\n\n'
        "func main() {\n"
        "\tmux := http.NewServeMux()\n"
        '\tmux.HandleFunc("/echo", echoHandler)\n'
        "}\n\n"
        "func echoHandler(w http.ResponseWriter, r *http.Request) {\n"
        "\tw.Write([]byte(\"echo\"))\n"
        "}\n",
    )
    routes = NetHTTPAnalyzer(tmp_path).find_routes()
    assert "GET" in routes[0].methods and "POST" in routes[0].methods


def test_query_param_captured_from_handler_body(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "net/http"\n\n'
        "func main() {\n"
        "\tmux := http.NewServeMux()\n"
        '\tmux.HandleFunc("/search", search)\n'
        "}\n\n"
        "func search(w http.ResponseWriter, r *http.Request) {\n"
        '\tq := r.URL.Query().Get("userId")\n'
        "}\n",
    )
    routes = NetHTTPAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["userId"]
