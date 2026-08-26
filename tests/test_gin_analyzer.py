from languages.go.gin_analyzer import GinAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_confirmed_gin_router_routes_are_extracted(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "github.com/gin-gonic/gin"\n\n'
        "func main() {\n"
        "\trouter := gin.Default()\n"
        '\trouter.GET("/users/:userId", getUser)\n'
        "}\n\n"
        "func getUser(c *gin.Context) {\n"
        '\tid := c.Param("userId")\n'
        "}\n",
    )
    routes = GinAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/users/:userId"
    assert routes[0].methods == ["GET"]
    assert routes[0].handler_name == "getUser"


def test_unconfirmed_identifier_is_not_claimed(tmp_path):
    # some arbitrary struct with its own .GET method shouldn't be mistaken
    # for a gin router just because the method name matches
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        "func main() {\n"
        '\tclient.GET("/users/:userId", getUser)\n'
        "}\n",
    )
    assert GinAnalyzer(tmp_path).find_routes() == []


def test_inline_middleware_arg_captured_as_auth_decorator(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "github.com/gin-gonic/gin"\n\n'
        "func main() {\n"
        "\trouter := gin.Default()\n"
        '\trouter.POST("/orders", authMiddleware, createOrder)\n'
        "}\n\n"
        "func createOrder(c *gin.Context) {}\n",
    )
    routes = GinAnalyzer(tmp_path).find_routes()
    assert "authMiddleware" in routes[0].auth_decorators


def test_query_param_captured_from_handler_body(tmp_path):
    _write(
        tmp_path,
        "main.go",
        "package main\n\n"
        'import "github.com/gin-gonic/gin"\n\n'
        "func main() {\n"
        "\trouter := gin.Default()\n"
        '\trouter.GET("/search", search)\n'
        "}\n\n"
        "func search(c *gin.Context) {\n"
        '\tuserId := c.Query("userId")\n'
        "}\n",
    )
    routes = GinAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["userId"]
