from languages.dotnet.aspnet_analyzer import AspNetAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_minimal_api_routes_are_extracted(tmp_path):
    _write(
        tmp_path,
        "Program.cs",
        'var app = WebApplication.Create();\n'
        'app.MapGet("/users/{id}", GetUser);\n'
        "app.Run();\n",
    )
    routes = AspNetAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/users/{id}"
    assert routes[0].methods == ["GET"]
    assert routes[0].handler_name == "GetUser"


def test_minimal_api_middleware_arg_captured_as_auth(tmp_path):
    _write(
        tmp_path,
        "Program.cs",
        'var app = WebApplication.Create();\n'
        'app.MapPost("/orders", RequireAuth, CreateOrder);\n',
    )
    routes = AspNetAnalyzer(tmp_path).find_routes()
    assert routes[0].auth_decorators == ["RequireAuth"]


def test_attribute_routing_combines_class_and_method_path(tmp_path):
    _write(
        tmp_path,
        "UsersController.cs",
        "[ApiController]\n"
        '[Route("api/users")]\n'
        "public class UsersController : ControllerBase\n"
        "{\n"
        '    [HttpGet("{id}")]\n'
        "    public User GetUser(int id) { return null; }\n"
        "}\n",
    )
    routes = AspNetAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/api/users/{id}"


def test_controller_token_is_substituted_with_class_name(tmp_path):
    _write(
        tmp_path,
        "UsersController.cs",
        "[ApiController]\n"
        '[Route("api/[controller]")]\n'
        "public class UsersController : ControllerBase\n"
        "{\n"
        '    [HttpGet("{id}")]\n'
        "    public User GetUser(int id) { return null; }\n"
        "}\n",
    )
    routes = AspNetAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/Users/{id}"


def test_authorize_attribute_found_regardless_of_order(tmp_path):
    _write(
        tmp_path,
        "UsersController.cs",
        "[ApiController]\n"
        '[Route("api/users")]\n'
        "public class UsersController : ControllerBase\n"
        "{\n"
        "    [Authorize]\n"
        '    [HttpDelete("{id}")]\n'
        "    public void DeleteUser(int id) {}\n"
        "}\n",
    )
    routes = AspNetAnalyzer(tmp_path).find_routes()
    assert routes[0].auth_decorators == ["Authorize"]


def test_non_controller_class_is_ignored(tmp_path):
    _write(
        tmp_path,
        "Helper.cs",
        "public class Helper\n"
        "{\n"
        '    [HttpGet("{id}")]\n'
        "    public void NotARoute(int id) {}\n"
        "}\n",
    )
    assert AspNetAnalyzer(tmp_path).find_routes() == []


def test_minimal_api_and_attribute_routing_coexist(tmp_path):
    _write(
        tmp_path,
        "Program.cs",
        'var app = WebApplication.Create();\n'
        'app.MapGet("/health", HealthCheck);\n',
    )
    _write(
        tmp_path,
        "UsersController.cs",
        "[ApiController]\n"
        '[Route("api/users")]\n'
        "public class UsersController : ControllerBase\n"
        "{\n"
        '    [HttpGet("{id}")]\n'
        "    public User GetUser(int id) { return null; }\n"
        "}\n",
    )
    routes = AspNetAnalyzer(tmp_path).find_routes()
    assert {r.path for r in routes} == {"/health", "/api/users/{id}"}
