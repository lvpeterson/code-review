from languages.java.spring_analyzer import SpringAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_class_level_request_mapping_is_not_a_separate_route(tmp_path):
    _write(
        tmp_path,
        "UserController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/users\")\n"
        "public class UserController {\n"
        "    @GetMapping(\"/{id}\")\n"
        "    public User getUser(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert len(routes) == 1
    assert routes[0].path == "/api/users/{id}"


def test_preauthorize_found_regardless_of_order_above_mapping(tmp_path):
    _write(
        tmp_path,
        "UserController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/users\")\n"
        "public class UserController {\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "    @DeleteMapping(\"/{id}\")\n"
        "    public void deleteUser(@PathVariable Long id) {}\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].auth_decorators == ["PreAuthorize"]


def test_request_param_captured_as_extra_param(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/search\")\n"
        "    public Order search(@RequestParam Long userId) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].extra_param_names == ["userId"]


def test_bare_cross_origin_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "@CrossOrigin\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/\")\n"
        "    public String list() { return \"\"; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "CONFIG-002" for f in findings)


def test_cross_origin_with_specific_origin_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "@CrossOrigin(origins = \"https://example.com\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/\")\n"
        "    public String list() { return \"\"; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "CONFIG-002" for f in findings)
