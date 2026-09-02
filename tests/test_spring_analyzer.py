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


def test_path_variable_constraint_captured_and_class_validated_detected(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.validation.annotation.Validated;\n"
        "import jakarta.validation.constraints.Positive;\n\n"
        "@RestController\n"
        "@Validated\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/{orderId}\")\n"
        "    public Order getOrder(@PathVariable @Positive Long orderId) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].class_validated is True
    assert routes[0].param_validations == {"orderId": ["Positive"]}


def test_constraint_without_class_validated_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import jakarta.validation.constraints.Positive;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/{orderId}\")\n"
        "    public Order getOrder(@PathVariable @Positive Long orderId) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "VALID-001" for f in findings)


def test_path_variable_without_any_constraint_is_not_flagged_by_valid_001(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/{orderId}\")\n"
        "    public Order getOrder(@PathVariable Long orderId) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "VALID-001" for f in findings)


def test_spring_boot_version_detected_from_parent_pom(tmp_path):
    _write(
        tmp_path,
        "pom.xml",
        "<project>\n"
        "  <parent>\n"
        "    <groupId>org.springframework.boot</groupId>\n"
        "    <artifactId>spring-boot-starter-parent</artifactId>\n"
        "    <version>2.1.0.RELEASE</version>\n"
        "  </parent>\n"
        "</project>\n",
    )
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/\")\n"
        "    public String list() { return \"\"; }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert result.framework_version == "2.1.0.RELEASE"
    assert result.framework_version_label == "Spring Boot"
    assert any(f.check_id == "CONFIG-003" and f.severity == "medium" for f in result.findings)


def test_request_body_without_valid_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PostMapping(\"/\")\n"
        "    public Order create(@RequestBody OrderDto dto) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].request_body_validations == {"dto": False}
    findings = analyzer.run_baseline_checks(routes)
    assert any(f.check_id == "VALID-002" for f in findings)


def test_request_body_with_valid_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import jakarta.validation.Valid;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PostMapping(\"/\")\n"
        "    public Order create(@Valid @RequestBody OrderDto dto) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].request_body_validations == {"dto": True}
    findings = analyzer.run_baseline_checks(routes)
    assert not any(f.check_id == "VALID-002" for f in findings)


def test_spring_boot_version_resolved_from_gradle_version_catalog(tmp_path):
    _write(
        tmp_path,
        "build.gradle.kts",
        'plugins {\n    id("org.springframework.boot") // resolved via alias\n}\n'
        'alias(libs.plugins.spring.boot)\n',
    )
    (tmp_path / "gradle").mkdir()
    _write(
        tmp_path,
        "gradle/libs.versions.toml",
        "[versions]\nspring-boot = \"3.2.1\"\n",
    )
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/\")\n"
        "    public String list() { return \"\"; }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert result.framework_version == "3.2.1"
    assert result.framework_version_label == "Spring Boot"


def test_multi_module_maven_prefers_root_pom_for_version(tmp_path):
    # Both poms directly declare spring-boot-starter-parent (an unusual but
    # real multi-module layout) with different versions -- root must win
    # regardless of filesystem traversal order.
    _write(
        tmp_path,
        "pom.xml",
        "<project>\n"
        "  <parent>\n"
        "    <groupId>org.springframework.boot</groupId>\n"
        "    <artifactId>spring-boot-starter-parent</artifactId>\n"
        "    <version>3.1.4</version>\n"
        "  </parent>\n"
        "  <modules><module>service</module></modules>\n"
        "</project>\n",
    )
    (tmp_path / "service").mkdir()
    _write(
        tmp_path,
        "service/pom.xml",
        "<project>\n"
        "  <parent>\n"
        "    <groupId>org.springframework.boot</groupId>\n"
        "    <artifactId>spring-boot-starter-parent</artifactId>\n"
        "    <version>1.5.22.RELEASE</version>\n"
        "  </parent>\n"
        "</project>\n",
    )
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/\")\n"
        "    public String list() { return \"\"; }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert result.framework_version == "3.1.4"
    assert result.framework_version_source[0] == "pom.xml"
