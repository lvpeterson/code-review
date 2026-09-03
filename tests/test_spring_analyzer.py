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


def test_path_variable_binding_name_captured_even_when_it_diverges_from_url_name(tmp_path):
    # A kebab-case URL segment requires an explicit @PathVariable("...")
    # binding, since Java identifiers can't contain hyphens -- the report's
    # code-view highlighting needs the Java-side name (orderId) to find
    # where the value is actually used in the handler body, since the
    # URL-side name (order-id) only ever appears inside the annotation's
    # string literal.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/{order-id}\")\n"
        "    public Order getOrder(@PathVariable(\"order-id\") Long orderId) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/orders/{order-id}"
    assert routes[0].path_variable_binding_names == ["orderId"]


def test_path_attribute_alias_is_recognized_at_method_level(tmp_path):
    # regression: `path = "..."` is Spring's own alias for the positional
    # `value` attribute, commonly used instead of it once another named
    # attribute (produces, method, ...) is also set on the same annotation.
    # Missing this used to silently truncate the whole sub-path down to the
    # class-level base path, not just drop one param.
    _write(
        tmp_path,
        "UserController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/users\")\n"
        "public class UserController {\n"
        "    @GetMapping(path = \"/{id}\", produces = \"application/json\")\n"
        "    public User getUser(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/users/{id}"


def test_path_attribute_alias_is_recognized_at_class_level(tmp_path):
    _write(
        tmp_path,
        "UserController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(path = \"/api/users\")\n"
        "public class UserController {\n"
        "    @GetMapping(\"/{id}\")\n"
        "    public User getUser(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/users/{id}"


def test_array_valued_mapping_uses_first_path_instead_of_dropping_route(tmp_path):
    # regression: @GetMapping({"/a", "/b"}) parses to an ElementArrayValue,
    # not a bare Literal -- unhandled, this used to silently truncate the
    # whole sub-path (and any path params in it) down to the class-level
    # base path instead of just picking one of the two equivalent paths.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping({\"/{orderId}\", \"/legacy/{orderId}\"})\n"
        "    public Order getOrder(@PathVariable Long orderId) { return null; }\n"
        "}\n",
    )
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].path == "/api/orders/{orderId}"


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


def test_class_level_validated_does_not_suppress_request_body_check(tmp_path):
    # @Validated on the class only governs @PathVariable/@RequestParam
    # constraints (VALID-001) -- it has no effect on @RequestBody, which
    # needs its own @Valid regardless. VALID-002 must still fire here.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.validation.annotation.Validated;\n\n"
        "@RestController\n"
        "@Validated\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PostMapping(\"/\")\n"
        "    public Order create(@RequestBody OrderDto dto) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].class_validated is True
    findings = analyzer.run_baseline_checks(routes)
    assert any(f.check_id == "VALID-002" for f in findings)


def test_direct_constraint_on_request_body_param_is_enforced_by_class_validated(tmp_path):
    # @NotNull directly on the @RequestBody parameter (not on a field inside
    # its type) is a *direct* constraint -- enforced by class-level
    # @Validated via the same AOP path as @PathVariable/@RequestParam.
    # @Valid is irrelevant to it, so VALID-001 must NOT fire even though
    # @Valid is absent. VALID-002 (the separate cascade-into-the-type's-own-
    # fields concern) still fires regardless -- it fires for every
    # @RequestBody missing @Valid with no type-based exception, since this
    # is a triage heuristic and a human traces the actual usage either way.
    # Both facts are simultaneously true: the direct constraint is enforced,
    # and the cascade gap is still worth a look.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import java.util.List;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.validation.annotation.Validated;\n"
        "import jakarta.validation.constraints.NotNull;\n\n"
        "@RestController\n"
        "@Validated\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PostMapping(\"/\")\n"
        "    public Order create(@RequestBody @NotNull List<String> someList) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].param_validations == {"someList": ["NotNull"]}
    findings = analyzer.run_baseline_checks(routes)
    assert not any(f.check_id == "VALID-001" for f in findings)
    assert any(f.check_id == "VALID-002" for f in findings)


def test_direct_constraint_on_request_body_param_without_class_validated_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import java.util.List;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import jakarta.validation.constraints.NotNull;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PostMapping(\"/\")\n"
        "    public Order create(@RequestBody @NotNull List<String> someList) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert any(f.check_id == "VALID-001" for f in findings)


def test_unconstrained_request_body_param_not_double_counted_in_param_validations(tmp_path):
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
    routes = SpringAnalyzer(tmp_path).find_routes()
    assert routes[0].param_validations == {}
    assert routes[0].request_body_validations == {"dto": False}


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


def test_class_level_preauthorize_covers_every_method(tmp_path):
    # regression: a class-level @PreAuthorize applies to every method in
    # the controller, same as class-level @Validated -- missing this used
    # to make every route in such a class a false-positive AUTH-001.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.security.access.prepost.PreAuthorize;\n\n"
        "@RestController\n"
        "@PreAuthorize(\"hasRole('ADMIN')\")\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/{id}\")\n"
        "    public Order get(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].auth_decorators == ["PreAuthorize"]
    findings = analyzer.run_baseline_checks(routes)
    assert not any(f.check_id == "AUTH-001" for f in findings)


def test_method_security_not_enabled_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.security.access.prepost.PreAuthorize;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "    @GetMapping(\"/{id}\")\n"
        "    public Order get(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert any(f.check_id == "AUTH-002" for f in result.findings)


def test_method_security_enabled_suppresses_the_finding(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "import org.springframework.security.access.prepost.PreAuthorize;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "    @GetMapping(\"/{id}\")\n"
        "    public Order get(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "import org.springframework.context.annotation.Configuration;\n"
        "import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;\n\n"
        "@Configuration\n"
        "@EnableMethodSecurity\n"
        "public class SecurityConfig {}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert not any(f.check_id == "AUTH-002" for f in result.findings)


def test_csrf_disabled_lambda_style_is_flagged(tmp_path):
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "public class SecurityConfig {\n"
        "    public void configure(HttpSecurity http) {\n"
        "        http.csrf(csrf -> csrf.disable());\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "AUTH-003" for f in findings)


def test_csrf_disabled_legacy_style_is_flagged(tmp_path):
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "public class SecurityConfig {\n"
        "    public void configure(HttpSecurity http) {\n"
        "        http.csrf().disable();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "AUTH-003" for f in findings)


def test_csrf_not_mentioned_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "public class SecurityConfig {\n"
        "    public void configure(HttpSecurity http) {\n"
        "        http.formLogin();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "AUTH-003" for f in findings)


def test_actuator_wildcard_exposure_flattened_key_is_flagged(tmp_path):
    _write(
        tmp_path,
        "application.properties",
        "management.endpoints.web.exposure.include=*\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "AUTH-004" for f in findings)


def test_actuator_sensitive_endpoint_nested_yaml_is_flagged(tmp_path):
    _write(
        tmp_path,
        "application.yml",
        "management:\n"
        "  endpoints:\n"
        "    web:\n"
        "      exposure:\n"
        "        include: env,heapdump\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "AUTH-004" for f in findings)


def test_actuator_health_only_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "application.properties",
        "management.endpoints.web.exposure.include=health\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "AUTH-004" for f in findings)


def test_matcher_verdict_resolves_permitall_and_downgrades_severity(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/public/status\")\n"
        "    public String status() { return \"\"; }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "public class SecurityConfig {\n"
        "    public SecurityFilterChain filterChain(HttpSecurity http) {\n"
        "        http.authorizeHttpRequests(auth -> auth\n"
        "            .requestMatchers(\"/api/orders/public/**\").permitAll()\n"
        "            .anyRequest().authenticated()\n"
        "        );\n"
        "        return http.build();\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    route = result.routes[0]
    assert route.auth_matcher_verdict == "permitAll()"
    auth_finding = next(f for f in result.findings if f.check_id == "AUTH-001")
    assert auth_finding.severity == "info"


def test_matcher_verdict_resolves_role_requirement_more_specific_pattern_wins(tmp_path):
    # first matching pattern wins, same as Spring's own evaluation order --
    # the more specific /api/orders/** rule must beat the anyRequest() catch-all
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(\"/{id}\")\n"
        "    public Order get(@PathVariable Long id) { return null; }\n"
        "}\n",
    )
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "public class SecurityConfig {\n"
        "    public SecurityFilterChain filterChain(HttpSecurity http) {\n"
        "        http.authorizeHttpRequests(auth -> auth\n"
        "            .requestMatchers(\"/api/orders/**\").hasRole(\"ADMIN\")\n"
        "            .anyRequest().authenticated()\n"
        "        );\n"
        "        return http.build();\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    route = result.routes[0]
    assert route.auth_matcher_verdict == "hasRole(ADMIN)"
    auth_finding = next(f for f in result.findings if f.check_id == "AUTH-001")
    assert auth_finding.severity == "low"


def test_actuator_permitall_coverage_is_flagged(tmp_path):
    _write(
        tmp_path,
        "application.properties",
        "management.endpoints.web.exposure.include=*\n",
    )
    _write(
        tmp_path,
        "SecurityConfig.java",
        "package com.example;\n"
        "public class SecurityConfig {\n"
        "    public SecurityFilterChain filterChain(HttpSecurity http) {\n"
        "        http.authorizeHttpRequests(auth -> auth\n"
        "            .requestMatchers(\"/actuator/**\").permitAll()\n"
        "            .anyRequest().authenticated()\n"
        "        );\n"
        "        return http.build();\n"
        "    }\n"
        "}\n",
    )
    result = SpringAnalyzer(tmp_path).analyze()
    assert any(f.check_id == "AUTH-005" for f in result.findings)


def test_xml_literal_produces_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(value = \"/legacy\", produces = \"application/xml\")\n"
        "    public String legacy() { return \"\"; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].xml_media_types == ["application/xml"]
    findings = analyzer.run_baseline_checks(routes)
    assert any(f.check_id == "XML-001" for f in findings)


def test_xml_spring_mediatype_constant_is_flagged(tmp_path):
    # regression: MediaType.APPLICATION_XML_VALUE resolves (via
    # _first_literal_value-style MemberReference handling) to the constant
    # NAME "APPLICATION_XML_VALUE", not the literal string "application/xml"
    # -- detection has to work off the constant name too, not just literals.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.http.MediaType;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(value = \"/legacy\", produces = MediaType.APPLICATION_XML_VALUE)\n"
        "    public String legacy() { return \"\"; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].xml_media_types == ["APPLICATION_XML_VALUE"]
    findings = analyzer.run_baseline_checks(routes)
    assert any(f.check_id == "XML-001" for f in findings)


def test_xml_as_second_entry_in_produces_array_is_still_caught(tmp_path):
    # regression: produces is array-typed -- a naive "first value only"
    # extraction (fine for a single-valued attribute like a mapping path)
    # would silently drop an XML format listed after a JSON one.
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(value = \"/items\", produces = {\"application/json\", \"application/xml\"})\n"
        "    public String items() { return \"\"; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    routes = analyzer.find_routes()
    assert routes[0].xml_media_types == ["application/xml"]
    findings = analyzer.run_baseline_checks(routes)
    assert any(f.check_id == "XML-001" for f in findings)


def test_json_only_produces_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n\n"
        "@RestController\n"
        "@RequestMapping(\"/api/orders\")\n"
        "public class OrderController {\n"
        "    @GetMapping(value = \"/status\", produces = \"application/json\")\n"
        "    public String status() { return \"\"; }\n"
        "}\n",
    )
    analyzer = SpringAnalyzer(tmp_path)
    findings = analyzer.run_baseline_checks(analyzer.find_routes())
    assert not any(f.check_id == "XML-001" for f in findings)
