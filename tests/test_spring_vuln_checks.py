"""Tests for the general dangerous-sink/vulnerability-class checks added
on top of the route/auth-specific analysis in test_spring_analyzer.py:
SQL injection via concatenation, AOP self-invocation bypass, insecure
cookie flags, and open redirect.
"""
from languages.java.spring_analyzer import SpringAnalyzer


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_sql_concatenation_in_create_query_is_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderRepositoryImpl.java",
        "package com.example;\n"
        "public class OrderRepositoryImpl {\n"
        "    void f(String userInput, EntityManager em) {\n"
        "        em.createQuery(\"SELECT o FROM Order o WHERE o.sku = '\" + userInput + \"'\");\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "SQLI-001" for f in findings)


def test_sql_with_bind_parameter_variable_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderRepositoryImpl.java",
        "package com.example;\n"
        "public class OrderRepositoryImpl {\n"
        "    void f(String sku, EntityManager em) {\n"
        "        String query = \"SELECT o FROM Order o WHERE o.sku = :sku\";\n"
        "        em.createQuery(query).setParameter(\"sku\", sku);\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "SQLI-001" for f in findings)


def test_sql_concatenation_jdbc_template_and_prepare_statement_are_flagged(tmp_path):
    _write(
        tmp_path,
        "Repo.java",
        "package com.example;\n"
        "public class Repo {\n"
        "    void f(String userInput, JdbcTemplate jdbcTemplate, Connection conn) throws Exception {\n"
        "        jdbcTemplate.queryForObject(\"SELECT * FROM x WHERE y = '\" + userInput + \"'\", String.class);\n"
        "        conn.prepareStatement(\"SELECT * FROM x WHERE y = '\" + userInput + \"'\");\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert sum(1 for f in findings if f.check_id == "SQLI-001") == 2


def test_bare_self_invocation_bypasses_transactional(tmp_path):
    _write(
        tmp_path,
        "OrderService.java",
        "package com.example;\n"
        "import org.springframework.transaction.annotation.Transactional;\n\n"
        "public class OrderService {\n"
        "    @Transactional\n"
        "    void chargeCard() {}\n"
        "    void refund() {\n"
        "        chargeCard();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    finding = next(f for f in findings if f.check_id == "PROXY-001")
    assert finding.severity == "medium"


def test_this_qualified_self_invocation_bypasses_preauthorize(tmp_path):
    _write(
        tmp_path,
        "OrderService.java",
        "package com.example;\n"
        "import org.springframework.security.access.prepost.PreAuthorize;\n\n"
        "public class OrderService {\n"
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
        "    void deleteAll() {}\n"
        "    void cleanup() {\n"
        "        this.deleteAll();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    finding = next(f for f in findings if f.check_id == "PROXY-001")
    assert finding.severity == "high"


def test_call_from_a_different_class_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "OrderService.java",
        "package com.example;\n"
        "import org.springframework.transaction.annotation.Transactional;\n\n"
        "public class OrderService {\n"
        "    @Transactional\n"
        "    void chargeCard() {}\n"
        "}\n",
    )
    _write(
        tmp_path,
        "OrderController.java",
        "package com.example;\n"
        "public class OrderController {\n"
        "    void handle(OrderService service) {\n"
        "        service.chargeCard();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "PROXY-001" for f in findings)


def test_cookie_missing_secure_and_httponly_is_flagged(tmp_path):
    _write(
        tmp_path,
        "CookieController.java",
        "package com.example;\n"
        "import javax.servlet.http.Cookie;\n\n"
        "public class CookieController {\n"
        "    void f(javax.servlet.http.HttpServletResponse response) {\n"
        "        Cookie cookie = new Cookie(\"session\", \"abc123\");\n"
        "        response.addCookie(cookie);\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    finding = next(f for f in findings if f.check_id == "AUTH-006")
    assert "Secure" in finding.title and "HttpOnly" in finding.title


def test_cookie_with_secure_and_httponly_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "CookieController.java",
        "package com.example;\n"
        "import javax.servlet.http.Cookie;\n\n"
        "public class CookieController {\n"
        "    void f(javax.servlet.http.HttpServletResponse response) {\n"
        "        Cookie cookie = new Cookie(\"session\", \"abc123\");\n"
        "        cookie.setSecure(true);\n"
        "        cookie.setHttpOnly(true);\n"
        "        response.addCookie(cookie);\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "AUTH-006" for f in findings)


def test_response_cookie_builder_missing_flags_is_flagged(tmp_path):
    _write(
        tmp_path,
        "CookieController.java",
        "package com.example;\n"
        "public class CookieController {\n"
        "    void f() {\n"
        "        ResponseCookie cookie = ResponseCookie.from(\"session\", \"abc123\").build();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "AUTH-006" for f in findings)


def test_send_redirect_with_dynamic_target_is_flagged(tmp_path):
    _write(
        tmp_path,
        "RedirectController.java",
        "package com.example;\n"
        "public class RedirectController {\n"
        "    void f(javax.servlet.http.HttpServletResponse response, String userInput) throws Exception {\n"
        "        response.sendRedirect(userInput);\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "REDIRECT-001" for f in findings)


def test_send_redirect_with_literal_target_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "RedirectController.java",
        "package com.example;\n"
        "public class RedirectController {\n"
        "    void f(javax.servlet.http.HttpServletResponse response) throws Exception {\n"
        "        response.sendRedirect(\"/home\");\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "REDIRECT-001" for f in findings)


def test_location_header_with_dynamic_value_is_flagged(tmp_path):
    _write(
        tmp_path,
        "RedirectController.java",
        "package com.example;\n"
        "public class RedirectController {\n"
        "    ResponseEntity<Void> f(String userInput) {\n"
        "        return ResponseEntity.status(302).header(\"Location\", userInput).build();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert any(f.check_id == "REDIRECT-001" for f in findings)


def test_unrelated_header_call_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "SomeController.java",
        "package com.example;\n"
        "public class SomeController {\n"
        "    ResponseEntity<Void> f(String userInput) {\n"
        "        return ResponseEntity.ok().header(\"X-Custom\", userInput).build();\n"
        "    }\n"
        "}\n",
    )
    findings = SpringAnalyzer(tmp_path).run_baseline_checks([])
    assert not any(f.check_id == "REDIRECT-001" for f in findings)
