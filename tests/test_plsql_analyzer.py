from pathlib import Path

from checks import plsql
from core.html_report import render_html
from enumerator import enumerate_target
from languages.sql import detector


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def _ids(tmp_path):
    return [h.rule.id for h in plsql.scan_project(tmp_path)]


def test_execute_immediate_concatenating_a_variable_is_flagged(tmp_path):
    _write(
        tmp_path,
        "pkg.pkb",
        "CREATE OR REPLACE PROCEDURE drop_it(p_name VARCHAR2) AUTHID CURRENT_USER IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE 'DELETE FROM t WHERE name = ''' || p_name || '''';\n"
        "EXCEPTION\n"
        "  WHEN NO_DATA_FOUND THEN RAISE;\n"
        "END;\n",
    )
    assert "INJ-1" in _ids(tmp_path)


def test_execute_immediate_concatenating_only_literals_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "pkg.pkb",
        "CREATE OR REPLACE PROCEDURE p AUTHID CURRENT_USER IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE 'TRUNCATE ' || 'TABLE ' || 'staging';\n"
        "EXCEPTION\n"
        "  WHEN NO_DATA_FOUND THEN RAISE;\n"
        "END;\n",
    )
    assert "INJ-1" not in _ids(tmp_path)


def test_swallowing_others_handler_is_flagged_even_if_unit_raises_elsewhere(tmp_path):
    # The RAISE belongs to the NO_DATA_FOUND handler, not to WHEN OTHERS --
    # scoping EXC-2's suppression to the whole unit used to hide this.
    _write(
        tmp_path,
        "p.prc",
        "CREATE OR REPLACE PROCEDURE p AUTHID CURRENT_USER IS\n"
        "BEGIN\n"
        "  UPDATE t SET x = 1;\n"
        "EXCEPTION\n"
        "  WHEN NO_DATA_FOUND THEN\n"
        "    RAISE;\n"
        "  WHEN OTHERS THEN\n"
        "    v_count := 0;\n"
        "END;\n",
    )
    assert "EXC-2" in _ids(tmp_path)


def test_others_handler_that_reraises_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        "CREATE OR REPLACE PROCEDURE p AUTHID CURRENT_USER IS\n"
        "BEGIN\n"
        "  UPDATE t SET x = 1;\n"
        "EXCEPTION\n"
        "  WHEN OTHERS THEN\n"
        "    ROLLBACK;\n"
        "    RAISE;\n"
        "END;\n",
    )
    assert "EXC-2" not in _ids(tmp_path)


def test_case_when_inside_others_handler_does_not_end_handler_early(tmp_path):
    # The CASE's own WHEN must not be mistaken for the next sibling handler,
    # or the RAISE after it would fall outside the extracted handler text.
    _write(
        tmp_path,
        "p.prc",
        "CREATE OR REPLACE PROCEDURE p AUTHID CURRENT_USER IS\n"
        "BEGIN\n"
        "  UPDATE t SET x = 1;\n"
        "EXCEPTION\n"
        "  WHEN OTHERS THEN\n"
        "    CASE SQLCODE\n"
        "      WHEN -1 THEN v_msg := 'dup';\n"
        "      ELSE v_msg := 'other';\n"
        "    END CASE;\n"
        "    RAISE;\n"
        "END;\n",
    )
    assert "EXC-2" not in _ids(tmp_path)


def test_dedup_does_not_mutate_shared_rule_descriptions(tmp_path):
    before = {r.id: r.description for r in plsql.RULES}
    # CREATE PROCEDURE without AUTHID or EXCEPTION trips both AUTHZ-2 and
    # EXC-3 on the same line, which dedup folds together.
    _write(tmp_path, "p.prc", "CREATE OR REPLACE PROCEDURE p IS\nBEGIN\n  NULL;\nEND;\n")
    hits = plsql.scan_project(tmp_path)
    plsql.scan_project(tmp_path)

    assert {r.id: r.description for r in plsql.RULES} == before
    folded = [h for h in hits if h.also_matched]
    assert folded and "also matched" in folded[0].title


def test_detector_treats_oracle_extension_as_plsql(tmp_path):
    _write(tmp_path, "pkg.pks", "CREATE PACKAGE p AS END;\n")
    assert detector.detect_language(tmp_path)
    assert detector.detect_frameworks(tmp_path) == ["plsql"]


def test_detector_does_not_claim_plain_tsql_as_plsql(tmp_path):
    _write(tmp_path, "proc.sql", "CREATE PROCEDURE dbo.p AS\nBEGIN\n  EXEC sp_executesql @sql;\nEND\n")
    assert detector.detect_language(tmp_path)
    assert detector.detect_frameworks(tmp_path) == []


def test_enumerator_produces_project_wide_findings(tmp_path):
    (tmp_path / "db").mkdir()
    _write(
        tmp_path,
        "db/p.prc",
        "CREATE OR REPLACE PROCEDURE p(p_tab VARCHAR2)\n"
        "  AUTHID DEFINER IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE 'SELECT 1 FROM ' || p_tab;\n"
        "END;\n",
    )
    results = [r for r in enumerate_target(tmp_path) if r.language == "sql"]
    assert len(results) == 1 and results[0].framework == "plsql"
    assert results[0].routes == []

    findings = results[0].findings
    inj = next(f for f in findings if f.check_id == "INJ-1")
    assert inj.route is None
    assert inj.severity == "high"
    assert inj.file == str(Path("db/p.prc"))
    assert inj.line == 4
    assert any(f.check_id == "AUTHZ-1" and f.confidence == "REVIEW" for f in findings)


def test_html_findings_tab_shows_snippet_and_review_badge(tmp_path):
    _write(
        tmp_path,
        "pkg.pks",
        "CREATE OR REPLACE PACKAGE pkg AUTHID DEFINER AS\n"
        "  PROCEDURE p;\n"
        "END;\n",
    )
    html_out = render_html(enumerate_target(tmp_path), tmp_path)
    assert "AUTHZ-1" in html_out
    assert 'class="finding-confidence"' in html_out
    assert "finding-snippet" in html_out


# A procedure wrapper that is otherwise clean (AUTHID set, handler re-raises),
# so each test below only sees findings from the body lines it's about.
def _proc(body):
    return (
        "CREATE OR REPLACE PROCEDURE p(p_in VARCHAR2) AUTHID CURRENT_USER IS\n"
        "  v_sql VARCHAR2(400);\n"
        "BEGIN\n"
        + body +
        "EXCEPTION\n"
        "  WHEN OTHERS THEN RAISE;\n"
        "END;\n"
    )


def test_parameterized_execute_immediate_is_not_flagged_as_variable(tmp_path):
    # Strings used to be masked including their quotes, so INJ-4's regex
    # skipped the blanked literal and matched USING as "the variable".
    _write(tmp_path, "p.prc", _proc("  EXECUTE IMMEDIATE 'DELETE FROM t WHERE id = :1' USING p_in;\n"))
    assert "INJ-4" not in _ids(tmp_path)


def test_execute_immediate_of_a_variable_is_still_flagged(tmp_path):
    _write(tmp_path, "p.prc", _proc("  EXECUTE IMMEDIATE v_sql;\n"))
    assert "INJ-4" in _ids(tmp_path)


def test_package_body_is_never_flagged_for_missing_authid(tmp_path):
    _write(
        tmp_path,
        "pkg.pkb",
        "CREATE OR REPLACE PACKAGE BODY pkg AS\n"
        "  PROCEDURE q IS BEGIN NULL; EXCEPTION WHEN OTHERS THEN RAISE; END;\n"
        "END pkg;\n",
    )
    assert "AUTHZ-2" not in _ids(tmp_path)


def test_authid_on_a_wrapped_header_line_counts(tmp_path):
    _write(tmp_path, "pkg.pks", "CREATE OR REPLACE PACKAGE pkg\n  AUTHID CURRENT_USER\nAS\n  PROCEDURE q;\nEND;\n")
    assert "AUTHZ-2" not in _ids(tmp_path)


def test_package_spec_without_authid_is_flagged(tmp_path):
    _write(tmp_path, "pkg.pks", "CREATE OR REPLACE PACKAGE pkg AS\n  PROCEDURE q;\nEND;\n")
    assert "AUTHZ-2" in _ids(tmp_path)


def test_variable_built_by_concatenation_then_executed_is_flagged(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        _proc(
            "  v_sql := 'SELECT name FROM emp WHERE dept = '''\n"
            "           || p_in || '''';\n"
            "  EXECUTE IMMEDIATE v_sql;\n"
        ),
    )
    hits = plsql.scan_project(tmp_path)
    inj6 = [h for h in hits if h.rule.id == "INJ-6"]
    assert inj6 and inj6[0].line_no == 6
    # INJ-4 fires on the same line and is folded into the higher-severity hit.
    assert "INJ-4" in inj6[0].also_matched


def test_open_for_and_dbms_sql_parse_of_concatenated_variable_are_flagged(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        _proc(
            "  v_sql := 'SELECT 1 FROM ' || p_in;\n"
            "  OPEN c FOR v_sql;\n"
            "  DBMS_SQL.PARSE(cur, v_sql, DBMS_SQL.NATIVE);\n"
        ),
    )
    assert _ids(tmp_path).count("INJ-6") == 2


def test_variable_built_only_from_literals_and_itself_is_not_injection(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        _proc(
            "  v_sql := 'SELECT 1 FROM dual';\n"
            "  v_sql := v_sql || ' WHERE 1 = ' || 1 || CHR(10);\n"
            "  EXECUTE IMMEDIATE v_sql;\n"
        ),
    )
    assert "INJ-6" not in _ids(tmp_path)


def test_dbms_assert_wrapped_operand_is_not_injection(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        _proc(
            "  v_sql := 'SELECT 1 FROM ' || DBMS_ASSERT.SQL_OBJECT_NAME(p_in);\n"
            "  EXECUTE IMMEDIATE v_sql;\n"
        ),
    )
    assert "INJ-6" not in _ids(tmp_path)


def test_htp_concatenating_unescaped_input_is_xss(tmp_path):
    _write(tmp_path, "p.prc", _proc("  HTP.P('<b>Hello ' || p_in || '</b>');\n"))
    assert "XSS-1" in _ids(tmp_path)


def test_htp_with_escaped_operand_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        _proc(
            "  HTP.P('<b>' || HTF.ESCAPE_SC(p_in) || '</b>');\n"
            "  sys.htp.print('<i>' || APEX_ESCAPE.HTML(p_in) || '</i>');\n"
            "  HTP.P('<hr>');\n"
        ),
    )
    ids = _ids(tmp_path)
    assert "XSS-1" not in ids and "XSS-2" not in ids


def test_htp_of_a_single_variable_is_review_level(tmp_path):
    _write(tmp_path, "p.prc", _proc("  HTP.P(p_in);\n"))
    hits = [h for h in plsql.scan_project(tmp_path) if h.rule.id == "XSS-2"]
    assert hits and hits[0].confidence == "REVIEW"


def test_client_identifier_in_a_condition_is_flagged(tmp_path):
    _write(
        tmp_path,
        "p.prc",
        _proc(
            "  IF SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER') = 'admin' THEN\n"
            "    DELETE FROM audit_log;\n"
            "  END IF;\n"
        ),
    )
    assert "AUTHZ-5" in _ids(tmp_path)


def test_client_identifier_read_for_logging_is_not_flagged(tmp_path):
    _write(tmp_path, "p.prc", _proc("  v_sql := SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER');\n"))
    assert "AUTHZ-5" not in _ids(tmp_path)


def test_sql_delivered_as_txt_is_scanned_and_detected(tmp_path):
    _write(tmp_path, "delivered_code.txt", _proc("  EXECUTE IMMEDIATE 'DELETE FROM t WHERE c = ''' || p_in || '''';\n"))
    assert "INJ-1" in _ids(tmp_path)
    assert detector.detect_frameworks(tmp_path) == ["plsql"]

    html_out = render_html(enumerate_target(tmp_path), tmp_path)
    # Highlighted as SQL (keyword spans), not as plain text.
    assert '<span class="k">EXECUTE</span>' in html_out


def test_non_sql_txt_files_are_ignored(tmp_path):
    _write(tmp_path, "requirements.txt", "javalang==0.13.0\npygments>=2.17\n")
    _write(
        tmp_path,
        "README.txt",
        "Begin by creating a user. Grant access to the team\n"
        "Create procedure docs in the wiki. Ask for the password := 'hunter22' reset.\n"
        "Store the DOB column encrypted.\n",
    )
    assert not detector.detect_language(tmp_path)
    assert _ids(tmp_path) == []
