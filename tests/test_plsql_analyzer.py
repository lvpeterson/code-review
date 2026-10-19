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
        "db/pkg.pkb",
        "CREATE OR REPLACE PACKAGE BODY pkg AUTHID DEFINER AS\n"
        "  PROCEDURE p(p_tab VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT 1 FROM ' || p_tab;\n"
        "  END;\n"
        "END;\n",
    )
    results = [r for r in enumerate_target(tmp_path) if r.language == "sql"]
    assert len(results) == 1 and results[0].framework == "plsql"
    assert results[0].routes == []

    findings = results[0].findings
    inj = next(f for f in findings if f.check_id == "INJ-1")
    assert inj.route is None
    assert inj.severity == "high"
    assert inj.file == str(Path("db/pkg.pkb"))
    assert inj.line == 4
    assert any(f.check_id == "AUTHZ-1" and f.confidence == "REVIEW" for f in findings)


def test_html_findings_tab_shows_snippet_and_review_badge(tmp_path):
    _write(
        tmp_path,
        "pkg.pkb",
        "CREATE OR REPLACE PACKAGE BODY pkg AUTHID DEFINER AS\n"
        "  PROCEDURE p IS BEGIN NULL; END;\n"
        "END;\n",
    )
    html_out = render_html(enumerate_target(tmp_path), tmp_path)
    assert "AUTHZ-1" in html_out
    assert 'class="finding-confidence"' in html_out
    assert "finding-snippet" in html_out
