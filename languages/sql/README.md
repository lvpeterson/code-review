# SQL: plsql (Oracle)

No route extraction -- stored code has no routes of its own; it's reached
through whatever calls it (an app's JDBC/ORM call, a scheduler job, a DB
link, another package). Every finding is project-wide (`route=None`), so
it all lands in the HTML report's **Findings** tab, in `--sarif`, and in
`--fail-on`.

The rules and engine live in `checks/plsql.py`. `plsql_analyzer.py` is only
the adapter from `PlsqlHit` to `core.models.Finding`. To scan only the
PL/SQL in a mixed repo, use `--language sql`.

## Detection

`detector.py`: the language is "sql" if any `.sql .pls .pkb .pks .pck .fnc
.prc .trg .typ` file exists (case-insensitive), or a `.txt` file whose
contents look like SQL. Code often arrives as `.txt` (pasted from a ticket,
emailed, exported from a DB client), but a `.txt` is only scanned if a line
*starts* with a real statement shape: `CREATE [OR REPLACE] PROCEDURE|
FUNCTION|PACKAGE|TRIGGER|TYPE <name>` followed by `(`/`IS`/`AS`/`AUTHID`/
`RETURN`/trigger timing, a line that's only `BEGIN` or `DECLARE`,
`EXECUTE IMMEDIATE`, or `GRANT ... TO ...;`. So `requirements.txt`,
licenses and prose READMEs are skipped
(`checks/plsql.py:looks_like_sql()`). Snippets from `.txt` files are still
highlighted as SQL in the HTML report. The framework (really the
dialect) is `plsql` if any of those files has an Oracle-only extension
(anything but `.sql`), or a `.sql` file contains an Oracle-only construct
(`EXECUTE IMMEDIATE`, `AUTHID`, `CREATE PACKAGE`, `DBMS_*.`, `UTL_*.`,
`PRAGMA AUTONOMOUS_TRANSACTION`, `RAISE_APPLICATION_ERROR`). A repo of
plain T-SQL/Postgres `.sql` files is detected as sql with **no** framework,
so it gets no deep-dive. That's on purpose: the injection rules below
don't know `sp_executesql`, `EXEC(@sql)`, or PL/pgSQL's `EXECUTE`, and
running them anyway would look like a clean bill of health.

## How matching works

- **Masking**: comments are always blanked before matching. String
  contents are blanked too (the quotes themselves are kept, so `'abc'`
  becomes `'   '`), except for rules that have to see inside a literal
  (`CRED-1`, `CRED-3`, `CRYPTO-4`, `AUTHZ-5`) and the `||`-chain rules. So
  `'EXECUTE IMMEDIATE ...'` inside a log message can't fire `INJ-*`, but
  rules can still tell a literal was there.
- **Post checks** (`Rule.post_check`): for rules a one-line regex can't
  decide, a function sees the whole file. `top_level_operands()` splits an
  expression into its depth-0 `||` operands, parens and literals aware.
  INJ-6, XSS-1/2, AUTHZ-2 and AUTHZ-5 use this.
- **Literal-only `||` chains are suppressed** (`INJ-1/2/3`): a chain built
  only from string or number literals isn't injectable. The chain walker
  follows `||` across wrapped lines.
- **Block checks**: some rules are dropped if a pattern appears in the
  surrounding code. For most rules that's the enclosing
  PROCEDURE/FUNCTION/TRIGGER/PACKAGE BODY, found by BEGIN/END depth
  counting that skips nested local subprograms as opaque units. **EXC-2
  only looks at its own handler**: from `WHEN OTHERS THEN` to the next
  sibling `WHEN` or the closing `END`. Nested BEGIN, CASE and LOOP blocks
  are depth-tracked, so a CASE's `WHEN` or an `EXIT WHEN` doesn't end the
  handler early.
- **Dedup**: when several rules fire on one line, the highest-severity one
  is kept and the rest appear in its title as `[also matched: ...]`. For
  example, `EXC-3` and `AUTHZ-2` both fire on a bare `CREATE PROCEDURE`.
- **Confidence**: `REVIEW` rules (shown with a "review" badge in the HTML
  report, `[REVIEW]` in the console, `properties.confidence` in SARIF) are
  ones the rule itself can't decide. The rest are `CONFIRM`.
- `CUSTOM_LOG_CALLS` at the top of `checks/plsql.py`: add a project's own
  error-logging procedure names there so EXC-2 stops flagging handlers
  that call them.

## Rules

| ID | Sev | What |
|---|---|---|
| INJ-1 | high | `EXECUTE IMMEDIATE` with `\|\|` concatenation of a non-literal |
| INJ-2 | high | `DBMS_SQL.PARSE` with `\|\|` concatenation |
| INJ-3 | high | `OPEN c FOR` with `\|\|` concatenation |
| INJ-4 | medium (review) | `EXECUTE IMMEDIATE <variable>`: trace the variable |
| INJ-5 | high (review) | dynamic identifier (`FROM`/`INTO`/`TABLE` + `\|\|`) with no `DBMS_ASSERT` in the unit |
| INJ-6 | high | `EXECUTE IMMEDIATE v` / `OPEN c FOR v` / `DBMS_SQL.PARSE(c, v)` where `v` is assigned in the same unit from a `\|\|` chain with an operand that isn't a literal, `v` itself, or `DBMS_ASSERT.*(...)` |
| EXC-1 | high | `WHEN OTHERS THEN NULL;` |
| EXC-2 | high (review) | `WHEN OTHERS` handler with no RAISE or logging call in that handler |
| EXC-3 | medium (review) | `CREATE PROCEDURE/FUNCTION` with no `EXCEPTION` section |
| AUTHZ-1 | medium (review) | `AUTHID DEFINER` |
| AUTHZ-2 | medium (review) | no `AUTHID` clause in the unit header (so it defaults to definer rights). Specs and standalone units only; a `PACKAGE BODY` can't carry AUTHID |
| AUTHZ-3 | high | `GRANT ... TO PUBLIC` |
| AUTHZ-4 | high | DBA / SYSDBA / RESOURCE / CONNECT / `* ANY` grants |
| AUTHZ-5 | high (review) | `SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER'\|'CLIENT_INFO'\|'MODULE'\|'ACTION'\|'OS_USER'\|'HOST'\|'TERMINAL')` in a condition on the same line (after IF/ELSIF/WHEN/WHERE/AND/OR/CASE, or directly compared). These values are client-controlled |
| XSS-1 | high | `HTP.P/PRINT/PRN(...)` with a `\|\|` chain containing an operand not wrapped in `HTF.ESCAPE_SC`/`ESCAPE_URL`, `APEX_ESCAPE.*` or `UTL_URL.ESCAPE` |
| XSS-2 | medium (review) | `HTP.P/PRINT/PRN(v)` with a single unescaped non-literal value |
| CRED-1 | high | `password := 'literal'` / `=> 'literal'` |
| CRED-2 | high | `IDENTIFIED BY` in DDL |
| CRED-3 | medium | `UTL_HTTP`/`DBMS_LDAP`/`UTL_SMTP` call with two or more string literals |
| NET-1 | medium (review) | `UTL_HTTP` request with no ACL reference in the unit |
| NET-2 | medium (review) | `UTL_FILE` read or write |
| NET-3 | high (review) | `DBMS_SCHEDULER` EXTERNAL job (OS command) |
| NET-4 | low (review) | `DBMS_PIPE` |
| CRYPTO-1 | high | DES/3DES/RC4 through `DBMS_CRYPTO` |
| CRYPTO-2 | high | `DBMS_OBFUSCATION_TOOLKIT` |
| CRYPTO-3 | high | `HASH_MD5` |
| CRYPTO-4 | medium (review) | hardcoded key or IV literal in `DBMS_CRYPTO.ENCRYPT/DECRYPT` |
| PRAGMA-1 | medium (review) | `PRAGMA AUTONOMOUS_TRANSACTION` |
| PRIV-1 | high | dynamic `GRANT` through `EXECUTE IMMEDIATE` |
| PRIV-2 | high | dynamic `DROP`/`TRUNCATE` through `EXECUTE IMMEDIATE` |
| PRIV-3 | medium (review) | `DBMS_SESSION.SET_CONTEXT` |
| SYN-1 | medium (review) | `CREATE PUBLIC SYNONYM` |
| DATA-1 | low (review) | `SELECT * FROM` |
| DATA-2 | medium (review) | PII/financial column names (SSN, CARD_NUMBER, DOB, ...) |

## Still manual

- **Taint**: every rule here only detects that a pattern is present. INJ-1
  says a non-literal was concatenated in, not that the value came from a
  caller. Trace the procedure's parameters back to whoever calls it,
  including app-side code that SQLI-001 may or may not have flagged.
- **Concatenation in an earlier statement**: INJ-6 follows `v_sql` back to
  its `:=` assignments in the same unit, but no further: a package-level
  variable, a value built in another procedure and passed in, or one
  filled via `SELECT ... INTO` still only shows as INJ-4 (review).
- **USERENV through a variable**: AUTHZ-5 only fires when the
  `SYS_CONTEXT` call is in the condition itself. `v := SYS_CONTEXT(...)`
  then `IF v = 'admin'` isn't followed.
- **Other HTP output**: XSS-1/2 cover `HTP.P/PRINT/PRN`. Tag helpers
  (`HTP.TABLEDATA(v)`, `HTP.ANCHOR(...)`) and APEX region source
  aren't checked.
- **Definer-rights exposure**: AUTHZ-1/2 flag the clause. Who holds
  `EXECUTE` on the unit, and what the owning schema can reach, comes from
  the grants (often in a separate schema/DBA repo), not from this code.
- **Other dialects**: T-SQL and PL/pgSQL have no analyzer yet (see Detection).
