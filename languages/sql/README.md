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
.prc .trg .typ` file exists (case-insensitive). The framework (really the
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
  contents are blanked too, except for rules that have to see inside a
  literal (`CRED-1`, `CRED-3`, `CRYPTO-4`) and the `||`-chain rules. So
  `'EXECUTE IMMEDIATE ...'` inside a log message can't fire `INJ-*`.
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
| EXC-1 | high | `WHEN OTHERS THEN NULL;` |
| EXC-2 | high (review) | `WHEN OTHERS` handler with no RAISE or logging call in that handler |
| EXC-3 | medium (review) | `CREATE PROCEDURE/FUNCTION` with no `EXCEPTION` section |
| AUTHZ-1 | medium (review) | `AUTHID DEFINER` |
| AUTHZ-2 | medium (review) | no `AUTHID` clause (so it defaults to definer rights) |
| AUTHZ-3 | high | `GRANT ... TO PUBLIC` |
| AUTHZ-4 | high | DBA / SYSDBA / RESOURCE / CONNECT / `* ANY` grants |
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
- **Concatenation in an earlier statement**: `v_sql := '...' || p_x;`
  followed later by `EXECUTE IMMEDIATE v_sql` only shows up as INJ-4
  (review). Nothing traces `v_sql` back to its assignment.
- **Definer-rights exposure**: AUTHZ-1/2 flag the clause. Who holds
  `EXECUTE` on the unit, and what the owning schema can reach, comes from
  the grants (often in a separate schema/DBA repo), not from this code.
- **Other dialects**: T-SQL and PL/pgSQL have no analyzer yet (see Detection).
