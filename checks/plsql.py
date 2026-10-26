"""PL/SQL rule engine -- regex rules with comment/string masking, enclosing
program-unit extraction (BEGIN/END depth counting that skips nested local
subprograms), and literal-only || chain suppression.

Run by `languages/sql/plsql_analyzer.py`, which converts each PlsqlHit
into a core.models.Finding. Oracle-specific: the injection rules know EXECUTE
IMMEDIATE / DBMS_SQL / OPEN ... FOR, not T-SQL's sp_executesql or
PL/pgSQL's EXECUTE.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class Rule:
    id: str
    category: str
    severity: str          # HIGH | MEDIUM | LOW
    description: str
    pattern: str
    note: str = ""
    # .txt only counts once looks_like_sql() says so -- see iter_plsql_files.
    file_exts: tuple = (".sql", ".pls", ".pkb", ".pks", ".pck", ".fnc", ".prc", ".trg", ".typ", ".txt")
    # If block_suppress is set the finding is dropped when the pattern matches
    # anywhere in the extracted enclosing program-unit body.
    block_suppress: str | None = None
    # If block_require is set the finding is dropped when the pattern does NOT
    # match anywhere in the enclosing body.
    block_require: str | None = None
    # Human-readable reason shown when a finding survives block checking.
    block_note: str | None = None
    # CONFIRM → block analysis is confident enough to call it real
    # REVIEW  → manual verification still needed
    confidence: str = "CONFIRM"
    # When True the initial per-line pattern match runs against the
    # comment-only-masked text (string literal contents are visible). Use this
    # only for rules whose pattern must see inside a string value, e.g.
    # CRED-1 which matches password := 'literal'. For all other rules leave
    # False so that keywords appearing inside a string literal (e.g.
    # 'EXECUTE IMMEDIATE ...' inside a log message) cannot cause false
    # positives. Block-check suppression patterns always run on comment-masked
    # text regardless of this flag.
    match_in_strings: bool = False
    # When True: if the ||-joined operand chain (spanning wrapped lines) is built
    # entirely from string/numeric literals the finding is suppressed -- literal-only
    # concatenation inside EXECUTE IMMEDIATE is not injectable.
    literal_concat_suppress: bool = False
    # For literal_concat_suppress rules: sub-pattern that locates the point inside
    # the match where the || operand chain actually starts. When None the chain
    # starts at the first single-quote in the match span.
    chain_anchor_pattern: str | None = None
    # What block_suppress / block_require are checked against:
    #   "unit"    → the whole enclosing PROCEDURE/FUNCTION/TRIGGER/PACKAGE BODY
    #   "handler" → only the exception handler starting at the matched line,
    #               up to the next sibling WHEN ... THEN or the closing END
    block_scope: str = "unit"
    # Name of a function in _POST_CHECKS that gets the match plus the whole
    # file (both masked views) and decides whether the finding is kept. For
    # rules a per-line regex can't express on its own: following a variable
    # back to its assignment, splitting a call's argument into || operands,
    # reading a unit header that wraps onto several lines. When it keeps the
    # finding, block_note is attached as the explanation.
    post_check: str | None = None


# ── User-configurable "this counts as error logging" identifiers ────────────
# Add any project-specific error-logging procedure/package names here so EXC-2
# (WHEN OTHERS THEN without RAISE or logging) stops flagging handlers that
# call an in-house logger it doesn't already recognise. Matched case-
# insensitively as a whole word/qualified call -- a raw name like "msg_log"
# matches any MSG_LOG.<anything> call; a qualified entry like "etl_log.fail"
# only matches that specific call. Regex-special characters must be escaped.
CUSTOM_LOG_CALLS: list[str] = [
    r"etl_log\.fail",
    r"msg_log",
]

_EXC2_LOG_CALLS = (
    r"log_error|log\.error|p_log|pkg_log|log_pkg|ins_error"
    + ("|" + "|".join(CUSTOM_LOG_CALLS) if CUSTOM_LOG_CALLS else "")
)

RULES: list[Rule] = [
    # ── SQL Injection ──────────────────────────────────────────────────────
    Rule("INJ-1", "SQL Injection", "HIGH",
         "EXECUTE IMMEDIATE with string concatenation",
         r'(?i)\bEXECUTE\s+IMMEDIATE\b[^;]*\|\|',
         "Build the SQL string with bind-variable placeholders (:var) and pass values "
         + "via the USING clause; never concatenate user-supplied input into a "
         + "dynamic SQL string.",
         literal_concat_suppress=True,
         chain_anchor_pattern=r'(?i)\bEXECUTE\s+IMMEDIATE\s+'),

    Rule("INJ-2", "SQL Injection", "HIGH",
         "DBMS_SQL.PARSE with string concatenation",
         r'(?i)\bDBMS_SQL\s*\.\s*PARSE\s*\([^;]*\|\|',
         "Use DBMS_SQL.BIND_VARIABLE instead of concatenating input into the SQL text "
         + "passed to DBMS_SQL.PARSE.",
         literal_concat_suppress=True,
         chain_anchor_pattern=r'(?i)\bDBMS_SQL\s*\.\s*PARSE\s*\('),

    Rule("INJ-3", "SQL Injection", "HIGH",
         "REF CURSOR opened FOR with string concatenation",
         r'(?i)\bOPEN\s+\w+\s+FOR\s+[^;]*\|\|',
         "Use OPEN cursor FOR query USING bind_var instead of concatenating user input "
         + "into the cursor query string.",
         literal_concat_suppress=True,
         chain_anchor_pattern=r'(?i)\bOPEN\s+\w+\s+FOR\s+'),

    Rule("INJ-4", "SQL Injection", "MEDIUM",
         "EXECUTE IMMEDIATE with a variable first argument (verify taint)",
         # [nNqQ]? covers N'...' and q'[...]' literals. Matched against fully
         # masked text, which keeps a literal's quotes, so a parameterized
         # EXECUTE IMMEDIATE '...' USING x never reaches USING as the "variable".
         r"(?i)\bEXECUTE\s+IMMEDIATE\s+(?![nNqQ]?')[A-Za-z_]\w*",
         "The SQL string starts with a variable, not a literal; trace every assignment "
         + "to that variable and confirm no unsanitised input reaches it.",
         confidence="REVIEW"),

    Rule("INJ-6", "SQL Injection", "HIGH",
         "Dynamic SQL variable built by concatenating a non-literal",
         r"(?i)(?:\bEXECUTE\s+IMMEDIATE\s+|\bOPEN\s+\w+\s+FOR\s+"
         r"|\bDBMS_SQL\s*\.\s*PARSE\s*\(\s*\w+\s*,\s*)"
         r"(?![nNqQ]?')(?!(?:SELECT|WITH)\b)(?P<var>[A-Za-z_][\w$#]*)\b(?!\s*[(.])",
         "The variable executed here is assigned, somewhere in this unit, from a || "
         + "chain that includes a non-literal operand -- the two-statement form of "
         + "INJ-1/2/3. Rebuild it with bind placeholders and pass the values via USING "
         + "(or DBMS_SQL.BIND_VARIABLE); wrap any dynamic identifier in DBMS_ASSERT.",
         post_check="var_built_by_concat",
         block_note="Assignment found in this unit that concatenates a non-literal into "
                    + "this variable."),

    Rule("INJ-5", "SQL Injection", "HIGH",
         "Dynamic identifier built via || without DBMS_ASSERT validation",
         r'(?i)\bEXECUTE\s+IMMEDIATE\b[^;]*\b(?:FROM|INTO|UPDATE|TABLE)\b[^;]*\|\|',
         "Table and column names inserted dynamically must be validated with "
         + "DBMS_ASSERT.SQL_OBJECT_NAME() or DBMS_ASSERT.ENQUOTE_NAME() to prevent "
         + "identifier injection.",
         block_suppress=r'(?i)\bDBMS_ASSERT\b',
         block_note="No DBMS_ASSERT call found near this EXECUTE IMMEDIATE -- "
                    + "dynamic identifiers appear unvalidated.",
         confidence="REVIEW"),

    # ── Exception Handling ─────────────────────────────────────────────────
    Rule("EXC-1", "Exception Handling", "HIGH",
         "WHEN OTHERS THEN NULL -- silently swallows all exceptions",
         r'(?i)\bWHEN\s+OTHERS\s+THEN\s+NULL\s*;',
         "Silently discarding all exceptions hides bugs and security events; "
         + "at minimum log the error via DBMS_OUTPUT, an audit table, or "
         + "RAISE_APPLICATION_ERROR before continuing."),

    Rule("EXC-2", "Exception Handling", "HIGH",
         "WHEN OTHERS THEN without RAISE or error logging",
         r'(?i)\bWHEN\s+OTHERS\s+THEN\b',
         "Catching OTHERS without re-raising or logging hides failures; "
         + "add RAISE, RAISE_APPLICATION_ERROR, or structured error logging "
         + "after the THEN.",
         block_suppress=(
             r'(?i)\b(?:RAISE(?:_APPLICATION_ERROR)?\b'
             r'|DBMS_OUTPUT\.PUT_LINE\b'
             rf'|{_EXC2_LOG_CALLS})\b'
         ),
         block_note="No RAISE or error-logging call found in the handler block -- "
                    + "exception may be silently swallowed.",
         confidence="REVIEW",
         block_scope="handler"),

    Rule("EXC-3", "Exception Handling", "MEDIUM",
         "Stored program unit without an EXCEPTION block",
         r'(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:PROCEDURE|FUNCTION)\b',
         "Every stored program unit that may encounter run-time errors should have "
         + "an EXCEPTION block so failures are caught, logged, and surfaced rather "
         + "than propagating as raw ORA- errors.",
         block_suppress=r'(?i)\bEXCEPTION\b',
         block_note="No EXCEPTION block found in this CREATE PROCEDURE/FUNCTION -- "
                    + "unhandled errors will surface as uncontrolled ORA- exceptions.",
         confidence="REVIEW"),

    # ── Invoker / Definer Rights ───────────────────────────────────────────
    Rule("AUTHZ-1", "Invoker & Definer Rights", "MEDIUM",
         "AUTHID DEFINER -- unit runs with schema-owner privileges",
         r'(?i)\bAUTHID\s+DEFINER\b',
         "DEFINER rights means the unit executes as the owning schema; if "
         + "user-controlled input influences the code path the caller effectively "
         + "inherits the owner's privileges. Prefer AUTHID CURRENT_USER unless "
         + "elevation is intentional and all inputs are strictly validated.",
         confidence="REVIEW"),

    Rule("AUTHZ-2", "Invoker & Definer Rights", "MEDIUM",
         "CREATE PROCEDURE/FUNCTION/PACKAGE without explicit AUTHID clause",
         # Not PACKAGE BODY: AUTHID is only legal in the package spec, so a body
         # can never carry it and used to be flagged unconditionally.
         r'(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:PROCEDURE|FUNCTION|PACKAGE\b(?!\s+BODY\b))',
         "Without an explicit AUTHID clause the unit runs with DEFINER "
         + "(schema-owner) rights by default; document and review whether this "
         + "privilege elevation is intentional for each program unit.",
         post_check="header_lacks_authid",
         block_note="No AUTHID clause in the unit header -- "
                    + "unit defaults to DEFINER (owner) rights.",
         confidence="REVIEW"),

    Rule("AUTHZ-3", "Invoker & Definer Rights", "HIGH",
         "GRANT TO PUBLIC -- privilege exposed to every database user",
         r'(?i)\bGRANT\b[^;]+\bTO\s+PUBLIC\b',
         "Granting any privilege to PUBLIC exposes it to every current and future "
         + "schema including untrusted application accounts; grant only to specific "
         + "roles or named accounts that genuinely require the access."),

    Rule("AUTHZ-4", "Invoker & Definer Rights", "HIGH",
         "DBA or highly privileged system role / ANY privilege granted",
         r'(?i)\bGRANT\s+(?:DBA|SYSDBA|SYSOPER|RESOURCE|CONNECT'
         r'|EXECUTE\s+ANY|SELECT\s+ANY|DROP\s+ANY|CREATE\s+ANY'
         r'|ALTER\s+ANY|INSERT\s+ANY|UPDATE\s+ANY|DELETE\s+ANY)\b',
         "Highly privileged roles and ANY-level system privileges should almost "
         + "never be granted to application accounts; use fine-grained object "
         + "privileges scoped to the exact objects the account needs."),

    Rule("AUTHZ-5", "Invoker & Definer Rights", "HIGH",
         "Access decision based on a client-supplied USERENV attribute",
         r"(?i)\bSYS_CONTEXT\s*\(\s*'USERENV'\s*,\s*'(?:CLIENT_IDENTIFIER|CLIENT_INFO"
         r"|MODULE|ACTION|OS_USER|HOST|TERMINAL)'\s*\)",
         "CLIENT_IDENTIFIER, CLIENT_INFO, MODULE and ACTION are set by the client "
         + "(DBMS_SESSION / DBMS_APPLICATION_INFO, or connection attributes), and "
         + "OS_USER/HOST/TERMINAL are whatever the client machine reports; any session "
         + "can spoof them. Base the decision on SESSION_USER, an enabled role, or an "
         + "application context that only a trusted package can set.",
         match_in_strings=True,
         post_check="in_condition",
         block_note="Compared or tested in a condition on this line -- looks like it "
                    + "drives a decision, not just logging.",
         confidence="REVIEW"),

    # ── Hardcoded Credentials ──────────────────────────────────────────────
    Rule("CRED-1", "Hardcoded Credentials", "HIGH",
         "Hardcoded password / secret in variable assignment or named parameter call",
         r"(?i)(?:password|passwd|pwd|secret|api_key|apikey|credential|token)"
         r"\b[^;]*(?::=|=>)\s*'[^']{4,}'",
         "Move credentials out of source code into Oracle Wallet, a Vault, "
         + "environment variables, or a secured config table; "
         + "never commit plaintext secrets.",
         match_in_strings=True),

    Rule("CRED-2", "Hardcoded Credentials", "HIGH",
         "IDENTIFIED BY in DDL -- hardcoded password for user/DB link creation",
         r'(?i)\bIDENTIFIED\s+BY\s+\S',
         "IDENTIFIED BY stores the password in the DDL statement itself; passwords "
         + "set this way appear in audit trails and can be extracted from SYS.LINK$ "
         + "(DB links) or DBA_USERS history. Use Oracle Wallet or External Password "
         + "Store for DB links; for user creation, rotate passwords immediately via "
         + "a privileged provisioning process rather than embedding them in scripts."),

    Rule("CRED-3", "Hardcoded Credentials", "MEDIUM",
         "UTL_HTTP / DBMS_LDAP / UTL_SMTP call with multiple string literals "
         + "(possible inline credentials)",
         r"(?i)\b(?:UTL_HTTP|DBMS_LDAP|UTL_SMTP)\b[^;]*'[^']{4,}'[^;]*'[^']{4,}'",
         "Credentials passed as string literals to UTL_ packages appear in V$SQL, "
         + "AWR snapshots, and trace files; read them from a secured configuration "
         + "table or Oracle Wallet at runtime instead.",
         match_in_strings=True),

    # ── File & Network Access ──────────────────────────────────────────────
    Rule("NET-1", "File & Network Access", "MEDIUM",
         "UTL_HTTP outbound call -- verify ACL restriction and URL source",
         r'(?i)\bUTL_HTTP\s*\.\s*(?:BEGIN_REQUEST|REQUEST|GET)\s*\(',
         "Outbound HTTP from the database bypasses application-tier controls; "
         + "confirm the target URL comes from a trusted config source (not user "
         + "input) and that an ACL restricts reachable hosts.",
         block_suppress=r'(?i)\bACL\b|DBMS_NETWORK_ACL',
         block_note="No ACL / DBMS_NETWORK_ACL reference nearby -- "
                    + "confirm the outbound target is allowlisted.",
         confidence="REVIEW"),

    Rule("NET-2", "File & Network Access", "MEDIUM",
         "UTL_FILE filesystem read/write",
         r'(?i)\bUTL_FILE\s*\.\s*(?:FOPEN|GET_LINE|PUT_LINE|FCOPY|FREMOVE|FRENAME)\s*\(',
         "UTL_FILE can read and write OS-level files as the Oracle OS user; "
         + "confirm the DIRECTORY object points to a restricted path and that "
         + "EXECUTE on UTL_FILE is not granted broadly (especially not to PUBLIC).",
         confidence="REVIEW"),

    Rule("NET-3", "File & Network Access", "HIGH",
         "DBMS_SCHEDULER EXTERNAL job -- OS command execution",
         r'(?i)\bDBMS_SCHEDULER\s*\.\s*(?:CREATE_JOB|CREATE_PROGRAM)\b[^;]+\bEXTERNAL',
         "DBMS_SCHEDULER EXTERNAL jobs run OS commands as the Oracle OS user; "
         + "confirm the command path and all arguments are static constants, "
         + "not influenced by any user-supplied input.",
         confidence="REVIEW"),

    Rule("NET-4", "File & Network Access", "LOW",
         "DBMS_PIPE inter-session communication (unencrypted channel)",
         r'(?i)\bDBMS_PIPE\s*\.\s*\w+\s*\(',
         "DBMS_PIPE messages are readable by any session that has EXECUTE on "
         + "DBMS_PIPE; do not pass sensitive data through pipes without encryption.",
         confidence="REVIEW"),

    # ── Cryptography ──────────────────────────────────────────────────────
    Rule("CRYPTO-1", "Cryptography", "HIGH",
         "Weak cipher used via DBMS_CRYPTO (DES, 3DES, RC4)",
         r'(?i)\bDBMS_CRYPTO\s*\.\s*(?:ENCRYPT|DECRYPT)\b[^;]+'
         r'DBMS_CRYPTO\s*\.\s*(?:DES_CBC_PKCS5|DES3_CBC_PKCS5|RC4)\b',
         "DES, 3DES, and RC4 are broken algorithms; use "
         + "DBMS_CRYPTO.ENCRYPT_AES256 with CBC or GCM padding and a randomly "
         + "generated IV stored separately from the ciphertext."),

    Rule("CRYPTO-2", "Cryptography", "HIGH",
         "DBMS_OBFUSCATION_TOOLKIT usage (deprecated -- weak DES/MD5)",
         r'(?i)\bDBMS_OBFUSCATION_TOOLKIT\b',
         "DBMS_OBFUSCATION_TOOLKIT is deprecated and implements weak DES encryption "
         + "and MD5 hashing; replace with DBMS_CRYPTO using AES-256."),

    Rule("CRYPTO-3", "Cryptography", "HIGH",
         "MD5 hash via DBMS_CRYPTO",
         r'(?i)\bDBMS_CRYPTO\s*\.\s*(?:HASH|MAC)\b[^;]+\bDBMS_CRYPTO\s*\.\s*HASH_MD5\b',
         "MD5 is cryptographically broken for integrity; use "
         + "DBMS_CRYPTO.HASH_SH256 or stronger (HASH_SH384, HASH_SH512)."),

    Rule("CRYPTO-4", "Cryptography", "MEDIUM",
         "Hardcoded key or IV literal in DBMS_CRYPTO call",
         r"(?i)\bDBMS_CRYPTO\s*\.\s*(?:ENCRYPT|DECRYPT)\b[^;]*'[^']{8,}'",
         "A hardcoded key or IV means every ciphertext can be decrypted by anyone "
         + "who reads the source; derive and rotate keys via Oracle Key Vault or "
         + "a KMS.",
         confidence="REVIEW",
         match_in_strings=True),

    # ── Transaction Control ────────────────────────────────────────────────
    Rule("PRAGMA-1", "Transaction Control", "MEDIUM",
         "PRAGMA AUTONOMOUS_TRANSACTION -- bypasses calling transaction",
         r'(?i)\bPRAGMA\s+AUTONOMOUS_TRANSACTION\b',
         "Autonomous transactions commit independently of the caller's transaction, "
         + "which can cause data inconsistency (partial writes survive rollback) and "
         + "makes audit trails unreliable; restrict use to genuine audit/error-log "
         + "tables only, never for business logic.",
         confidence="REVIEW"),

    # ── Privilege Escalation ───────────────────────────────────────────────
    Rule("PRIV-1", "Privilege Escalation", "HIGH",
         "Dynamic GRANT statement via EXECUTE IMMEDIATE",
         r'(?i)\bEXECUTE\s+IMMEDIATE\b[^;]*\bGRANT\b',
         "Generating GRANT statements dynamically is very high risk; if any part of "
         + "the grantee or privilege name comes from user input, an attacker can "
         + "grant themselves DBA. Allowlist every grantee and privilege name explicitly."),

    Rule("PRIV-2", "Privilege Escalation", "HIGH",
         "Dynamic DROP or TRUNCATE via EXECUTE IMMEDIATE",
         r'(?i)\bEXECUTE\s+IMMEDIATE\b[^;]*\b(?:DROP|TRUNCATE)\b',
         "Dynamically dropping or truncating objects is destructive and irreversible; "
         + "confirm the object name comes only from a static allowlist, not from any "
         + "user-controlled input."),

    Rule("PRIV-3", "Privilege Escalation", "MEDIUM",
         "DBMS_SESSION.SET_CONTEXT -- application context manipulation",
         r'(?i)\bDBMS_SESSION\s*\.\s*SET_CONTEXT\s*\(',
         "Application contexts used for row-level security can be abused if the "
         + "context-setter is callable with insufficient privilege; verify the "
         + "namespace is protected and only the intended trusted package sets it.",
         confidence="REVIEW"),

    # ── Web Output (PL/SQL Web Toolkit / APEX) ─────────────────────────────
    Rule("XSS-1", "Web Output", "HIGH",
         "HTP output concatenating an unescaped non-literal",
         r'(?i)\bHTP\s*\.\s*(?:P|PRINT|PRN)\s*\(',
         "HTP.P/PRINT/PRN write straight into the HTML response. Wrap every "
         + "non-literal operand in HTF.ESCAPE_SC() or APEX_ESCAPE.HTML() (or use "
         + "HTP.PRINTS / HTP.PS, which escape), or it's reflected/stored XSS "
         + "whenever that value can come from a user.",
         post_check="htp_concat_unescaped",
         block_note="At least one || operand is neither a literal nor wrapped in an "
                    + "escaping function."),

    Rule("XSS-2", "Web Output", "MEDIUM",
         "HTP output of a single unescaped value (verify it's pre-escaped HTML)",
         r'(?i)\bHTP\s*\.\s*(?:P|PRINT|PRN)\s*\(',
         "The argument is one non-literal value passed straight through. Fine if "
         + "it's HTML this code built and escaped itself; XSS if it holds user "
         + "input. Trace where it's assigned.",
         post_check="htp_single_unescaped",
         confidence="REVIEW"),

    # ── Public Synonyms ────────────────────────────────────────────────────
    Rule("SYN-1", "Object Exposure", "MEDIUM",
         "CREATE PUBLIC SYNONYM -- object resolvable by every database user",
         r'(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?PUBLIC\s+SYNONYM\b',
         "Public synonyms make the target object resolvable from any schema including "
         + "untrusted application accounts; prefer private synonyms or schema-qualified "
         + "references to avoid unintended access paths.",
         confidence="REVIEW"),

    # ── Data Exposure ──────────────────────────────────────────────────────
    Rule("DATA-1", "Data Exposure", "LOW",
         "SELECT * -- wildcard column fetch may expose sensitive or future columns",
         r'(?i)\bSELECT\s+\*\s+FROM\b',
         "SELECT * fetches every column including ones added by future schema changes; "
         + "enumerate only the columns the code actually needs to minimise accidental "
         + "data exposure.",
         confidence="REVIEW"),

    Rule("DATA-2", "Data Exposure", "MEDIUM",
         "Sensitive PII / financial column referenced without apparent encryption",
         r'(?i)\b(?:SSN|SOCIAL_SECURITY_NUM|CREDIT_CARD_NUM|CARD_NUMBER|CVV2?|CCV'
         r'|DATE_OF_BIRTH|DOB|BANK_ACCOUNT|ACCOUNT_NUMBER|TAX_ID'
         r'|NI_NUMBER|PASSPORT_NUM)\b',
         "Sensitive PII/financial columns should be stored encrypted or tokenised; "
         + "confirm the column has appropriate access controls and masking policies "
         + "for non-privileged queries (e.g. Oracle Data Masking or VPD).",
         confidence="REVIEW"),
]


# ── Constants ─────────────────────────────────────────────────────────────────
IGNORE_DIRS = {
    ".git", ".svn", ".idea", "__pycache__",
    "node_modules", "target", "build", "out", "bin",
}

PLSQL_EXTENSIONS = {ext for r in RULES for ext in r.file_exts}

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

@dataclass
class PlsqlHit:
    rule:       Rule
    file:       str
    line_no:    int
    line:       str
    confidence: str = "CONFIRM"
    block_note: str | None = None
    # Other rule IDs that fired on this same line and were folded into this
    # hit by dedup(). Lives on the hit, never on the shared Rule object.
    also_matched: list[str] = field(default_factory=list)

    @property
    def title(self) -> str:
        if not self.also_matched:
            return self.rule.description
        return f"{self.rule.description}  [also matched: {', '.join(self.also_matched)}]"

# ── Comment / string masking ──────────────────────────────────────────────────
def _mask_plsql(lines: list[str], mask_strings: bool) -> list[str]:
    """
    PL/SQL comment + optional string masker.

    Always blanks:
      - -- line comments (to end of line)
      - /* ... */ block comments (spanning lines)

    When mask_strings=True also blanks single-quoted string contents, but
    keeps the delimiting quotes themselves -- so 'abc' becomes '   '. Rules
    still can't see keywords inside a literal, but can tell a literal was
    there (INJ-4's "first argument isn't a literal" check depends on it), and
    the operand walker can find literal boundaries without re-lexing. The ''
    in-string escape is blanked to two spaces, so in fully masked text every
    remaining quote is a real delimiter.
    in_string persists across lines because PL/SQL allows multi-line literals.
    """
    out: list[str] = []
    in_block_comment = False
    in_string = False          # persists across lines (PL/SQL multi-line strings)

    for line in lines:
        result: list[str] = []
        i = 0
        n = len(line)

        while i < n:
            ch  = line[i]
            two = line[i:i + 2]

            if in_block_comment:
                if two == '*/':
                    result.append('  ')
                    i += 2
                    in_block_comment = False
                else:
                    result.append(' ')
                    i += 1
                continue

            if in_string:
                if ch == "'":
                    if i + 1 < n and line[i + 1] == "'":
                        result.append('  ' if mask_strings else "''")
                        i += 2          # '' = escaped quote -- stay in string
                    else:
                        result.append(ch)
                        i += 1
                        in_string = False
                else:
                    result.append(' ' if mask_strings else ch)
                    i += 1
                continue

            # Not in any comment or string
            if two == '--':
                result.append(' ' * (n - i))
                i = n
            elif two == '/*':
                result.append('  ')
                i += 2
                in_block_comment = True
            elif ch == "'":
                result.append(ch)
                i += 1
                in_string = True
            else:
                result.append(ch)
                i += 1

        out.append(''.join(result))
    return out


def mask_comments_only(lines: list[str]) -> list[str]:
    """
    Blank comments while leaving string literal contents intact.
    Used for per-line rule matching so patterns in live string arguments
    remain visible (e.g. the DBMS_ASSERT suppression patterns).
    """
    return _mask_plsql(lines, mask_strings=False)


def mask_comments_and_strings(lines: list[str]) -> list[str]:
    """
    Blank both comments and string literal contents.
    Used for BEGIN/END depth counting so that BEGIN or END appearing
    inside a string literal does not corrupt the block-boundary counter.
    """
    return _mask_plsql(lines, mask_strings=True)


# ── BEGIN/END block extraction ────────────────────────────────────────────────
# Matches bare END or END <label>; explicitly excludes END IF / END LOOP /
# END CASE / END CURSOR so those don't close the wrong depth level.
_END_RE    = re.compile(r'(?i)\bEND\b(?!\s+(?:IF|LOOP|CASE|CURSOR)\b)')
_BEGIN_RE  = re.compile(r'(?i)\bBEGIN\b')
_HEADER_RE = re.compile(r'(?i)\b(?:PROCEDURE|FUNCTION|TRIGGER|PACKAGE(?:\s+BODY)?)\b')


def _find_matching_end(masked_lines: list[str], start_i: int, limit: int) -> int | None:
    """
    Starting at a line containing a PROCEDURE/FUNCTION/TRIGGER/PACKAGE header,
    return the index of the line that closes that unit's own body.

    A unit's declare section may contain local nested subprograms (e.g. a
    helper logging procedure) each with their own self-contained BEGIN...END.
    Those are skipped as opaque units -- via recursion -- so their BEGIN/END
    aren't mistaken for the enclosing unit's own body boundaries. Without
    this, a nested subprogram's END would prematurely look like the outer
    unit's closing END, truncating the extracted block before it ever
    reaches the real EXCEPTION section that follows.

    Returns None if no BEGIN is found before `limit` (e.g. a package-spec-only
    declaration with no body).
    """
    depth = 0
    in_body = False
    i = start_i
    while i < limit:
        line = masked_lines[i]

        if i != start_i and not in_body and _HEADER_RE.search(line):
            nested_end = _find_matching_end(masked_lines, i, limit)
            if nested_end is None:
                i += 1
                continue
            i = nested_end + 1
            continue

        begin_count = len(_BEGIN_RE.findall(line))
        end_count   = len(_END_RE.findall(line))

        depth += begin_count
        if begin_count:
            in_body = True

        if in_body:
            depth -= end_count
            if depth <= 0:
                return i

        i += 1

    return None


def plsql_block_bounds(masked_lines: list[str], match_line_idx: int) -> tuple[int, int]:
    """
    (first, last) line index, inclusive, of the tightest enclosing
    PROCEDURE / FUNCTION / TRIGGER / PACKAGE BODY that contains
    match_line_idx -- or a fixed +/-60 line window when no enclosing header
    is found. Depth counting runs on fully masked lines so 'BEGIN' or 'END'
    inside a string literal can't corrupt the counter.
    """
    total = len(masked_lines)

    # Walk backward over candidate headers looking for the one whose own body
    # (per _find_matching_end, which skips nested subprograms as opaque units)
    # actually spans match_line_idx. The nearest preceding header is not
    # necessarily the right one -- it may belong to an earlier sibling helper
    # subprogram declared in the same declare section whose body closes
    # before match_line_idx is ever reached; in that case keep walking
    # backward for the real enclosing unit.
    for i in range(match_line_idx, max(-1, match_line_idx - 250), -1):
        if not _HEADER_RE.search(masked_lines[i]):
            continue
        candidate_end = _find_matching_end(masked_lines, i, min(i + 500, total))
        if candidate_end is not None and candidate_end >= match_line_idx:
            return i, candidate_end

    return max(0, match_line_idx - 60), min(total, match_line_idx + 60) - 1


def extract_plsql_block(
    masked_lines:  list[str],   # comment+string masked -- for depth counting
    text_lines:    list[str],   # comment-only masked -- for suppression patterns
    match_line_idx: int,
) -> str:
    """
    Text of the enclosing unit (see plsql_block_bounds). The returned text
    comes from comment-only masked lines so real string-literal arguments
    (e.g. the 'EXCEPTION' keyword in a RAISE_APPLICATION_ERROR call) remain
    visible to block_suppress / block_require pattern checks.
    """
    first, last = plsql_block_bounds(masked_lines, match_line_idx)
    return "\n".join(text_lines[first:last + 1])


# END LOOP / END CASE / END IF are matched as one token so their trailing
# keyword isn't also counted as an opener.
_HANDLER_TOKEN_RE = re.compile(r'(?i)\b(?:END(?:\s+(IF|LOOP|CASE))?|BEGIN|CASE|LOOP|WHEN)\b')
_HANDLER_START_RE = re.compile(r'(?i)\bWHEN\s+OTHERS\s+THEN\b')


def extract_handler_block(
    masked_lines:   list[str],   # comment+string masked -- for token scanning
    text_lines:     list[str],   # comment-only masked -- returned text
    match_line_idx: int,
    max_lines:      int = 200,
) -> str:
    """
    Text of the single exception handler that starts on match_line_idx:
    everything after its WHEN ... THEN up to the next sibling WHEN or the
    END that closes the EXCEPTION section. Nested BEGIN/CASE/LOOP blocks
    inside the handler are depth-tracked so a CASE's WHEN, an EXIT WHEN, or
    a nested block's END doesn't end the handler early.

    Scoping EXC-2 to this (instead of the whole enclosing unit) is what stops
    a RAISE somewhere else in the procedure from hiding a handler that
    genuinely swallows the exception.
    """
    end_idx = min(len(masked_lines), match_line_idx + max_lines)
    joined_masked = "\n".join(masked_lines[match_line_idx:end_idx])
    joined_text   = "\n".join(text_lines[match_line_idx:end_idx])

    start = _HANDLER_START_RE.search(joined_masked)
    pos = start.end() if start else 0

    depth = 0
    for tok in _HANDLER_TOKEN_RE.finditer(joined_masked, pos):
        word = tok.group().split()[0].upper()
        suffix = (tok.group(1) or "").upper()
        if word in ("BEGIN", "CASE", "LOOP"):
            depth += 1
        elif word == "END":
            if suffix == "IF":
                continue
            if depth == 0:
                return joined_text[pos:tok.start()]
            depth -= 1
        elif word == "WHEN" and depth == 0:
            return joined_text[pos:tok.start()]

    return joined_text[pos:]


# ── Block check ───────────────────────────────────────────────────────────────
def apply_block_check(
    rule:           Rule,
    masked_lines:   list[str],
    text_lines:     list[str],
    match_line_idx: int,
) -> tuple[bool, str | None]:
    """
    Returns (keep_finding, block_note).
    keep_finding=False means the check determined it is a false positive.
    """
    if rule.block_suppress is None and rule.block_require is None:
        return True, None

    if rule.block_scope == "handler":
        block = extract_handler_block(masked_lines, text_lines, match_line_idx)
    else:
        block = extract_plsql_block(masked_lines, text_lines, match_line_idx)

    if rule.block_require and not re.search(rule.block_require, block):
        return False, None   # required pattern absent → suppress

    if rule.block_suppress and re.search(rule.block_suppress, block):
        return False, None   # suppression pattern present → false positive

    return True, rule.block_note


# ── || concatenation chain analysis ──────────────────────────────────────────
def plsql_chain_contains_variable(text: str, start_idx: int, max_scan: int = 4000) -> bool:
    """
    Walk a PL/SQL ||-joined operand chain starting at start_idx.

    Returns True  the moment a non-literal operand is found (variable,
                  function call, etc.) -- the chain is potentially injectable.
    Returns True  on anything inconclusive (unterminated literal, hit max_scan).
    Returns False only when the chain cleanly ends having seen nothing but
                  string and/or numeric literals -- literal-only concat is safe.

    PL/SQL strings use single quotes; '' is the in-string escaped quote.
    """
    n = min(len(text), start_idx + max_scan)
    i = start_idx

    while i < n and text[i] in ' \t\r\n':
        i += 1

    while i < n:
        ch = text[i]

        if ch == "'":
            # Single-quoted string literal
            i += 1
            closed = False
            while i < n:
                if text[i] == "'":
                    i += 1
                    if i < n and text[i] == "'":
                        i += 1   # '' escape -- stay in string
                        continue
                    closed = True
                    break
                i += 1
            if not closed:
                return True   # ran off end of text mid-literal -- inconclusive

        elif ch.isdigit():
            # Numeric literal (integer or simple float)
            while i < n and (text[i].isdigit() or text[i] in '.eE'):
                i += 1

        else:
            return True   # non-literal operand -- variable or expression

        # Skip whitespace after operand
        while i < n and text[i] in ' \t\r\n':
            i += 1

        # Check for || continuation
        if i + 1 < n and text[i:i + 2] == '||':
            i += 2
            while i < n and text[i] in ' \t\r\n':
                i += 1
            continue   # consume next operand

        return False   # chain ended cleanly with literal(s) only

    return True   # hit max_scan -- inconclusive


def find_chain_start_col(rule: Rule, match: re.Match) -> int:
    """
    Column (within the matched line) where the || operand chain starts.
    If chain_anchor_pattern is set we start right after that anchor match;
    otherwise we start at the first single-quote in the match span (the
    opening of the first string literal in the SQL text being built).
    """
    span = match.group()
    if rule.chain_anchor_pattern:
        anchor = re.search(rule.chain_anchor_pattern, span)
        if anchor:
            return match.start() + anchor.end()
        return match.start()
    q = re.search(r"'", span)
    return match.start() + (q.start() if q else 0)


# ── Post checks (Rule.post_check) ────────────────────────────────────────────
@dataclass
class FileView:
    """Both masked views of one file, per-line and joined. Masking is
    length-preserving, so a single offset indexes into either joined string,
    and fully_masked keeps literal quotes (see _mask_plsql), so walking it
    sees exactly where each literal starts and ends while comment_masked
    supplies the actual operand text."""
    fully_masked:   list[str]
    comment_masked: list[str]
    joined_fm:      str
    joined_cm:      str
    offsets:        list[int]   # offsets[i] = start of line i in either joined string


def top_level_operands(view: FileView, start: int, max_scan: int = 4000) -> list[str] | None:
    """
    Split the expression starting at `start` into its top-level || operands,
    stopping at the first depth-0 ';', ',' or unmatched ')' -- i.e. the end of
    an assignment's right-hand side or of a call's first argument. Parens
    are depth-tracked, so `HTF.ESCAPE_SC(a || b)` stays one operand.
    Returns None when the end isn't found within max_scan (inconclusive).
    """
    fm, cm = view.joined_fm, view.joined_cm
    end = min(len(fm), start + max_scan)
    parts: list[str] = []
    depth = 0
    in_str = False
    seg = start
    i = start
    while i < end:
        ch = fm[i]
        if ch == "'":
            in_str = not in_str
        elif in_str:
            pass
        elif ch == '(':
            depth += 1
        elif ch == ')' and depth > 0:
            depth -= 1
        elif depth == 0 and (ch in ');,'):
            parts.append(cm[seg:i])
            return parts
        elif depth == 0 and fm.startswith('||', i):
            parts.append(cm[seg:i])
            i += 2
            seg = i
            continue
        i += 1
    return None


# A whole operand that's a literal: '...' / N'...' / q'[...]', a number,
# CHR(n), or NULL.
_LITERAL_OPERAND_RE = re.compile(
    r"(?is)^\s*(?:[nN]?'.*'|[qQ]'.*'|\d+(?:\.\d+)?|CHR\s*\(\s*\d+\s*\)|NULL)\s*$"
)
_ASSERT_OPERAND_RE = re.compile(r"(?is)^\s*(?:SYS\s*\.\s*)?DBMS_ASSERT\s*\.\s*\w+\s*\(")
_ESCAPED_OPERAND_RE = re.compile(
    r"(?is)^\s*(?:SYS\s*\.\s*)?(?:HTF\s*\.\s*ESCAPE_(?:SC|URL)|APEX_ESCAPE\s*\.\s*\w+"
    r"|UTL_URL\s*\.\s*ESCAPE)\s*\("
)


def _is_literal(operand: str) -> bool:
    return bool(_LITERAL_OPERAND_RE.match(operand))


def _post_var_built_by_concat(match: re.Match, line_idx: int, view: FileView) -> bool:
    """INJ-6: keep when the executed variable is assigned anywhere in the
    enclosing unit from a || chain with at least one operand that's not a
    literal, not the variable itself (`v := v || ' AND ...'`), and not
    wrapped in DBMS_ASSERT."""
    var = match.group("var")
    first, last = plsql_block_bounds(view.fully_masked, line_idx)
    unit_start = view.offsets[first]
    unit_end = view.offsets[last] + len(view.fully_masked[last])
    # `v :=` or a declaration `v [CONSTANT] TYPE[(n)] [NOT NULL] :=`.
    assign_re = re.compile(
        rf"(?i)\b{re.escape(var)}\b"
        r"(?:\s+(?:CONSTANT\s+)?[\w.%]+(?:\s*\(\s*[\w\s,]*\))?(?:\s+NOT\s+NULL)?)?\s*:="
    )
    self_re = re.compile(rf"(?i)^\s*{re.escape(var)}\s*$")
    for m in assign_re.finditer(view.joined_fm, unit_start, unit_end):
        operands = top_level_operands(view, m.end())
        if operands is None or len(operands) < 2:
            continue
        if any(
            not (_is_literal(op) or self_re.match(op) or _ASSERT_OPERAND_RE.match(op))
            for op in operands
        ):
            return True
    return False


def _htp_unsafe_operands(match: re.Match, line_idx: int, view: FileView) -> tuple[int, int] | None:
    """(operand count, unsafe count) for an HTP.P(...) argument, or None."""
    operands = top_level_operands(view, view.offsets[line_idx] + match.end())
    if operands is None:
        return None
    unsafe = sum(
        1 for op in operands
        if op.strip() and not (_is_literal(op) or _ESCAPED_OPERAND_RE.match(op))
    )
    return len(operands), unsafe


def _post_htp_concat_unescaped(match: re.Match, line_idx: int, view: FileView) -> bool:
    counts = _htp_unsafe_operands(match, line_idx, view)
    return counts is not None and counts[0] >= 2 and counts[1] > 0


def _post_htp_single_unescaped(match: re.Match, line_idx: int, view: FileView) -> bool:
    counts = _htp_unsafe_operands(match, line_idx, view)
    return counts is not None and counts == (1, 1)


def _post_header_lacks_authid(match: re.Match, line_idx: int, view: FileView) -> bool:
    """AUTHZ-2: AUTHID can only appear in the header, between CREATE and the
    IS/AS that starts the body -- which may wrap onto later lines."""
    start = view.offsets[line_idx] + match.start()
    header_end = re.compile(r"(?i)\b(?:IS|AS)\b").search(view.joined_fm, start, start + 3000)
    header = view.joined_fm[start:header_end.start() if header_end else start + 3000]
    return not re.search(r"(?i)\bAUTHID\b", header)


_CONDITION_BEFORE_RE = re.compile(r"(?i)\b(?:IF|ELSIF|WHEN|WHERE|AND|OR|CASE)\b")
_COMPARISON_AFTER_RE = re.compile(r"(?i)^\s*(?:=|!=|<>|\^=|~=|\bIN\b|\bLIKE\b|\bNOT\s+IN\b)")


def _post_in_condition(match: re.Match, line_idx: int, view: FileView) -> bool:
    """AUTHZ-5: keep only when the SYS_CONTEXT call sits in a condition on
    its own line -- after IF/ELSIF/WHEN/WHERE/AND/OR/CASE, or directly
    compared. A plain assignment (usually logging) isn't flagged. Known gap:
    reading it into a variable and comparing that later isn't followed."""
    line = view.fully_masked[line_idx]
    return bool(
        _CONDITION_BEFORE_RE.search(line[:match.start()])
        or _COMPARISON_AFTER_RE.match(line[match.end():])
    )


_POST_CHECKS = {
    "var_built_by_concat":   _post_var_built_by_concat,
    "htp_concat_unescaped":  _post_htp_concat_unescaped,
    "htp_single_unescaped":  _post_htp_single_unescaped,
    "header_lacks_authid":   _post_header_lacks_authid,
    "in_condition":          _post_in_condition,
}


# ── Deduplication ─────────────────────────────────────────────────────────────
def dedup(findings: list[PlsqlHit]) -> list[PlsqlHit]:
    """
    When multiple rules fire on the exact same (file, line), keep only the
    highest-severity one and record the extra rule IDs on that hit's
    also_matched (shown via PlsqlHit.title). Never mutates the shared Rule --
    appending to rule.description here used to leak "[also matched: ...]"
    into every later hit of that rule and into the SARIF rule descriptors.
    """
    grouped: dict[tuple, list[PlsqlHit]] = defaultdict(list)
    for f in findings:
        grouped[(f.file, f.line_no)].append(f)

    result = []
    for _, group in grouped.items():
        group.sort(key=lambda f: SEV_ORDER[f.rule.severity])
        primary = group[0]
        primary.also_matched = [g.rule.id for g in group[1:]]
        result.append(primary)
    return result


# ── Scanner ───────────────────────────────────────────────────────────────────
def scan_file(path: Path, rules: list[Rule]) -> list[PlsqlHit]:
    findings: list[PlsqlHit] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    lines = text.splitlines()

    # comment-only masked: rules fire against this (string contents preserved)
    comment_masked = mask_comments_only(lines)
    # fully masked: used for BEGIN/END depth counting only
    fully_masked   = mask_comments_and_strings(lines)

    # Single joined string for cross-line || chain analysis.
    # Always built from comment_masked (strings visible) so the chain walker
    # can identify string-literal operands correctly, even when the trigger
    # pattern ran against fully_masked. Masking is length-preserving so
    # per-line column offsets are valid for both masked views.
    cm_offsets: list[int] = []
    _off = 0
    for cml in comment_masked:
        cm_offsets.append(_off)
        _off += len(cml) + 1
    joined_cm = "\n".join(comment_masked)
    view = FileView(
        fully_masked=fully_masked,
        comment_masked=comment_masked,
        joined_fm="\n".join(fully_masked),
        joined_cm=joined_cm,
        offsets=cm_offsets,
    )

    for rule in rules:
        if not any(str(path).lower().endswith(ext) for ext in rule.file_exts):
            continue

        for i, raw_line in enumerate(lines, 1):
            # Which masked view to trigger against:
            #   comment_masked (strings visible) -- when the rule needs to see
            #     string literal content (CRED-1 etc.) OR when it has
            #     literal_concat_suppress (chain anchor must land on the first
            #     quote, not on blanked-out space where the string was).
            #   fully_masked (strings blanked) -- for all other rules, so that
            #     keywords that happen to appear inside a string literal (e.g.
            #     'EXECUTE IMMEDIATE...' in a log message) can't false-positive.
            use_cm = rule.match_in_strings or rule.literal_concat_suppress
            check_line = (comment_masked if use_cm else fully_masked)[i - 1]
            if not check_line.strip():
                continue

            match = re.search(rule.pattern, check_line, re.IGNORECASE)
            if not match:
                continue

            # Literal-only || chain → safe, suppress.
            # The chain walker must always run against comment-masked text
            # (strings visible) so it can identify 'literal' operands even
            # when the trigger pattern matched against fully-masked text.
            # Positions are compatible because masking is length-preserving.
            if rule.literal_concat_suppress:
                col         = find_chain_start_col(rule, match)
                chain_start = cm_offsets[i - 1] + col
                if not plsql_chain_contains_variable(joined_cm, chain_start):
                    continue

            if rule.post_check and not _POST_CHECKS[rule.post_check](match, i - 1, view):
                continue

            keep, block_note = apply_block_check(
                rule, fully_masked, comment_masked, i - 1
            )
            if not keep:
                continue
            if rule.post_check:
                block_note = block_note or rule.block_note

            findings.append(PlsqlHit(
                rule=rule,
                file=str(path),
                line_no=i,
                line=raw_line.rstrip(),
                confidence=rule.confidence,
                block_note=block_note,
            ))

    return findings


# Extensions that hold SQL only some of the time -- code delivered as .txt
# is common (pasted out of a ticket, emailed, exported from a DB client), but
# so are requirements.txt, LICENSE.txt and READMEs. These are scanned only
# when their contents look like SQL statements.
SNIFFED_EXTENSIONS = {".txt"}
# Sniffing streams the file in chunks cut at line boundaries (every sniff
# pattern fits on one line), so a large SQL dump is accepted as soon as its
# first matching line is read and memory stays flat regardless of file size.
_SNIFF_CHUNK_CHARS = 1024 * 1024

# Statement shapes, anchored at line start, that prose and dependency lists
# don't produce: a CREATE of a stored unit followed by its name, a line
# that's only BEGIN/DECLARE, EXECUTE IMMEDIATE, or a GRANT ... TO ...; that
# ends in a semicolon.
_SQL_SNIFF_RE = re.compile(
    r"(?im)^\s*(?:"
    r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:NON)?EDITIONABLE\s+)?"
    r"(?:PROCEDURE|FUNCTION|PACKAGE(?:\s+BODY)?|TRIGGER|TYPE(?:\s+BODY)?)\s+[\w\"$#.]+"
    r"\s*(?:\(|\b(?:IS|AS|AUTHID|RETURN|BEFORE|AFTER|INSTEAD|FOR|UNDER|ACCESSIBLE)\b|$)"
    r"|(?:BEGIN|DECLARE)\s*$"
    r"|EXECUTE\s+IMMEDIATE\b"
    r"|GRANT\s+[^;\n]+\s+TO\s+[^;\n]+;"
    r")"
)


def looks_like_sql(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", errors="ignore") as fh:
            carry = ""
            while True:
                chunk = fh.read(_SNIFF_CHUNK_CHARS)
                if not chunk:
                    return bool(carry) and bool(_SQL_SNIFF_RE.search(carry))
                buf = carry + chunk
                cut = buf.rfind("\n") + 1
                if cut and _SQL_SNIFF_RE.search(buf, 0, cut):
                    return True
                carry = buf[cut:]
    except OSError:
        return False


def iter_plsql_files(root: Path):
    """Yield PL/SQL source files under root. Extension match is case-
    insensitive (.SQL/.PKB are common on Oracle shops), and IGNORE_DIRS is
    checked against the path *relative to root* so a target that itself
    lives under e.g. a "build" folder isn't skipped wholesale. A .txt is
    yielded only if looks_like_sql()."""
    for path in root.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in PLSQL_EXTENSIONS or not path.is_file():
            continue
        if suffix in SNIFFED_EXTENSIONS and not looks_like_sql(path):
            continue
        yield path


def scan_project(root: Path) -> list[PlsqlHit]:
    all_findings: list[PlsqlHit] = []
    for path in iter_plsql_files(root):
        all_findings.extend(scan_file(path, RULES))
    return dedup(all_findings)

