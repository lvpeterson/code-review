"""AWS Lambda (Python) handler checks -- LMB-xxx.

A Lambda handler's `event` is the attacker-controlled input (API Gateway
request, S3 object key, SQS message body...). This module:

  * finds handlers (`def x(event, context)`), reported as EntryPoints;
  * taint-tracks names derived from `event` through assignments, loops,
    `with` targets, f-strings, and one level of calls into helper functions
    defined in the same module (the helper's parameter becomes tainted);
  * flags tainted data reaching command/code execution, deserialization,
    SQL, outbound HTTP (SSRF), filesystem paths and sts:AssumeRole;
  * plus configuration-style checks that don't need taint (verify=False,
    logging the raw event, secrets in env vars, error details in responses,
    public S3 ACLs, static boto3 credentials).

Taint is intra-module and name-based: it doesn't follow attributes on
objects, return values of other modules, or data round-tripped through a
datastore. A sink with a non-literal but *untainted* argument is still
reported at lower severity with confidence REVIEW.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from checks import secrets
from core.fsutil import iter_files, read_text_safe
from core.models import EntryPoint, Finding
from core.rulescan import make_finding, rel, scan_text

_HANDLER_SIG = re.compile(r"(?m)^\s*(?:async\s+)?def\s+\w+\s*\(\s*(?:\w*event\w*)\s*(?::[^,]+)?,\s*(?:context|ctx|_context|lambda_context|_)\b")
_SECRET_ENV = re.compile(r"(?i)password|passwd|secret|token|api_?key|private_?key|credential")
_CMD_FUNCS = {"os.system", "os.popen", "os.execl", "os.execlp", "os.execv", "os.execvp", "os.spawnl", "os.spawnlp",
              "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput"}
_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
_DESER = {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "dill.loads", "jsonpickle.decode",
          "shelve.open", "yaml.unsafe_load", "yaml.full_load"}
_HTTP = re.compile(r"^(?:requests|httpx|session|s|client|http)\.(?:get|post|put|patch|delete|head|request|options)$|"
                   r"^(?:urllib\.request\.)?urlopen$|^urllib3\.\w+\.request$|^(?:http\.client\.)?HTTPS?Connection$")
_FILE_FUNCS = {"open", "os.remove", "os.unlink", "shutil.rmtree", "shutil.copy", "shutil.move", "os.rename",
               "pathlib.Path", "Path", "io.open", "codecs.open"}
_LOG_FUNCS = re.compile(r"^(?:print|(?:logging|logger|log|LOGGER|LOG|_logger)\.(?:debug|info|warning|warn|error|exception|critical))$")


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def is_handler(fn: ast.AST) -> bool:
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    args = [a.arg for a in fn.args.args]
    if len(args) >= 2 and "event" in args[0].lower() and args[1].lower() in ("context", "ctx", "_context", "lambda_context", "_"):
        return True
    return fn.name in ("lambda_handler", "handler") and len(args) == 2


def is_lambda_source(text: str) -> bool:
    return bool(_HANDLER_SIG.search(text))


@dataclass
class _Analysis:
    tainted: dict[str, set[str]] = field(default_factory=dict)  # function name -> tainted names


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _target_names(target: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}


def _propagate(fn: ast.AST, seeds: set[str]) -> set[str]:
    tainted = set(seeds)
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            new: set[str] = set()
            if isinstance(node, ast.Assign) and _names(node.value) & tainted:
                for t in node.targets:
                    new |= _target_names(t)
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)) and node.value is not None and _names(node.value) & tainted:
                new |= _target_names(node.target)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and _names(node.iter) & tainted:
                new |= _target_names(node.target)
            elif isinstance(node, ast.withitem) and node.optional_vars is not None and _names(node.context_expr) & tainted:
                new |= _target_names(node.optional_vars)
            elif isinstance(node, ast.NamedExpr) and _names(node.value) & tainted:
                new |= _target_names(node.target)
            if new - tainted:
                tainted |= new
                changed = True
    return tainted


def _analyze_taint(tree: ast.Module) -> dict[ast.AST, set[str]]:
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    result: dict[ast.AST, set[str]] = {}
    work = [(fn, {fn.args.args[0].arg}) for fn in funcs.values() if is_handler(fn)]
    seen_seeds: dict[str, set[str]] = {}
    while work:
        fn, seeds = work.pop()
        prev = seen_seeds.get(fn.name, set())
        if seeds <= prev and fn in result:
            continue
        seen_seeds[fn.name] = prev | seeds
        tainted = _propagate(fn, seen_seeds[fn.name])
        result[fn] = tainted
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            callee = funcs.get(dotted(call.func).split(".")[-1])
            if callee is None or callee is fn:
                continue
            params = [a.arg for a in callee.args.args]
            if params and params[0] == "self":
                params = params[1:]
            new_seeds = set()
            for i, arg in enumerate(call.args):
                if i < len(params) and _names(arg) & tainted:
                    new_seeds.add(params[i])
            for kw in call.keywords:
                if kw.arg in params and _names(kw.value) & tainted:
                    new_seeds.add(kw.arg)
            if new_seeds:
                work.append((callee, new_seeds))
    return result


def _is_literal(node: Optional[ast.AST]) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_literal(e) for e in node.elts)
    return False


def _kw(call: ast.Call, name: str) -> Optional[ast.AST]:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _first_arg(call: ast.Call, kwname: Optional[str] = None) -> Optional[ast.AST]:
    if call.args:
        return call.args[0]
    return _kw(call, kwname) if kwname else None


def _built_string(node: Optional[ast.AST]) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


class _Checker:
    def __init__(self, relative: str, tree: ast.Module, text: str):
        self.relative = relative
        self.tree = tree
        self.text = text
        self.findings: list[Finding] = []
        self.taint = _analyze_taint(tree)
        self.security_context = bool(re.search(r"(?i)token|secret|password|nonce|otp|api_?key|salt", text))

    def add(self, cid, sev, title, note, node, conf=None):
        self.findings.append(make_finding(cid, sev, title, note, self.relative, getattr(node, "lineno", 1), conf))

    def tainted_in(self, node: Optional[ast.AST], scope: set[str]) -> bool:
        return node is not None and bool(_names(node) & scope)

    def run(self) -> list[Finding]:
        scopes: dict[ast.AST, set[str]] = {}
        for fn, names in self.taint.items():
            for n in ast.walk(fn):
                scopes.setdefault(n, set()).update(names)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self.call(node, scopes.get(node, set()))
            elif isinstance(node, ast.Dict):
                self.dict_literal(node)
            elif isinstance(node, ast.ExceptHandler):
                self.except_handler(node)
        return self.findings

    def call(self, c: ast.Call, scope: set[str]) -> None:
        name = dotted(c.func)
        short = name.split(".")[-1]
        args = list(c.args) + [k.value for k in c.keywords]
        any_tainted = any(self.tainted_in(a, scope) for a in args)
        first = _first_arg(c)

        # command execution
        if name in _CMD_FUNCS or name in _SUBPROCESS:
            shell = _kw(c, "shell")
            shell_true = isinstance(shell, ast.Constant) and shell.value is True
            if any_tainted and (name in _CMD_FUNCS or shell_true or isinstance(first, (ast.Name, ast.JoinedStr, ast.BinOp))):
                self.add("LMB-001", "high", f"Event data reaches {name}()",
                         "A value derived from the Lambda event is used to build a command. With shell=True "
                         "/ os.system any ;, | or $() in it runs as a command in the function's execution "
                         "role. Pass an argument list without a shell, and validate against an allow-list.", c)
            elif (name in _CMD_FUNCS or shell_true) and not _is_literal(first):
                self.add("LMB-001", "medium", f"{name}() with a shell and a non-literal command",
                         "Trace where the command string comes from.", c, "REVIEW")
        # code execution
        elif name in ("eval", "exec", "compile", "builtins.eval"):
            if any_tainted:
                self.add("LMB-002", "high", f"Event data reaches {name}()",
                         "Arbitrary code execution in the function's role. Use json.loads / ast.literal_eval.", c)
            elif not _is_literal(first):
                self.add("LMB-002", "medium", f"{name}() of a non-literal", "Trace the argument's source.", c, "REVIEW")
        # deserialization
        elif name in _DESER or (name in ("yaml.load", "yaml.load_all") and not self._safe_loader(c)):
            self.add("LMB-003", "high" if any_tainted else "medium",
                     f"Unsafe deserialization: {name}()" + (" of event data" if any_tainted else ""),
                     "pickle/marshal/unsafe YAML can execute code while loading. Use json, or "
                     "yaml.safe_load.", c, None if any_tainted else "REVIEW")
        # SQL
        elif short in ("execute", "executemany", "raw", "executescript") or name in ("sqlalchemy.text", "text"):
            if _built_string(first):
                self.add("LMB-004", "high" if self.tainted_in(first, scope) else "medium",
                         "SQL built with string formatting" + (" from event data" if self.tainted_in(first, scope) else ""),
                         "Use parameterized queries (cursor.execute(sql, params)) -- never f-strings, % or + "
                         "to splice values into SQL.", c, None if self.tainted_in(first, scope) else "REVIEW")
        # outbound HTTP
        elif _HTTP.match(name) or short == "urlopen":
            url = _first_arg(c, "url")
            if short == "request" and len(c.args) >= 2:
                url = c.args[1]
            if self.tainted_in(url, scope):
                self.add("LMB-005", "high", "Event data controls an outbound request URL (SSRF)",
                         "The caller chooses where the function connects -- including internal VPC "
                         "services and the Lambda runtime API. Allow-list hosts/schemes and resolve + "
                         "check the IP before connecting.", c, "REVIEW")
            if name.startswith(("requests.", "httpx.", "session.")) or name in ("requests.request",):
                verify = _kw(c, "verify")
                if isinstance(verify, ast.Constant) and verify.value is False:
                    self.add("LMB-008", "medium", "TLS verification disabled (verify=False)",
                             "Any MITM can read and alter the request, including credentials.", c)
                if _kw(c, "timeout") is None and name.startswith("requests."):
                    self.add("LMB-009", "low", "HTTP request without a timeout",
                             "A hung upstream keeps the function running until the Lambda timeout "
                             "(cost / concurrency exhaustion). Pass timeout=.", c)
        # filesystem
        elif name in _FILE_FUNCS or name.endswith(".download_file"):
            target = first if name not in ("os.rename", "shutil.move", "shutil.copy") else None
            if name.endswith(".download_file"):
                target = c.args[2] if len(c.args) >= 3 else _kw(c, "Filename")
            if target is not None and self.tainted_in(target, scope):
                self.add("LMB-006", "medium", f"Event data used as a filesystem path ({name})",
                         "../ sequences let the caller read/overwrite files outside the intended "
                         "directory (/tmp is shared across warm invocations). Use os.path.basename + a "
                         "fixed directory, or a generated name.", c)
            elif isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.startswith("/tmp/") \
                    and name in ("open", "io.open", "codecs.open") and len(c.args) > 1:
                self.add("LMB-017", "low", f"Fixed /tmp path: {first.value}",
                         "/tmp persists across warm invocations of the same execution environment -- data "
                         "from one request can leak into the next. Use tempfile and clean up.", c, "REVIEW")
        # STS
        elif short == "assume_role":
            if self.tainted_in(_kw(c, "RoleArn"), scope):
                self.add("LMB-016", "high", "Event data chooses which IAM role to assume",
                         "The caller picks the RoleArn -- a confused-deputy path to any role that trusts "
                         "this function's role. Map an allow-listed identifier to the ARN server-side.", c)
        # logging the raw event
        if _LOG_FUNCS.match(name) or name == "print":
            if any(self._is_raw_event(a, scope) for a in args):
                self.add("LMB-007", "medium", "Whole Lambda event written to logs",
                         "The raw event includes Authorization headers, cookies, tokens and request "
                         "bodies -- all of it lands in CloudWatch for anyone with logs:GetLogEvents. Log "
                         "selected, non-sensitive fields only.", c)
        # weak crypto / randomness
        if name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1"):
            self.add("LMB-010", "low", f"Weak hash {name}()",
                     "Fine for checksums, not for anything security-related (signatures, tokens, "
                     "passwords).", c, "REVIEW")
        if name.startswith("random.") and short in ("random", "randint", "choice", "choices", "randrange", "getrandbits", "sample") \
                and self.security_context:
            self.add("LMB-010", "medium", f"Non-cryptographic {name}() in security-sensitive code",
                     "random is predictable. Use the secrets module for tokens/keys/nonces.", c, "REVIEW")
        # secrets via environment
        if name in ("os.environ.get", "os.getenv", "environ.get", "getenv"):
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and _SECRET_ENV.search(first.value):
                self.add("LMB-011", "low", f"Secret read from environment variable {first.value}",
                         "Lambda environment variables are visible to anyone with "
                         "lambda:GetFunctionConfiguration and live in Terraform state. Fetch the secret "
                         "from Secrets Manager / SSM SecureString at runtime instead.", c, "REVIEW")
        # static credentials
        if short in ("client", "resource", "Session") and name.startswith(("boto3", "session", "Session")):
            if _is_literal(_kw(c, "aws_secret_access_key")) and _kw(c, "aws_secret_access_key") is not None:
                self.add("LMB-014", "high", "Static AWS credentials passed to boto3",
                         "Use the function's execution role -- boto3 picks it up automatically.", c)
        # public object ACLs
        acl = _kw(c, "ACL")
        if isinstance(acl, ast.Constant) and acl.value in ("public-read", "public-read-write", "authenticated-read"):
            self.add("LMB-013", "medium", f"S3 object written with ACL={acl.value}",
                     "Objects become readable by everyone. Serve through CloudFront/presigned URLs instead.", c)
        if short == "generate_presigned_url":
            exp = _kw(c, "ExpiresIn")
            if isinstance(exp, ast.Constant) and isinstance(exp.value, int) and exp.value > 86400:
                self.add("LMB-018", "low", f"Presigned URL valid for {exp.value // 3600}h",
                         "Long-lived presigned URLs are bearer tokens that can be shared/leaked. Keep them short.", c)

    def _is_raw_event(self, node: ast.AST, scope: set[str]) -> bool:
        handlers_event = {fn.args.args[0].arg for fn in self.taint if is_handler(fn)}
        if isinstance(node, ast.Name) and node.id in handlers_event:
            return True
        if isinstance(node, ast.Call) and dotted(node.func) in ("json.dumps", "str", "repr") and node.args:
            return self._is_raw_event(node.args[0], scope)
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) and self._is_raw_event(v.value, scope) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self._is_raw_event(node.left, scope) or self._is_raw_event(node.right, scope)
        return False

    @staticmethod
    def _safe_loader(c: ast.Call) -> bool:
        loader = _kw(c, "Loader") or (c.args[1] if len(c.args) > 1 else None)
        return loader is not None and re.search(r"Safe|BaseLoader", dotted(loader) or "") is not None

    def dict_literal(self, d: ast.Dict) -> None:
        for k, v in zip(d.keys, d.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() == "access-control-allow-origin" \
                    and isinstance(v, ast.Constant) and v.value == "*":
                self.add("LMB-015", "low", "Response allows any origin (Access-Control-Allow-Origin: *)",
                         "Any website can read this API's responses from a victim's browser. Echo back only "
                         "allow-listed origins.", d)

    def except_handler(self, h: ast.ExceptHandler) -> None:
        for node in ast.walk(h):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            leaks = False
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Call):
                    n = dotted(sub.func)
                    if n in ("traceback.format_exc", "traceback.format_exception"):
                        leaks = True
                    elif n in ("str", "repr") and sub.args and isinstance(sub.args[0], ast.Name) and sub.args[0].id == h.name:
                        leaks = True
                elif isinstance(sub, ast.FormattedValue) and isinstance(sub.value, ast.Name) and sub.value.id == h.name:
                    leaks = True
            if leaks:
                self.add("LMB-012", "low", "Exception details returned to the caller",
                         "Stack traces / exception messages reveal internals (paths, SQL, ARNs, library "
                         "versions). Log them, return a generic error and a request id.", node)


def scan_file(path: Path, root: Path) -> tuple[list[Finding], list[EntryPoint]]:
    text = read_text_safe(path)
    relative = rel(path, root)
    findings = scan_text(text, secrets.secret_rules(), relative, "hash")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings, []
    checker = _Checker(relative, tree, text)
    findings += checker.run()
    entry_points = []
    for fn in ast.walk(tree):
        if is_handler(fn):
            entry_points.append(EntryPoint(
                kind="LambdaHandler",
                detail=_guess_trigger(fn),
                handler_name=f"{path.stem}.{fn.name}",
                file=relative,
                line=fn.lineno,
                source_start_line=fn.lineno,
                source_end_line=getattr(fn, "end_lineno", fn.lineno),
            ))
    return findings, entry_points


def _guess_trigger(fn: ast.AST) -> str:
    keys = {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    if keys & {"httpMethod", "queryStringParameters", "pathParameters", "requestContext", "rawPath", "routeKey"}:
        return "API Gateway / function URL (HTTP)"
    if "s3" in keys and "Records" in keys:
        return "S3 event"
    if "Sns" in keys:
        return "SNS"
    if "Records" in keys and ("body" in keys or "receiptHandle" in keys):
        return "SQS"
    if "detail-type" in keys or "detail" in keys:
        return "EventBridge"
    if "Records" in keys and "dynamodb" in keys:
        return "DynamoDB stream"
    return ""


def scan_project(root: Path) -> tuple[list[Finding], list[EntryPoint]]:
    findings: list[Finding] = []
    entry_points: list[EntryPoint] = []
    for path in iter_files(root, (".py",)):
        text = read_text_safe(path)
        if not is_lambda_source(text):
            continue
        f, e = scan_file(path, root)
        findings += f
        entry_points += e
    _terraform_context(root, findings, entry_points)
    return findings, entry_points


def _terraform_context(root: Path, findings: list[Finding], entry_points: list[EntryPoint]) -> None:
    """When the same repo deploys the function with Terraform, tie each
    handler file to its aws_lambda_function: execution-role permissions
    (blast radius of any code finding) and public triggers (who can send
    `event`). Adds LMB-019 per handler and appends the context to every
    finding in that file."""
    try:
        from checks import tf_graph
        if not any(True for _ in tf_graph.iter_tf_files(root)):
            return
        proj = tf_graph.load(root)
    except Exception:
        return
    rroot = root.resolve()
    for lam in proj.lambdas:
        fn_addr = f"aws_lambda_function.{lam.block.labels[1]}"
        fn_where = f"{rel(lam.block.file.resolve(), rroot)}:{lam.block.line}"
        for code in lam.code_files:
            relative = rel(code, rroot)
            role_txt = lam.role.summary(rroot) if lam.role else "role not resolvable from Terraform"
            public = ("Reachable by: " + "; ".join(lam.public_via) + ". ") if lam.public_via else ""
            note = f" Deployed as {fn_addr} ({fn_where}); runs as {role_txt}. {public}".rstrip()
            in_file = [f for f in findings if f.file == relative]
            for f in in_file:
                f.description += note
            handler_fn = (lam.handler or "").rsplit(".", 1)[-1]
            ep = next((e for e in entry_points if e.file == relative and e.handler_name.endswith("." + handler_fn)), None)
            if ep is not None and lam.public_via:
                ep.detail = "; ".join(x for x in (ep.detail, f"public: {lam.public_via[0]}") if x)
            privileged = bool(lam.role and lam.role.privileged)
            serious = [f for f in in_file if f.severity in ("high", "critical")]
            sev = "high" if privileged and (serious or lam.public_via) else "medium" if privileged else "info"
            findings.append(make_finding(
                "LMB-019", sev,
                f"Handler '{lam.handler}' runs as {lam.role.address if lam.role else 'an unresolved role'}"
                + (" with admin-level / privilege-escalation permissions" if privileged else ""),
                "Every finding in this handler executes with the execution role's permissions. "
                + (f"{len(serious)} high-severity code finding(s) here combine with it. " if serious and privileged else "")
                + "Scope the role to the specific actions and resources the function uses." + note,
                relative, ep.line if ep else 1, None if privileged else "REVIEW"))
