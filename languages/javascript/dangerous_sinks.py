"""Dangerous-sink heuristics shared by every JS/TS framework analyzer
(Express, Hono, Next.js) -- command injection, path traversal, SSRF, open
redirect. One shared module rather than duplicated per analyzer file (the
convention every other JS helper in this package follows) because these
scans are substantial and genuinely framework-agnostic: they look at raw
Node/browser-fetch APIs that show up identically no matter which of the
three frameworks registered the route that (maybe) calls them.

Same philosophy as checks/injection.py's Java counterpart: presence-only,
flags a dangerous API called with an argument that isn't a fixed string
literal, never a real taint trace. A non-literal argument might still be a
hardcoded constant, not attacker-controlled.
"""
from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from checks import injection as injection_checks
from core.fsutil import iter_files, read_text_safe
from core.models import Finding

_JS_LANGUAGE = Language(tsjs.language())
_TS_LANGUAGE = Language(tsts.language_typescript())

_SHELL_EXEC_NAMES = {"exec", "execSync"}
_SPAWN_LIKE_NAMES = {"spawn", "spawnSync", "execFile", "execFileSync"}

# fs's own read/write/delete/stream APIs -- the actual string-to-path
# construction moment, same idea as Java's `new File(...)`/`Paths.get(...)`.
# A `path.join(base, userInput)` argument is itself a non-literal
# call_expression, so it's still caught here with no extra tracing needed.
_FS_PATH_SINK_NAMES = {
    "readFile", "readFileSync",
    "writeFile", "writeFileSync",
    "unlink", "unlinkSync",
    "createReadStream", "createWriteStream",
}

# axios.get/post/etc and the built-in http(s) module's .get/.request all
# take the URL as their first argument; `fetch` is a bare global call, not
# a member call, so it's matched separately by name alone.
_HTTP_CLIENT_METHOD_NAMES = {"get", "post", "put", "patch", "delete", "request"}
_HTTP_CLIENT_OBJECT_NAMES = {"axios", "http", "https"}
_FETCH_NAME = "fetch"


def _parser_for(path: Path) -> Parser:
    return Parser(_TS_LANGUAGE) if path.suffix == ".ts" else Parser(_JS_LANGUAGE)


def _node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


def _callee_name(func: Node, src: bytes) -> str:
    """`exec(...)` -> "exec"; `child_process.exec(...)` -> "exec" (the
    property name, ignoring the namespace object) -- either form is common
    depending on whether child_process was destructured or required whole.
    """
    if func.type == "member_expression":
        prop = func.child_by_field_name("property")
        return _node_text(prop, src) if prop else ""
    return _node_text(func, src)


def _is_literal_ish(node: Node) -> bool:
    """True for a string/template literal with no interpolation, or a
    number/boolean -- anything else (identifier, member access, call,
    binary `+` concatenation, a template literal WITH interpolation) counts
    as non-literal for this heuristic.
    """
    if node.type == "string":
        return True
    if node.type == "template_string":
        return not any(c.type == "template_substitution" for c in node.children)
    return node.type in ("number", "true", "false")


def _has_non_literal_argument(args: list[Node]) -> bool:
    return any(not _is_literal_ish(a) for a in args)


def _object_has_shell_true(node: Node, src: bytes) -> bool:
    """True if any argument is an object literal containing `shell: true`
    (checked textually -- good enough for the common inline-options-object
    case; a shell flag assembled elsewhere and spread in wouldn't be seen).
    """
    for arg in node.named_children:
        if arg.type == "object":
            text = _node_text(arg, src)
            if "shell:" in text.replace(" ", "") or "shell :" in text:
                if "true" in text:
                    return True
    return False


def _detect_command_injection_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)
        relative_file = str(src_file.relative_to(target_path))

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            name = _callee_name(func, src)

            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []
            line = node.start_point[0] + 1

            if name in _SHELL_EXEC_NAMES and args and not _is_literal_ish(args[0]):
                findings.append(injection_checks.command_injection_sink_finding(relative_file, line))
            elif name in _SPAWN_LIKE_NAMES and args_node is not None and _object_has_shell_true(args_node, src):
                findings.append(injection_checks.command_injection_sink_finding(relative_file, line))
    return findings


def _detect_path_traversal_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)
        relative_file = str(src_file.relative_to(target_path))

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue
            name = _callee_name(func, src)
            if name not in _FS_PATH_SINK_NAMES:
                continue

            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []
            if args and not _is_literal_ish(args[0]):
                line = node.start_point[0] + 1
                findings.append(injection_checks.path_traversal_sink_finding(relative_file, line, f"{name}(...)"))
    return findings


def _detect_ssrf_sinks(target_path: Path) -> list[Finding]:
    """`fetch(url)` (a bare global call) and `<obj>.get/post/.../request(url)`
    where `<obj>` is literally named `axios`/`http`/`https` -- restricted to
    those three names specifically because `get`/`post`/etc are far too
    generic a method name to flag on any object (Express/Hono's own
    `app.get(path, handler)` route registrations would otherwise match).
    """
    findings: list[Finding] = []
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)
        relative_file = str(src_file.relative_to(target_path))

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None:
                continue

            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []
            line = node.start_point[0] + 1

            if func.type == "identifier" and _node_text(func, src) == _FETCH_NAME:
                if args and not _is_literal_ish(args[0]):
                    findings.append(injection_checks.ssrf_sink_finding(relative_file, line, "fetch(...)"))
                continue

            if func.type != "member_expression":
                continue
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj is None or prop is None or obj.type != "identifier":
                continue
            obj_name = _node_text(obj, src)
            method_name = _node_text(prop, src)
            if obj_name not in _HTTP_CLIENT_OBJECT_NAMES or method_name not in _HTTP_CLIENT_METHOD_NAMES:
                continue
            if args and not _is_literal_ish(args[0]):
                findings.append(injection_checks.ssrf_sink_finding(relative_file, line, f"{obj_name}.{method_name}(...)"))
    return findings


def _detect_open_redirect_sinks(target_path: Path) -> list[Finding]:
    """Any `<obj>.redirect(nonLiteralArg)` call -- deliberately broad by
    method name rather than per-framework, since "redirect" as a method
    name is specific enough on its own to catch Express's `res.redirect()`,
    Hono's `c.redirect()`, and Next's `NextResponse.redirect()` in one
    check with no framework branching.
    """
    findings: list[Finding] = []
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)
        relative_file = str(src_file.relative_to(target_path))

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue
            prop = func.child_by_field_name("property")
            if prop is None or _node_text(prop, src) != "redirect":
                continue

            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []
            if args and not _is_literal_ish(args[0]):
                line = node.start_point[0] + 1
                findings.append(injection_checks.open_redirect_sink_finding(relative_file, line, "redirect(...)"))
    return findings


def detect_dangerous_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += _detect_command_injection_sinks(target_path)
    findings += _detect_path_traversal_sinks(target_path)
    findings += _detect_ssrf_sinks(target_path)
    findings += _detect_open_redirect_sinks(target_path)
    return findings
