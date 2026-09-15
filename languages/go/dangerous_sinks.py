"""Dangerous-sink heuristics shared by every Go framework analyzer (Gin,
net/http) -- command injection, path traversal, SSRF, open redirect. One
shared module (using the existing `_ts_utils.py` helpers, same convention
those two analyzers already follow) rather than duplicated per analyzer
file, since these scans look at raw stdlib APIs (`os/exec`, `os`,
`net/http`) that show up identically no matter which framework registered
the route that (maybe) calls them.

Same philosophy as checks/injection.py's Java counterpart: presence-only,
flags a dangerous API called with an argument that isn't a fixed string
literal, never a real taint trace.
"""
from __future__ import annotations

from pathlib import Path

from checks import injection as injection_checks
from core.fsutil import iter_files, read_text_safe
from core.models import Finding
from languages.go._ts_utils import iter_nodes, node_text, parser

_LITERAL_NODE_TYPES = {
    "interpreted_string_literal", "raw_string_literal",
    "int_literal", "float_literal", "true", "false",
}


def _is_literal_ish(node) -> bool:
    return node.type in _LITERAL_NODE_TYPES


def _has_non_literal_argument(args: list) -> bool:
    return any(not _is_literal_ish(a) for a in args)


def _call_parts(node, src: bytes):
    """(object_name, method_name, args) for a `pkg.Func(...)`/`obj.Method(...)`
    call_expression, or None if `node` isn't shaped that way.
    """
    if node.type != "call_expression":
        return None
    func = node.child_by_field_name("function")
    if func is None or func.type != "selector_expression":
        return None
    operand = func.child_by_field_name("operand")
    field = func.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return None

    args_node = node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []
    return node_text(operand, src), node_text(field, src), args


_EXEC_FUNC_NAMES = {"Command", "CommandContext"}


def _detect_command_injection_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for go_file in iter_files(target_path, (".go",)):
        src = read_text_safe(go_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)
        relative_file = str(go_file.relative_to(target_path))

        for node in iter_nodes(tree.root_node):
            parts = _call_parts(node, src)
            if parts is None:
                continue
            obj_name, method_name, args = parts
            if obj_name != "exec" or method_name not in _EXEC_FUNC_NAMES:
                continue
            if _has_non_literal_argument(args):
                line = node.start_point[0] + 1
                findings.append(injection_checks.command_injection_sink_finding(relative_file, line))
    return findings


_OS_PATH_SINK_NAMES = {"Open", "ReadFile", "WriteFile", "Create", "Remove"}


def _detect_path_traversal_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for go_file in iter_files(target_path, (".go",)):
        src = read_text_safe(go_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)
        relative_file = str(go_file.relative_to(target_path))

        for node in iter_nodes(tree.root_node):
            parts = _call_parts(node, src)
            if parts is None:
                continue
            obj_name, method_name, args = parts
            if obj_name != "os" or method_name not in _OS_PATH_SINK_NAMES:
                continue
            if args and not _is_literal_ish(args[0]):
                line = node.start_point[0] + 1
                findings.append(
                    injection_checks.path_traversal_sink_finding(relative_file, line, f"os.{method_name}(...)")
                )
    return findings


_HTTP_URL_FUNC_NAMES = {"Get", "Post", "PostForm", "NewRequest", "NewRequestWithContext"}
# The URL argument's position differs: Get/Post/PostForm take it first;
# NewRequest/NewRequestWithContext take (ctx,) method, url, body -- url is
# the 2nd positional arg for NewRequest, 3rd for NewRequestWithContext.
_HTTP_URL_ARG_INDEX = {
    "Get": 0, "Post": 0, "PostForm": 0,
    "NewRequest": 1, "NewRequestWithContext": 2,
}


def _detect_ssrf_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for go_file in iter_files(target_path, (".go",)):
        src = read_text_safe(go_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)
        relative_file = str(go_file.relative_to(target_path))

        for node in iter_nodes(tree.root_node):
            parts = _call_parts(node, src)
            if parts is None:
                continue
            obj_name, method_name, args = parts
            if obj_name != "http" or method_name not in _HTTP_URL_FUNC_NAMES:
                continue
            url_index = _HTTP_URL_ARG_INDEX[method_name]
            if len(args) > url_index and not _is_literal_ish(args[url_index]):
                line = node.start_point[0] + 1
                findings.append(
                    injection_checks.ssrf_sink_finding(relative_file, line, f"http.{method_name}(...)")
                )
    return findings


def _detect_open_redirect_sinks(target_path: Path) -> list[Finding]:
    """`http.Redirect(w, r, url, code)` (net/http, url is the 3rd
    positional arg) and gin's `c.Redirect(code, url)` (url is the 2nd,
    since gin has no separate writer/request args) -- two distinct
    call shapes distinguished by the object name.
    """
    findings: list[Finding] = []
    for go_file in iter_files(target_path, (".go",)):
        src = read_text_safe(go_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)
        relative_file = str(go_file.relative_to(target_path))

        for node in iter_nodes(tree.root_node):
            parts = _call_parts(node, src)
            if parts is None:
                continue
            obj_name, method_name, args = parts
            if method_name != "Redirect":
                continue

            if obj_name == "http" and len(args) > 2 and not _is_literal_ish(args[2]):
                line = node.start_point[0] + 1
                findings.append(injection_checks.open_redirect_sink_finding(relative_file, line, "http.Redirect(...)"))
            elif obj_name != "http" and len(args) > 1 and not _is_literal_ish(args[1]):
                line = node.start_point[0] + 1
                findings.append(
                    injection_checks.open_redirect_sink_finding(relative_file, line, f"{obj_name}.Redirect(...)")
                )
    return findings


def detect_dangerous_sinks(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += _detect_command_injection_sinks(target_path)
    findings += _detect_path_traversal_sinks(target_path)
    findings += _detect_ssrf_sinks(target_path)
    findings += _detect_open_redirect_sinks(target_path)
    return findings
