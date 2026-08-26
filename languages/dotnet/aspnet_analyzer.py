"""Deep-dive analyzer for ASP.NET Core targets.

Supports both common routing styles, extracted independently and merged:

  Minimal APIs      `app.MapGet("/path", Handler)` -- ASP.NET Core 6+,
                     increasingly the default for new APIs. Same shape as
                     Express's `app.get(path, handler)`.
  Attribute routing  `[HttpGet("path")]` on a controller method, with an
                     optional class-level `[Route("api/[controller]")]`
                     base path -- the closest analog to Spring's
                     @RequestMapping + @GetMapping pattern, including the
                     `[controller]` token that Route substitutes with the
                     controller class name (minus its "Controller" suffix).

tree-sitter gives real start/end positions directly here (unlike javalang
for Spring, which needed manual brace-counting), so the HTML report's code
view doesn't need any special-case handling for this language.
"""
from __future__ import annotations

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route
from core.paths import join_path_segments
from core.registry import register
from languages.dotnet._ts_utils import iter_nodes, node_text, parser, string_literal_value

_MINIMAL_API_METHODS = {
    "MapGet": "GET",
    "MapPost": "POST",
    "MapPut": "PUT",
    "MapPatch": "PATCH",
    "MapDelete": "DELETE",
}

_HTTP_ATTRIBUTE_METHODS = {
    "HttpGet": "GET",
    "HttpPost": "POST",
    "HttpPut": "PUT",
    "HttpPatch": "PATCH",
    "HttpDelete": "DELETE",
}

_CONTROLLER_ATTRIBUTES = {"ApiController", "Controller"}

# Attributes that plausibly indicate auth enforcement. Extend this list to
# match whatever this codebase's auth policy/attribute is actually called.
KNOWN_AUTH_INDICATORS = {
    "Authorize",
}


def _attribute_name(attribute_node, src: bytes) -> str | None:
    name_node = attribute_node.child_by_field_name("name")
    return node_text(name_node, src) if name_node else None


def _attribute_first_string_arg(attribute_node, src: bytes) -> str | None:
    arg_list = next((c for c in attribute_node.children if c.type == "attribute_argument_list"), None)
    if arg_list is None:
        return None
    for arg in arg_list.named_children:
        if arg.type != "attribute_argument":
            continue
        for inner in arg.named_children:
            value = string_literal_value(inner, src)
            if value is not None:
                return value
    return None


def _attributes_on(declaration_node, src: bytes) -> list:
    """Every `[Attr(...)]` attribute directly attached to a class/method
    declaration -- in this grammar, each `attribute_list` is a direct child
    of the declaration it decorates, not a separate preceding statement.
    """
    attrs = []
    for child in declaration_node.children:
        if child.type == "attribute_list":
            attrs.extend(a for a in child.named_children if a.type == "attribute")
    return attrs


def _describe_argument(argument_node, src: bytes) -> str:
    inner = argument_node.named_children[0] if argument_node.named_children else None
    if inner is None:
        return "?"
    if inner.type == "identifier":
        return node_text(inner, src)
    return "<inline handler>"


def _extract_minimal_api_call(node, src: bytes):
    if node.type != "invocation_expression":
        return None
    func = node.child_by_field_name("function")
    if func is None or func.type != "member_access_expression":
        return None
    name_node = func.child_by_field_name("name")
    if name_node is None:
        return None
    method_name = node_text(name_node, src)
    if method_name not in _MINIMAL_API_METHODS:
        return None

    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return None
    arg_nodes = [c for c in args_node.named_children if c.type == "argument"]
    if not arg_nodes:
        return None
    path_inner = arg_nodes[0].named_children[0] if arg_nodes[0].named_children else None
    path = string_literal_value(path_inner, src) if path_inner else None
    if path is None:
        return None

    return _MINIMAL_API_METHODS[method_name], path, arg_nodes[1:]


def _find_minimal_api_routes(tree_root, src: bytes, relative_file: str) -> list[Route]:
    routes = []
    for node in iter_nodes(tree_root):
        extracted = _extract_minimal_api_call(node, src)
        if extracted is None:
            continue
        method, path, rest_args = extracted

        handler_name = _describe_argument(rest_args[-1], src) if rest_args else "?"
        middleware_names = [_describe_argument(a, src) for a in rest_args[:-1]]

        routes.append(
            Route(
                path=path,
                methods=[method],
                handler_name=handler_name,
                file=relative_file,
                line=node.start_point[0] + 1,
                auth_decorators=middleware_names,
                raw_snippet=node_text(node, src)[:120],
            )
        )
    return routes


def _find_attribute_routing_routes(tree_root, src: bytes, relative_file: str) -> list[Route]:
    routes = []
    for class_node in iter_nodes(tree_root):
        if class_node.type != "class_declaration":
            continue
        class_attrs = _attributes_on(class_node, src)
        class_attr_names = {_attribute_name(a, src) for a in class_attrs}
        if not (_CONTROLLER_ATTRIBUTES & class_attr_names):
            continue

        controller_name = ""
        name_node = class_node.child_by_field_name("name")
        if name_node:
            controller_name = node_text(name_node, src)
            if controller_name.endswith("Controller"):
                controller_name = controller_name[: -len("Controller")]

        base_path = ""
        for attribute in class_attrs:
            if _attribute_name(attribute, src) == "Route":
                base_path = (_attribute_first_string_arg(attribute, src) or "").replace("[controller]", controller_name)

        body = class_node.child_by_field_name("body")
        if body is None:
            continue

        for member in body.named_children:
            if member.type != "method_declaration":
                continue
            method_attrs = _attributes_on(member, src)
            mapping_attr = next(
                (a for a in method_attrs if _attribute_name(a, src) in _HTTP_ATTRIBUTE_METHODS), None
            )
            if mapping_attr is None:
                continue

            http_method = _HTTP_ATTRIBUTE_METHODS[_attribute_name(mapping_attr, src)]
            sub_path = _attribute_first_string_arg(mapping_attr, src) or ""
            full_path = join_path_segments(base_path, sub_path)

            auth_decorators = [
                _attribute_name(a, src) for a in method_attrs if _attribute_name(a, src) in KNOWN_AUTH_INDICATORS
            ]
            handler_name_node = member.child_by_field_name("name")
            handler_name = node_text(handler_name_node, src) if handler_name_node else "?"

            routes.append(
                Route(
                    path=full_path,
                    methods=[http_method],
                    handler_name=handler_name,
                    file=relative_file,
                    line=member.start_point[0] + 1,
                    auth_decorators=auth_decorators,
                    raw_snippet=f"[{_attribute_name(mapping_attr, src)}(...)] {handler_name}(...)",
                    source_file=relative_file,
                    source_start_line=member.start_point[0] + 1,
                    source_end_line=member.end_point[0] + 1,
                )
            )
    return routes


@register("dotnet", "aspnet")
class AspNetAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []

        for cs_file in iter_files(self.target_path, (".cs",)):
            src = read_text_safe(cs_file).encode("utf-8")
            if not src:
                continue
            tree = parser().parse(src)
            relative_file = str(cs_file.relative_to(self.target_path))

            routes += _find_minimal_api_routes(tree.root_node, src, relative_file)
            routes += _find_attribute_routing_routes(tree.root_node, src, relative_file)

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: ASP.NET-specific checks -- e.g. [EnableCors("AllowAll")] with
        # a wildcard policy, query/body param detection ([FromQuery]/
        # [FromBody] parameter attributes, or Minimal API handler bodies
        # reading HttpContext.Request.Query directly), Minimal API handler
        # resolution to a named method's source range (currently falls back
        # to the registration line only).
        return findings
