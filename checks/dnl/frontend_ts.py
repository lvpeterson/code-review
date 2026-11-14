"""tree-sitter-c-sharp lowering to the roslyn-ir schema-1 subset (degraded mode).

Mirrors tools/roslyn-ir/src/CSharpLowering.cs shape for shape, minus the
semantic keys (`sym` on call/member/name/index, `type_full` on new/local): a
rule that needs a resolved symbol sees none and falls back to name matching or
stays silent, never raises.

Anything without a mapping becomes `other` (statement) / `unknown` (expression)
carrying its source text, which the rules treat conservatively. Lowering never
raises: a construct that fails becomes an unknown node, a member that fails
keeps its signature with a one-statement `other` body, and a file that fails
entirely returns an `{"error": ...}` record (load_file_ir turns it into a note).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import tree_sitter_c_sharp as _tscs
from tree_sitter import Language, Node, Parser

_PARSER = Parser(Language(_tscs.language()))

# Nesting budget, the analogue of the helper's JSON depth cap: past it the rest
# of the syntax is one other/unknown node holding its text, so a 5000-term
# concatenation cannot blow the recursion limit of the rules' walkers.
MAX_DEPTH = 300

_TYPE_NODES = {"class_declaration", "struct_declaration", "interface_declaration",
               "record_declaration", "record_struct_declaration", "enum_declaration"}
_STRUCT_KINDS = {"struct_declaration", "record_struct_declaration"}

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
            "\\": "\\", "'": "'", '"': '"'}
_ESC_RE = re.compile(r"\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{1,4}|.)", re.S)
_NUM_SUFFIX = re.compile(r"(?i)(?:ul|lu|u|l|f|d|m)$")


def _unescape(s: str) -> str:
    def sub(m: re.Match) -> str:
        e = m.group(1)
        if e[0] in "uUx" and len(e) > 1:
            try:
                return chr(int(e[1:], 16))
            except (ValueError, OverflowError):
                return m.group(0)
        return _ESCAPES.get(e, e)
    return _ESC_RE.sub(sub, s)


def _number(text: str):
    """Python value of a numeric literal token, None when unparseable."""
    t = text.replace("_", "")
    low = t.lower()
    try:
        if low.startswith("0x") or low.startswith("0b"):
            body = _NUM_SUFFIX.sub("", low) if low.startswith("0b") else re.sub(r"(?:ul|lu|u|l)$", "", low)
            return int(body, 16 if low.startswith("0x") else 2)
        body = _NUM_SUFFIX.sub("", t)
        if re.fullmatch(r"\d+", body):
            return int(body)
        return float(body)
    except ValueError:
        return None


class _Lowering:
    def __init__(self, src: bytes):
        self.src = src
        self.depth = 0
        # Receivers of enclosing `?.` accesses, consumed by member/element bindings.
        self.receivers: list[Node] = []
        # `using Sha = System.Security.Cryptography.SHA1;` aliases. Without the helper nothing
        # resolves them, so an alias used as an expression or `new` type is expanded in place:
        # the rules then see the real type name instead of a name that matches nothing.
        self.aliases: dict[str, str] = {}

    # -- helpers --------------------------------------------------------

    def text(self, n: Node | None) -> str:
        return self.src[n.start_byte:n.end_byte].decode("utf-8", errors="replace") if n is not None else ""

    @staticmethod
    def line(n: Node) -> int:
        return n.start_point[0] + 1

    @staticmethod
    def end_line(n: Node) -> int:
        # Row of the last character, like Roslyn's EndLine.
        return n.end_point[0] + (1 if n.end_point[1] > 0 or n.end_byte == n.start_byte else 0)

    def decl_line(self, n: Node) -> int:
        """Declaration line: first child after any attribute lists."""
        for c in n.children:
            if c.type != "attribute_list":
                return self.line(c)
        return self.line(n)

    @staticmethod
    def is_expr(c: Node) -> bool:
        """Named nodes plus the `this` / `base` keyword tokens, which the grammar leaves anonymous."""
        return c.is_named or c.type in ("this", "base")

    @staticmethod
    def kids(n: Node) -> list[Node]:
        return [c for c in n.children if (c.is_named or c.type in ("this", "base")) and c.type != "comment"]

    def named(self, n: Node) -> list[Node]:
        return self.kids(n)

    def simple_name(self, n: Node | None) -> str:
        """Rightmost identifier of a type name, without type arguments."""
        if n is None:
            return ""
        t = n.type
        if t == "identifier":
            return self.text(n)
        if t == "generic_name":
            first = next((c for c in n.children if c.type == "identifier"), None)
            return self.text(first) if first is not None else self.text(n)
        if t == "qualified_name":
            right = n.child_by_field_name("name")
            return self.simple_name(right) if right is not None else self.text(n)
        if t == "alias_qualified_name":
            return self.simple_name(n.child_by_field_name("name"))
        return self.text(n)

    @staticmethod
    def modifiers(n: Node, src_text) -> list[str]:
        mods = [src_text(c).lower() for c in n.children if c.type == "modifier"]
        for a, b, merged in (("protected", "internal", "protected internal"),
                             ("private", "protected", "private protected")):
            if a in mods and b in mods:
                ia, ib = mods.index(a), mods.index(b)
                first, second = min(ia, ib), max(ia, ib)
                del mods[second]
                mods[first] = merged
        return mods

    # -- node constructors ---------------------------------------------

    def other(self, n: Node) -> dict:
        return {"k": "other", "line": self.line(n), "text": self.text(n)}

    def unknown(self, n: Node) -> dict:
        return {"k": "unknown", "line": self.line(n), "text": self.text(n)}

    def name_node(self, ident: str, line: int) -> dict:
        return {"k": "name", "line": line, "id": ident}

    def lit(self, v, t: str, line: int) -> dict:
        return {"k": "lit", "line": line, "v": v, "t": t}

    # -- types and members ----------------------------------------------

    def collect_aliases(self, root: Node) -> None:
        stack = [root]
        while stack:
            cur = stack.pop()
            if cur.type == "using_directive":
                nm = cur.child_by_field_name("name")
                target = next((c for c in cur.named_children if c != nm and c.type != "comment"), None)
                if nm is not None and target is not None:
                    self.aliases[self.text(nm)] = self.text(target)
            elif cur.type in ("compilation_unit", "namespace_declaration", "file_scoped_namespace_declaration",
                              "declaration_list"):
                stack.extend(cur.children)

    def alias_chain(self, target: str, line: int) -> dict:
        """name / member chain for a dotted alias target."""
        parts = target.split(".")
        node = self.name_node(parts[0], line)
        for part in parts[1:]:
            node = {"k": "member", "line": line, "obj": node, "name": part}
        return node

    def unwrap(self, nodes, errors: bool = True) -> list[Node]:
        """`nodes` with `#if` / `#elif` / `#else` regions replaced by their contents, every branch
        (a security scan must see the code of the build it is not told about), and, for member /
        type lists, with ERROR nodes replaced by whatever declarations tree-sitter recovered."""
        out: list[Node] = []
        for c in nodes:
            if c.type in ("preproc_if", "preproc_elif", "preproc_else"):
                out.extend(self.unwrap(c.children, errors))
            elif errors and c.type == "ERROR":
                out.extend(self.unwrap(c.children, errors))
            else:
                out.append(c)
        return out

    def collect_types(self, root: Node) -> list[tuple[Node, str, str]]:
        found: list[tuple[Node, str, str]] = []

        def visit_list(nodes, ns: list[str], outer: list[str]) -> None:
            cur_ns = list(ns)
            for c in self.unwrap(nodes):
                t = c.type
                if t == "namespace_declaration":
                    nm = self.text(c.child_by_field_name("name"))
                    body = c.child_by_field_name("body")
                    visit_list(body.children if body is not None else [], cur_ns + [nm], outer)
                elif t == "file_scoped_namespace_declaration":
                    nm = self.text(c.child_by_field_name("name"))
                    cur_ns = cur_ns + [nm]
                    # Some grammar versions nest the declarations, others list them as siblings.
                    visit_list([k for k in c.children if k.type in _TYPE_NODES or k.type.endswith("namespace_declaration")],
                               cur_ns, outer)
                elif t in _TYPE_NODES:
                    ident = self.text(c.child_by_field_name("name"))
                    found.append((c, ".".join(ns_for(cur_ns)), ".".join(outer + [ident])))
                    body = c.child_by_field_name("body")
                    if body is not None and t != "enum_declaration":
                        visit_list(body.children, cur_ns, outer + [ident])

        def ns_for(parts: list[str]) -> list[str]:
            return [p for p in parts if p]

        visit_list(root.children, [], [])
        return found

    def type_record(self, node: Node, ns: str, name: str) -> dict:
        t = node.type
        kind = "struct" if t in _STRUCT_KINDS else "interface" if t == "interface_declaration" else "class"
        if t == "record_declaration" and any(c.type == "struct" for c in node.children):
            kind = "struct"
        body = node.child_by_field_name("body")
        members = [c for c in self.unwrap(body.children if body is not None else []) if c.is_named]
        bases: list[str] = []
        base_list = next((c for c in node.children if c.type == "base_list"), None)
        if base_list is not None:
            for b in base_list.named_children:
                if b.type == "primary_constructor_base_type":
                    b = next((k for k in b.named_children if k.type != "argument_list"), b)
                bases.append(self.simple_name(b))
        rec = {
            "name": name, "namespace": ns, "kind": kind,
            "modifiers": self.modifiers(node, self.text), "bases": bases,
            "attributes": self.attributes(node),
            "fields": self.fields(node, members), "properties": [], "methods": [],
        }
        for m in members:
            try:
                if m.type == "property_declaration":
                    rec["properties"].append(self.property(m))
                elif m.type in ("method_declaration", "constructor_declaration"):
                    rec["methods"].append(self.method(m))
            except Exception:  # noqa: BLE001 -- one bad member must not lose the file
                pass
        rec["line"] = self.decl_line(node)
        rec["end_line"] = self.end_line(node)
        return rec

    def fields(self, node: Node, members: list[Node]) -> list[dict]:
        out: list[dict] = []
        if node.type == "enum_declaration":
            enum_name = self.text(node.child_by_field_name("name"))
            for m in members:
                if m.type != "enum_member_declaration":
                    continue
                val = m.child_by_field_name("value")
                out.append({"name": self.text(m.child_by_field_name("name")), "type": enum_name,
                            "line": self.line(m), "init": self.expr(val) if val is not None else None,
                            "is_const": True})
            return out
        for m in members:
            if m.type != "field_declaration":
                continue
            try:
                is_const = any(self.text(c) == "const" for c in m.children if c.type == "modifier")
                decl = next((c for c in m.children if c.type == "variable_declaration"), None)
                if decl is None:
                    continue
                ty = self.text(decl.child_by_field_name("type"))
                for v in (c for c in decl.children if c.type == "variable_declarator"):
                    out.append({"name": self.text(v.child_by_field_name("name")), "type": ty, "line": self.line(v),
                                "init": self.declarator_init(v), "is_const": is_const})
            except Exception:  # noqa: BLE001
                continue
        return out

    def declarator_init(self, v: Node) -> dict | None:
        """Initializer Expr of a variable_declarator (the node after `=`), else None."""
        seen_eq = False
        for c in v.children:
            if c.type == "=":
                seen_eq = True
            elif seen_eq and self.is_expr(c) and c.type != "comment":
                return self.expr(c)
        return None

    def property(self, p: Node) -> dict:
        rec: dict = {"name": self.text(p.child_by_field_name("name")), "type": self.text(p.child_by_field_name("type")),
                     "attributes": self.attributes(p)}
        value = p.child_by_field_name("value")
        accessors = p.child_by_field_name("accessors")
        if value is not None and value.type == "arrow_expression_clause":
            # "=> expr" lowers as get: [return expr].
            e = self.arrow_expr(value)
            rec["get"] = [self.return_stmt(e, self.line(e) if e is not None else self.line(value))]
        elif accessors is not None:
            for acc in (c for c in accessors.children if c.type == "accessor_declaration"):
                kw = self.text(acc.child_by_field_name("name")).lower()
                key = "get" if kw == "get" else "set" if kw in ("set", "init") else None
                if key is None:
                    continue
                body = acc.child_by_field_name("body")
                if body is None:
                    continue
                if body.type == "block":
                    rec[key] = self.seq(body)
                else:
                    e = self.arrow_expr(body)
                    if e is None:
                        rec[key] = []
                    elif key == "get":
                        rec[key] = [self.return_stmt(e, self.line(e))]
                    else:
                        rec[key] = [self.expr_stmt(e, self.line(e))]
        if value is not None and value.type != "arrow_expression_clause":
            rec["init"] = self.expr(value)
        rec["line"] = self.decl_line(p)
        return rec

    def arrow_expr(self, arrow: Node) -> Node | None:
        return next((c for c in self.named(arrow)), None)

    def method(self, m: Node) -> dict:
        is_ctor = m.type == "constructor_declaration"
        name_node = m.child_by_field_name("name")
        name = ".ctor" if is_ctor else self.text(name_node)
        rt = None if is_ctor else self.text(m.child_by_field_name("returns"))
        implements: list[str] = []
        eis = next((c for c in m.children if c.type == "explicit_interface_specifier"), None)
        if eis is not None and not is_ctor:
            nm = next((c for c in eis.named_children), None)
            implements = [f"{self.text(nm)}.{name}"]
        returns_value = not is_ctor and rt != "void"
        body_node = m.child_by_field_name("body")
        body: list[dict] = []
        try:
            ctor_init = next((c for c in m.children if c.type == "constructor_initializer"), None)
            if ctor_init is not None:
                # ": base(x)" / ": this(x)" runs first; model it as a call statement.
                ln = self.line(ctor_init)
                is_base = any(c.type == "base" for c in ctor_init.children)
                call = {"k": "call", "line": ln, "fn": self.name_node("base" if is_base else "this", ln)}
                call.update(self.args(next((c for c in ctor_init.children if c.type == "argument_list"), None)))
                body.append({"k": "expr", "line": ln, "expr": call})
            if body_node is not None and body_node.type == "block":
                body.extend(self.seq(body_node))
            elif body_node is not None and body_node.type == "arrow_expression_clause":
                e = self.arrow_expr(body_node)
                if e is not None:
                    body.append(self.return_stmt(e, self.line(e)) if returns_value else self.expr_stmt(e, self.line(e)))
        except Exception:  # noqa: BLE001
            body = [self.other(body_node if body_node is not None else m)]
        return {
            "name": name, "modifiers": self.modifiers(m, self.text), "return_type": rt,
            "params": self.params(m.child_by_field_name("parameters")),
            "attributes": self.attributes(m), "handles": [], "implements": implements,
            "body": body, "line": self.decl_line(m), "end_line": self.end_line(m),
        }

    def params(self, plist: Node | None) -> list[dict]:
        out: list[dict] = []
        if plist is None:
            return out
        kids = list(plist.children)
        i = 0
        while i < len(kids):
            c = kids[i]
            if c.type == "parameter":
                out.append(self.parameter(c))
            elif c.type == "params":
                # The grammar emits `params T[] name` as loose tokens of the list.
                rest = [k for k in kids[i + 1:i + 3] if k.is_named]
                if len(rest) == 2:
                    out.append({"name": self.text(rest[1]), "type": self.text(rest[0]), "attributes": [],
                                "modifiers": ["params"]})
                    i += 2
            i += 1
        return out

    def parameter(self, p: Node) -> dict:
        ty = p.child_by_field_name("type")
        rec = {"name": self.text(p.child_by_field_name("name")), "type": self.text(ty) if ty is not None else None,
               "attributes": self.attributes(p)}
        mods = [self.text(c).lower() for c in p.children if c.type in ("modifier", "params", "this", "ref", "out", "in")]
        if mods:
            rec["modifiers"] = mods
        return rec

    def attributes(self, node: Node) -> list[dict]:
        out: list[dict] = []
        for lst in (c for c in node.children if c.type == "attribute_list"):
            for a in (c for c in lst.children if c.type == "attribute"):
                try:
                    out.append(self.attribute(a))
                except Exception:  # noqa: BLE001
                    continue
        return out

    def attribute(self, a: Node) -> dict:
        nm = self.simple_name(a.child_by_field_name("name"))
        if len(nm) > len("Attribute") and nm.endswith("Attribute"):
            nm = nm[: -len("Attribute")]
        args: list[dict] = []
        named: dict = {}
        alist = next((c for c in a.children if c.type == "attribute_argument_list"), None)
        for arg in (alist.children if alist is not None else []):
            if arg.type != "attribute_argument":
                continue
            key_node = arg.child_by_field_name("name")
            value = next((c for c in reversed(self.kids(arg)) if c != key_node and c.type != "comment"), None)
            e = self.expr(value) if value is not None else None
            if key_node is None:
                args.append(e)
            else:
                named[self.text(key_node)] = e
        return {"name": nm, "args": args, "named": named, "line": self.line(a)}

    # -- statements -----------------------------------------------------

    def seq(self, block: Node | list[Node], start: int = 0) -> list[dict]:
        """Statement list of a block (or of a node list). `using var x = ...;`
        wraps the rest of the enclosing list as the using body."""
        stmts = self.statements_of(block)
        out: list[dict] = []
        for i in range(start, len(stmts)):
            s = stmts[i]
            if s.type == "local_declaration_statement" and any(c.type == "using" for c in s.children):
                rest = stmts[i + 1:]
                if rest and self.depth >= MAX_DEPTH:
                    body = [{"k": "other", "line": self.line(rest[0]),
                             "text": self.src[rest[0].start_byte:rest[-1].end_byte].decode("utf-8", errors="replace")}]
                elif rest:
                    self.depth += 1
                    try:
                        body = self.seq(rest)
                    finally:
                        self.depth -= 1
                else:
                    body = []
                out.append({"k": "using", "line": self.line(s), "resource": self.locals_of(s), "body": body})
                return out
            out.extend(self.stmt(s))
        return out

    def statements_of(self, block) -> list[Node]:
        kids = self.unwrap(block if isinstance(block, list) else block.children, errors=False)
        return [c for c in kids if c.is_named and c.type != "comment"
                and (c.type.endswith("_statement") or c.type in ("block", "ERROR"))]

    def as_list(self, s: Node) -> list[Node]:
        return self.statements_of(s) if s.type == "block" else [s]

    def nested(self, node: Node, fn) -> list[dict]:
        """Lowered body of a nested statement, or one other node past the depth cap."""
        if self.depth >= MAX_DEPTH:
            return [self.other(node)]
        self.depth += 1
        try:
            return fn()
        finally:
            self.depth -= 1

    def body(self, s: Node | None) -> list[dict]:
        if s is None:
            return []
        return self.nested(s, lambda: self.seq(self.as_list(s)))

    def stmt(self, s: Node) -> list[dict]:
        """Lowered form of one statement: a list, because wrappers inline several."""
        try:
            return self._stmt(s)
        except RecursionError:
            return [self.other(s)]
        except Exception:  # noqa: BLE001 -- unknown shape: conservative other node
            return [self.other(s)]

    def _stmt(self, s: Node) -> list[dict]:
        t = s.type
        line = self.line(s)
        f = s.child_by_field_name
        if t == "block":
            return self.seq(s)
        if t == "local_declaration_statement":
            return self.locals_of(s)
        if t == "expression_statement":
            e = next((c for c in self.named(s)), None)
            return [self.expr_stmt(e, line)] if e is not None else [self.other(s)]
        if t == "return_statement":
            e = next((c for c in self.named(s)), None)
            return [self.return_stmt(e, line)]
        if t == "yield_statement":
            if any(c.type == "return" for c in s.children):
                e = next((c for c in self.named(s)), None)
                return [self.return_stmt(e, line)]
            return [self.other(s)]
        if t == "throw_statement":
            e = next((c for c in self.named(s)), None)
            return [{"k": "throw", "line": line, "value": self.expr(e) if e is not None else None}]
        if t == "if_statement":
            alt = f("alternative")
            return [{"k": "if", "line": line, "cond": self.expr(f("condition")),
                     "then": self.body(f("consequence")), "else": self.body(alt)}]
        if t == "foreach_statement":
            left, right = f("left"), f("right")
            if left is not None and left.type == "identifier":
                header = [self.name_node(self.text(left), self.line(left)), self.expr(right)]
            else:
                lhs = None
                if left is not None:
                    # Deconstruction target: Roslyn's text carries the declared type (`var (k, v)`).
                    ty = f("type")
                    lhs = ({"k": "unknown", "line": self.line(left), "text": f"{self.text(ty)} {self.text(left)}"}
                           if ty is not None and left.type != "identifier" else self.expr(left))
                header = [lhs, self.expr(right)]
            return [{"k": "loop", "line": line, "header": header, "body": self.body(f("body"))}]
        if t == "for_statement":
            header: list = []
            for c in s.children_by_field_name("initializer"):
                if c.type == "variable_declaration":
                    for v in (k for k in c.children if k.type == "variable_declarator"):
                        init = self.declarator_init(v)
                        if init is not None:
                            header.append(init)
                else:
                    header.append(self.expr(c))
            cond = f("condition")
            if cond is not None:
                header.append(self.expr(cond))
            for c in s.children_by_field_name("update"):
                header.append(self.expr(c))
            return [{"k": "loop", "line": line, "header": header, "body": self.body(f("body"))}]
        if t in ("while_statement", "do_statement"):
            return [{"k": "loop", "line": line, "header": [self.expr(f("condition"))], "body": self.body(f("body"))}]
        if t == "try_statement":
            catches = []
            for c in (k for k in s.children if k.type == "catch_clause"):
                decl = next((k for k in c.children if k.type == "catch_declaration"), None)
                ty = nm = None
                if decl is not None:
                    ty = self.text(decl.child_by_field_name("type"))
                    nn = decl.child_by_field_name("name")
                    nm = self.text(nn) if nn is not None else None
                catches.append({"type": ty, "name": nm, "body": self.body(c.child_by_field_name("body"))})
            fin = next((k for k in s.children if k.type == "finally_clause"), None)
            fin_block = next((k for k in fin.children if k.type == "block"), None) if fin is not None else None
            return [{"k": "try", "line": line, "body": self.body(f("body")), "catches": catches,
                     "finally": self.body(fin_block)}]
        if t == "using_statement":
            res: list[dict] = []
            decl = next((c for c in s.children if c.type == "variable_declaration"), None)
            if decl is not None:
                res = self.declaration_locals(decl)
            else:
                e = next((c for c in s.children if self.is_expr(c) and c != f("body") and c.type != "comment"), None)
                if e is not None:
                    res = [self.expr_stmt(e, self.line(e))]
            return [{"k": "using", "line": line, "resource": res, "body": self.body(f("body"))}]
        if t == "lock_statement":
            body = next((c for c in reversed(s.children) if c.is_named), None)
            return self.seq(self.as_list(body)) if body is not None else []
        if t in ("checked_statement", "unsafe_statement"):
            blk = next((c for c in s.children if c.type == "block"), None)
            return self.seq(blk) if blk is not None else []
        if t == "fixed_statement":
            decl = next((c for c in s.children if c.type == "variable_declaration"), None)
            out = self.declaration_locals(decl) if decl is not None else []
            body = f("body") or next((c for c in reversed(s.children) if c.is_named), None)
            if body is not None and body != decl:
                out += self.seq(self.as_list(body))
            return out
        if t == "labeled_statement":
            inner = next((c for c in s.named_children if c.type.endswith("_statement") or c.type == "block"), None)
            return self.stmt(inner) if inner is not None else [self.other(s)]
        if t == "switch_statement":
            value = f("value")
            sbody = f("body")
            out = []
            for sec in (c for c in self.unwrap(sbody.children if sbody is not None else [], errors=False)
                        if c.type == "switch_section"):
                stmts = self.statements_of(sec)
                out.append({"k": "if", "line": self.line(sec), "cond": self.expr(value),
                            "then": self.nested(sec, lambda stmts=stmts: self.seq(stmts)), "else": []})
            return out
        if t == "local_function_statement":
            params = self.lambda_params(f("parameters"))
            body_node = f("body")
            lam = {"k": "lambda", "line": line}
            if params:
                lam["params"] = params
            lam["body"] = self.lambda_body(body_node, s)
            ty = f("type") or f("returns")
            return [{"k": "local", "line": line, "name": self.text(f("name")), "type": self.text(ty),
                     "init": lam}]
        return [self.other(s)]

    def locals_of(self, s: Node) -> list[dict]:
        decl = next((c for c in s.children if c.type == "variable_declaration"), None)
        return self.declaration_locals(decl) if decl is not None else [self.other(s)]

    def declaration_locals(self, d: Node) -> list[dict]:
        ty = self.text(d.child_by_field_name("type"))
        out: list[dict] = []
        for v in (c for c in d.children if c.type == "variable_declarator"):
            name_node = v.child_by_field_name("name")
            if name_node is None:
                # `var (a, b) = e;` is a deconstructing assignment, not a declaration.
                init = self.declarator_init(v)
                target = {"k": "unknown", "line": self.line(v), "text": f"{ty} " + self.text(next(
                    (c for c in v.children if c.type != "="), v))}
                out.append({"k": "assign", "line": self.line(v), "target": target, "op": "=", "value": init})
                continue
            out.append({"k": "local", "line": self.line(v), "name": self.text(name_node), "type": ty,
                        "init": self.declarator_init(v)})
        return out

    def return_stmt(self, value: Node | None, line: int) -> dict:
        return {"k": "return", "line": line, "value": self.expr(value) if value is not None else None}

    def expr_stmt(self, e: Node, line: int) -> dict:
        """Expression used as a statement: assignments become assign, the rest expr."""
        if e.type == "assignment_expression":
            op = self.text(e.child_by_field_name("operator"))
            left, right = e.child_by_field_name("left"), e.child_by_field_name("right")
            node = {"k": "assign", "line": line, "target": self.expr(left)}
            if op in ("=", "+=", "-="):
                node["op"] = op
                node["value"] = self.expr(right)
            else:
                # x *= y  ->  x = (x * y): keeps "op" within the schema's closed set.
                node["op"] = "="
                node["value"] = {"k": "bin", "line": self.line(e), "op": op.rstrip("="),
                                 "l": self.expr(left), "r": self.expr(right)}
            return node
        return {"k": "expr", "line": line, "expr": self.expr(e)}

    # -- expressions ----------------------------------------------------

    def expr(self, e: Node | None) -> dict | None:
        if e is None:
            return None
        if self.depth >= MAX_DEPTH:
            return self.unknown(e)
        self.depth += 1
        try:
            return self._expr(e)
        except Exception:  # noqa: BLE001 -- includes RecursionError
            return self.unknown(e)
        finally:
            self.depth -= 1

    def _expr(self, e: Node) -> dict:
        t = e.type
        line = self.line(e)
        f = e.child_by_field_name
        # Transparent wrappers: the value is the inner expression's.
        if t in ("parenthesized_expression", "await_expression", "checked_expression", "ref_expression"):
            inner = next((c for c in self.named(e)), None)
            return self._expr(inner) if inner is not None else self.unknown(e)
        if t == "postfix_unary_expression":
            op = self.text(e.children[-1])
            operand = e.children[0]
            if op == "!":
                return self._expr(operand)
            return self.unary(op, operand, line, e)
        if t == "prefix_unary_expression":
            op = self.text(e.children[0])
            operand = e.children[-1]
            if op == "-" and operand.type in ("integer_literal", "real_literal"):
                v = _number(self.text(operand))
                if v is not None:
                    return self.lit(-v, "number", line)
            return self.unary(op, operand, line, e)
        if t in ("boolean_literal", "null_literal", "character_literal", "integer_literal", "real_literal",
                 "string_literal", "verbatim_string_literal", "raw_string_literal"):
            return self.literal(e, line)
        if t == "identifier":
            ident = self.text(e)
            if ident in self.aliases and re.fullmatch(r"[\w.]+", self.aliases[ident]):
                return self.alias_chain(self.aliases[ident], line)
            return self.name_node(ident, line)
        if t == "generic_name":
            return self.name_node(self.simple_name(e), line)
        if t == "predefined_type":
            return self.name_node(self.text(e), line)
        if t in ("this_expression", "this"):
            return self.name_node("this", line)
        if t in ("base_expression", "base"):
            return self.name_node("base", line)
        if t == "qualified_name":
            return self.member(f("qualifier"), self.simple_name(f("name")), line)
        if t == "member_access_expression":
            return self.member(f("expression"), self.simple_name(f("name")), line)
        if t == "conditional_access_expression":
            cond = f("condition")
            binding = next((c for c in reversed(e.children) if c != cond and self.is_expr(c)), None)
            if cond is None or binding is None:
                return self.unknown(e)
            self.receivers.append(cond)
            try:
                return self._expr(binding)
            finally:
                self.receivers.pop()
        if t == "member_binding_expression" and self.receivers:
            recv = self.receivers.pop()
            try:
                return self.member(recv, self.simple_name(f("name")), line)
            finally:
                self.receivers.append(recv)
        if t == "element_binding_expression" and self.receivers:
            recv = self.receivers.pop()
            try:
                return self.index(recv, e, line)
            finally:
                self.receivers.append(recv)
        if t == "invocation_expression":
            call = {"k": "call", "line": line, "fn": self.expr(f("function"))}
            call.update(self.args(f("arguments")))
            return call
        if t == "element_access_expression":
            return self.index(f("expression"), f("subscript"), line)
        if t == "object_creation_expression":
            ty = self.text(f("type"))
            if ty in self.aliases:
                ty = self.aliases[ty]
            return self.new(ty, f("arguments"), f("initializer"), line)
        if t == "implicit_object_creation_expression":
            args = next((c for c in e.children if c.type == "argument_list"), None)
            init = next((c for c in e.children if c.type == "initializer_expression"), None)
            return self.new(None, args, init, line)
        if t == "array_creation_expression":
            init = next((c for c in e.children if c.type == "initializer_expression"), None)
            return self.new(self.text(f("type")), None, init, line)
        if t == "implicit_array_creation_expression":
            init = next((c for c in e.children if c.type == "initializer_expression"), None)
            return self.new(None, None, init, line)
        if t == "initializer_expression":
            return self.new(None, None, e, line)
        if t == "anonymous_object_creation_expression":
            return self.anonymous_object(e, line)
        if t == "as_expression":
            return {"k": "cast", "line": line, "type": self.text(f("right")), "e": self.expr(f("left"))}
        if t == "cast_expression":
            return {"k": "cast", "line": line, "type": self.text(f("type")), "e": self.expr(f("value"))}
        if t == "declaration_expression":
            # `a * b` in argument position parses as the declaration of `b` of pointer type `a*`;
            # only `out` / `ref` arguments declare, so anywhere else it is a multiplication.
            ty, nm = f("type"), f("name")
            par = e.parent
            if (ty is not None and ty.type == "pointer_type" and nm is not None and par is not None
                    and par.type == "argument" and not any(c.type in ("out", "ref", "in") for c in par.children)):
                return {"k": "bin", "line": line, "op": "*", "l": self.expr(ty.child_by_field_name("type")),
                        "r": self.expr(nm)}
            return self.unknown(e)
        if t == "is_pattern_expression":
            pat = f("pattern")
            inner = self.kids(pat)[0] if pat is not None and pat.type == "constant_pattern" and self.kids(pat) else None
            # `x is Type` is a binary `is` for Roslyn; `is null`, `is Type v`, `is not` stay unknown.
            if inner is not None and inner.type in ("identifier", "qualified_name", "member_access_expression",
                                                    "generic_name", "predefined_type"):
                return {"k": "bin", "line": line, "op": "is", "l": self.expr(f("expression")), "r": self.expr(inner)}
            return self.unknown(e)
        if t in ("binary_expression", "is_expression"):
            return {"k": "bin", "line": line, "op": self.text(f("operator")),
                    "l": self.expr(f("left")), "r": self.expr(f("right"))}
        if t == "interpolated_string_expression":
            return self.interpolated(e, line)
        if t == "conditional_expression":
            return {"k": "cond", "line": line, "c": self.expr(f("condition")),
                    "t": self.expr(f("consequence")), "f": self.expr(f("alternative"))}
        if t in ("lambda_expression", "anonymous_method_expression"):
            return self.lambda_expr(e, line)
        return self.unknown(e)

    def unary(self, op: str, operand: Node, line: int, whole: Node) -> dict:
        if op in ("!", "-", "~", "++", "--"):
            return {"k": "unary", "line": line, "op": op, "e": self.expr(operand)}
        return self.unknown(whole)

    def literal(self, e: Node, line: int) -> dict:
        t, txt = e.type, self.text(e)
        if t == "boolean_literal":
            return self.lit(txt == "true", "bool", line)
        if t == "null_literal":
            return self.lit(None, "null", line)
        if t == "string_literal":
            if txt.endswith(("u8", "U8")):       # UTF-8 literal: "abc"u8
                txt = txt[:-2]
            return self.lit(_unescape(txt[1:-1]) if txt.endswith('"') else txt, "string", line)
        if t == "verbatim_string_literal":
            return self.lit(txt[2:-1].replace('""', '"'), "string", line)
        if t == "raw_string_literal":
            content = next((c for c in e.children if c.type == "raw_string_content"), None)
            return self.lit(self.text(content) if content is not None else "", "string", line)
        if t == "character_literal":
            return self.lit(_unescape(txt[1:-1]), "char", line)
        v = _number(txt)
        return self.lit(v, "number", line) if v is not None else self.unknown(e)

    def member(self, obj: Node | None, name: str, line: int) -> dict:
        return {"k": "member", "line": line, "obj": self.expr(obj), "name": name}

    def index(self, obj: Node | None, sub: Node | None, line: int) -> dict:
        args = [self.expr(self.argument_expr(a)) for a in (sub.children if sub is not None else [])
                if a.type == "argument"]
        return {"k": "index", "line": line, "obj": self.expr(obj), "args": args}

    def argument_expr(self, a: Node) -> Node | None:
        name = a.child_by_field_name("name")
        return next((c for c in reversed(self.kids(a)) if c != name and c.type != "comment"), None)

    def args(self, alist: Node | None) -> dict:
        """Positional args to "args", name: args to "named"."""
        pos: list = []
        named: dict = {}
        for a in (alist.children if alist is not None else []):
            if a.type != "argument":
                continue
            key = a.child_by_field_name("name")
            e = self.expr(self.argument_expr(a))
            if key is None:
                pos.append(e)
            else:
                named[self.text(key)] = e
        return {"args": pos, "named": named}

    def new(self, ty: str | None, alist: Node | None, init: Node | None, line: int) -> dict:
        args = [self.expr(self.argument_expr(a)) for a in (alist.children if alist is not None else [])
                if a.type == "argument"]
        entries: list[dict] = []
        if init is not None:
            for c in self.kids(init):
                if c.type == "comment":
                    continue
                if c.type == "assignment_expression" and self.text(c.child_by_field_name("operator")) == "=":
                    left = c.child_by_field_name("left")
                    nm = self.text(left)
                    entries.append({"name": nm, "value": self.expr(c.child_by_field_name("right"))})
                else:
                    entries.append({"name": None, "value": self.expr(c)})
        return {"k": "new", "line": line, "type": ty, "args": args, "init": entries}

    def anonymous_object(self, e: Node, line: int) -> dict:
        entries: list[dict] = []
        kids = [c for c in e.children if self.is_expr(c) and c.type != "comment"]
        i = 0
        while i < len(kids):
            c = kids[i]
            # `Name = expr` appears as identifier, `=`, expr in the flat child list.
            nxt = e.children[e.children.index(c) + 1] if e.children.index(c) + 1 < len(e.children) else None
            if c.type == "identifier" and nxt is not None and nxt.type == "=" and i + 1 < len(kids):
                entries.append({"name": self.text(c), "value": self.expr(kids[i + 1])})
                i += 2
            else:
                inferred = self.text(c) if c.type == "identifier" else (
                    self.simple_name(c.child_by_field_name("name")) if c.type == "member_access_expression" else None)
                entries.append({"name": inferred, "value": self.expr(c)})
                i += 1
        return {"k": "new", "line": line, "type": None, "args": [], "init": entries}

    def interpolated(self, e: Node, line: int) -> dict:
        parts: list[dict] = []
        for c in e.children:
            if c.type in ("string_content", "escape_sequence", "interpolation_string_content"):
                txt = self.text(c)
                if c.type == "escape_sequence":
                    txt = _unescape(txt)
                else:
                    txt = txt.replace("{{", "{").replace("}}", "}")
                if parts and parts[-1].get("_text"):
                    # tree-sitter splits `a{{b}}` into several text tokens; Roslyn has one text part.
                    parts[-1]["v"] += txt
                else:
                    node = self.lit(txt, "string", self.line(c))
                    node["_text"] = True
                    parts.append(node)
            elif c.type == "interpolation":
                inner = next((k for k in self.kids(c) if k.type not in (
                    "interpolation_brace", "interpolation_alignment_clause", "interpolation_format_clause", "comment")), None)
                parts.append(self.expr(inner))
        for part in parts:
            if part is not None:
                part.pop("_text", None)
        return {"k": "interp", "line": line, "parts": parts}

    def lambda_params(self, plist: Node | None) -> list[str]:
        if plist is None:
            return []
        if plist.type in ("identifier", "implicit_parameter"):
            return [self.text(plist)]
        if plist.type == "parameter":
            return [self.text(plist.child_by_field_name("name"))]
        return [self.text(p.child_by_field_name("name")) for p in plist.children if p.type == "parameter"]

    def lambda_expr(self, e: Node, line: int) -> dict:
        f = e.child_by_field_name
        plist = f("parameters")
        if plist is None:
            plist = next((c for c in e.children if c.type in (
                "parameter_list", "identifier", "parameter", "implicit_parameter")), None)
        node: dict = {"k": "lambda", "line": line}
        names = self.lambda_params(plist)
        if names:
            node["params"] = names
        body = f("body") or next((c for c in e.children if c.type == "block"), None)
        node["body"] = self.lambda_body(body, e)
        return node

    def lambda_body(self, body: Node | None, fallback: Node):
        """Stmt list for a block (or an assignment expression), else a single Expr."""
        if body is not None and body.type == "arrow_expression_clause":
            body = self.arrow_expr(body)
        if body is not None and body.type != "block" and body.type != "assignment_expression":
            return self.expr(body)
        return self.nested(fallback, lambda: self.seq(body) if body is not None and body.type == "block"
                           else ([self.expr_stmt(body, self.line(body))] if body is not None else []))


def _count_errors(root: Node) -> int:
    n = 0
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur.type == "ERROR" or cur.is_missing:
            n += 1
        if cur.has_error:
            stack.extend(cur.children)
    return n


_DIRECTIVE = re.compile(rb"^[ \t]*#[ \t]*(if|elif|else|endif)\b", re.I | re.M)


def _variants(src: bytes) -> list[bytes]:
    """Sources with the conditional-compilation directives neutralised, one per branch index:
    variant k keeps the k-th branch of every `#if` group (the last one when a group has fewer) and
    blanks the directive lines and the other branches with spaces, newlines kept, so every line
    number stays that of the original. They make valid code out of regions tree-sitter cannot
    parse (a directive splitting a signature, a namespace opened in one branch)."""
    lines = src.split(b"\n")
    kind: list[str | None] = []
    for ln in lines:
        m = _DIRECTIVE.match(ln)
        kind.append(m.group(1).decode().lower() if m else None)
    stack: list[list[int]] = []          # [group id, branch index] of the open `#if` groups
    groups: dict[int, int] = {}          # group id -> branch count
    membership: list[tuple[tuple[int, int], ...]] = []
    nxt = 0
    for k in kind:
        if k == "if":
            stack.append([nxt, 0])
            groups[nxt] = 1
            nxt += 1
            membership.append(())
        elif k in ("elif", "else") and stack:
            stack[-1][1] += 1
            groups[stack[-1][0]] = max(groups[stack[-1][0]], stack[-1][1] + 1)
            membership.append(())
        elif k == "endif" and stack:
            stack.pop()
            membership.append(())
        else:
            membership.append(tuple((g, b) for g, b in stack))
    count = min(max(groups.values(), default=0), 4)
    out: list[bytes] = []
    for v in range(count):
        res = []
        for ln, k, mem in zip(lines, kind, membership):
            keep = k is None and all(b == min(v, groups[g] - 1) for g, b in mem)
            res.append(ln if keep else b" " * len(ln.rstrip(b"\r")))
        out.append(b"\n".join(res))
    return out


_NOISE = re.compile(rb'//[^\n]*|/\*.*?\*/|@"(?:[^"]|"")*"|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


def _closed(src: bytes) -> bytes | None:
    """`src` with the missing closing braces appended on the last line (line numbers unchanged), or
    None when the braces balance or are over-closed. Recovers the types of a file cut short."""
    code = _NOISE.sub(b"", src)
    missing = code.count(b"{") - code.count(b"}")
    return src + b"}" * missing if 0 < missing <= 50 else None


def _method_key(m: dict) -> tuple:
    return (m["name"], tuple(p.get("type") for p in m.get("params") or []))


def _same(x: dict) -> str:
    return json.dumps(x, sort_keys=True, default=str)


def _merge(base: list[dict], extra: list[dict]) -> None:
    """Adds to `base` the types and members only `extra` (another preprocessor variant) has. A member
    counts as already present only when it is identical (body, attributes and lines included): two `#if`
    branches may declare the same signature with different bodies, and both must be scanned."""
    by_name = {t["name"]: t for t in base}
    for t in extra:
        have = by_name.get(t["name"])
        if have is None:
            base.append(t)
            by_name[t["name"]] = t
            continue
        for kind in ("methods", "properties", "fields"):
            seen = {_same(x) for x in have[kind]}
            sigs = {_method_key(x) for x in have[kind]} if kind == "methods" else set()
            # A body-less fragment of a signature already present (a broken parse) adds nothing to scan.
            have[kind] += [x for x in t[kind] if _same(x) not in seen
                           and not (kind == "methods" and not x.get("body") and _method_key(x) in sigs)]


def _lower_source(src: bytes) -> tuple[list[dict], int]:
    tree = _PARSER.parse(src)
    low = _Lowering(src)
    low.collect_aliases(tree.root_node)
    types = []
    for node, ns, name in low.collect_types(tree.root_node):
        try:
            types.append(low.type_record(node, ns, name))
        except Exception:  # noqa: BLE001 -- keep the other types of the file
            continue
    return types, _count_errors(tree.root_node)


def lower_file(path: Path, rel: str, project: str) -> dict:
    """IR record of one C# file: {path, language, project, parse_errors, types}.
    Never raises; a file that cannot be read or lowered returns {"error": ...}.

    Conditional compilation: every `#if` branch is lowered (over-lowering is the safe side). When the
    plain parse has errors, the file is parsed again once per branch
    index with the directives neutralised (_variants); the variant with the fewest errors is the base
    and members only other variants have are merged in, so no branch's sinks are dropped."""
    try:
        src = Path(path).read_bytes()
    except OSError as ex:
        return {"path": rel, "error": f"unreadable: {ex}"}
    if src.startswith(b"\xef\xbb\xbf"):
        src = src[3:]
    try:
        if sys.getrecursionlimit() < 10000:
            sys.setrecursionlimit(10000)
        types, errors = _lower_source(src)
        if errors:
            original = errors
            results = [(errors, 0, types)]
            extra = [(v, False) for v in (_variants(src) if _DIRECTIVE.search(src) else [])]
            closed = _closed(src)
            if closed is not None:
                extra.append((closed, True))
            for i, (v, is_closed) in enumerate(extra, 1):
                try:
                    t, e = _lower_source(v)
                except Exception:  # noqa: BLE001
                    continue
                results.append((e, i, t, is_closed))
            results.sort(key=lambda r: (r[0], r[1]))
            best = results[0]
            types, errors = best[2], best[0]
            # Braces added to recover the file do not make it error-free: keep the original count.
            if len(best) > 3 and best[3]:
                errors = original
            for r in results[1:]:
                _merge(types, r[2])
        return {"path": rel, "language": "cs", "project": project, "parse_errors": errors, "types": types}
    except Exception as ex:  # noqa: BLE001
        return {"path": rel, "error": f"tree-sitter lowering failed: {type(ex).__name__}: {ex}"}
