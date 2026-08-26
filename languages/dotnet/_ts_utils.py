"""Tiny tree-sitter helpers for the ASP.NET analyzer -- same trivial
node-text/walk helpers every other tree-sitter-based analyzer in this repo
duplicates locally (matches existing convention: no shared JS/Go util
module either)."""
from __future__ import annotations

import tree_sitter_c_sharp as tscs
from tree_sitter import Language, Node, Parser

CSHARP_LANGUAGE = Language(tscs.language())


def parser() -> Parser:
    return Parser(CSHARP_LANGUAGE)


def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def string_literal_value(node: Node, src: bytes) -> str | None:
    """C# string literals are a single leaf token including the quotes
    (unlike Python/JS's nested fragment children) -- just strip them."""
    if node.type != "string_literal":
        return None
    return node_text(node, src).strip('"')


def iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from iter_nodes(child)
