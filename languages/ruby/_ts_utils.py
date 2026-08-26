"""Tiny tree-sitter helpers shared by the Ruby analyzers -- same trivial
node-text/walk helpers every other tree-sitter-based analyzer in this repo
duplicates locally (matches existing convention: no shared JS/Go/C# util
module either)."""
from __future__ import annotations

import tree_sitter_ruby as tsrb
from tree_sitter import Language, Node, Parser

RUBY_LANGUAGE = Language(tsrb.language())


def parser() -> Parser:
    return Parser(RUBY_LANGUAGE)


def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def string_or_symbol_value(node: Node, src: bytes) -> str | None:
    """The literal text of a Ruby `'string'`/`"string"` or `:symbol`."""
    if node.type == "string":
        fragment = next((c for c in node.named_children if c.type == "string_content"), None)
        return node_text(fragment, src) if fragment else ""
    if node.type == "simple_symbol":
        return node_text(node, src).lstrip(":")
    return None


def iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from iter_nodes(child)
