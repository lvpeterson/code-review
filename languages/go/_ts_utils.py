"""Tiny tree-sitter helpers shared by the Go analyzers -- same trivial
node-text/walk helpers every other tree-sitter-based analyzer in this repo
duplicates locally rather than sharing (matches existing convention: no
shared JS util module either)."""
from __future__ import annotations

import tree_sitter_go as tsgo
from tree_sitter import Language, Node, Parser

GO_LANGUAGE = Language(tsgo.language())


def parser() -> Parser:
    return Parser(GO_LANGUAGE)


def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def string_value(node: Node, src: bytes) -> str | None:
    """Interpreted string literal's actual text content, quotes stripped."""
    if node.type != "interpreted_string_literal":
        return None
    fragment = next((c for c in node.named_children if c.type == "interpreted_string_literal_content"), None)
    return node_text(fragment, src) if fragment else ""


def iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from iter_nodes(child)
