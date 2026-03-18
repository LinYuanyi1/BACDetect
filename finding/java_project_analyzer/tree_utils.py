from __future__ import annotations

from collections.abc import Iterable

from tree_sitter import Node


TYPE_NODE_CANDIDATES = {
    "array_type",
    "boolean_type",
    "floating_point_type",
    "generic_type",
    "integral_type",
    "scoped_type_identifier",
    "type_identifier",
    "void_type",
}
ANNOTATION_NODE_TYPES = {
    "annotation",
    "marker_annotation",
    "normal_annotation",
}


def text_of(node: Node, source: bytes) -> str:
    """Return the text content of a node
    
    example: text_of(node, source) -> "MyClass"
    """
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def first_child(node: Node, node_type: str) -> Node | None:
    for child in node.children:
        if child.type == node_type:
            return child
    return None


def first_child_of_types(node: Node, node_types: set[str]) -> Node | None:
    for child in node.children:
        if child.type in node_types or child.type.endswith("_type"):
            return child
    return None


def walk_descendants(node: Node) -> Iterable[Node]:
    for child in node.children:
        yield child
        yield from walk_descendants(child)
