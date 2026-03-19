from __future__ import annotations

from collections.abc import Iterable

from tree_sitter import Node


# Small helpers shared by the parser and auth detector. Keeping these in one
# place avoids repeating the same Tree-sitter traversal patterns everywhere.

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
# A narrower subset used when we only care about references that may hint at
# security-related framework types inside method bodies.
TYPE_REFERENCE_NODE_TYPES = {
    "array_type",
    "generic_type",
    "scoped_type_identifier",
    "type_identifier",
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
    # Some Java grammar nodes use specific names such as "type_identifier",
    # while others end in "_type"; support both with one helper.
    for child in node.children:
        if child.type in node_types or child.type.endswith("_type"):
            return child
    return None


def walk_descendants(node: Node) -> Iterable[Node]:
    # A simple recursive walk is enough for the current analysis volume and is
    # easier to reason about than managing an explicit traversal stack.
    for child in node.children:
        yield child
        yield from walk_descendants(child)


def unique_texts(values: Iterable[str]) -> list[str]:
    """Preserve the first occurrence order while removing duplicates."""
    ordered_values: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered_values.append(value)
    return ordered_values
