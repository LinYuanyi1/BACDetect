from __future__ import annotations

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser


JAVA_SUFFIX = ".java"
DEFAULT_SECURITY_ANNOTATIONS = {
    "PreAuthorize",
    "PostAuthorize",
    "Secured",
    "RolesAllowed",
    "PermitAll",
    "DenyAll",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
}

_JAVA_LANGUAGE = Language(tsjava.language())


def create_java_parser() -> Parser:
    """Create a parser configured for the Java grammar."""
    return Parser(_JAVA_LANGUAGE)
