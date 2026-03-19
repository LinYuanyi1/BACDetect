from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from tree_sitter import Node

from java_project_analyzer.constants import JAVA_SUFFIX, create_java_parser
from java_project_analyzer.models import (
    ClassInfo,
    FieldInfo,
    FileAnalysis,
    MethodCallInfo,
    MethodInfo,
)
from java_project_analyzer.tree_utils import (
    ANNOTATION_NODE_TYPES,
    TYPE_NODE_CANDIDATES,
    TYPE_REFERENCE_NODE_TYPES,
    first_child,
    first_child_of_types,
    text_of,
    unique_texts,
    walk_descendants,
)


class JavaProjectAnalyzer:
    """Analyze Java source files and extract facts useful for security analysis."""

    def __init__(self) -> None:
        self._parser = create_java_parser()

    def analyze_project(self, project_root: Path) -> list[FileAnalysis]:
        return [self.analyze_file(path) for path in self.iter_java_files(project_root)]

    def analyze_file(self, java_file: Path) -> FileAnalysis:
        """Analyze a single Java file and extract the structure tree we care about."""
        source = java_file.read_bytes()
        tree = self._parser.parse(source)
        root = tree.root_node

        package_name: str | None = None
        imports: list[str] = []
        classes: list[ClassInfo] = []

        # Only the top-level declarations are needed here; deeper traversal
        # happens inside the class and method parsers below.
        for child in root.children:
            if child.type == "package_declaration":
                package_name = self._extract_package_name(child, source)
            elif child.type == "import_declaration":
                import_name = self._extract_import_name(child, source)
                if import_name is not None:
                    imports.append(import_name)
            elif child.type in {"class_declaration", "interface_declaration", "enum_declaration"}:
                classes.append(self._parse_class(child, source))

        return FileAnalysis(
            path=str(java_file),
            package=package_name,
            imports=imports,
            classes=classes,
        )

    def iter_java_files(self, project_root: Path) -> Iterable[Path]:
        for path in sorted(project_root.rglob(f"*{JAVA_SUFFIX}")):
            if path.is_file():
                yield path

    def _extract_package_name(self, package_node: Node, source: bytes) -> str | None:
        name_node = package_node.child_by_field_name("name")
        if name_node is None:
            name_node = self._find_named_child(package_node, {"identifier", "scoped_identifier"})
        return text_of(name_node, source) if name_node is not None else None

    def _extract_import_name(self, import_node: Node, source: bytes) -> str | None:
        name_node = import_node.child_by_field_name("name")
        if name_node is None:
            name_node = self._find_named_child(
                import_node,
                {"identifier", "scoped_identifier", "asterisk"},
            )
        return text_of(name_node, source) if name_node is not None else None

    def _parse_class(self, class_node: Node, source: bytes) -> ClassInfo:
        modifiers_node = first_child(class_node, "modifiers")
        name_node = class_node.child_by_field_name("name") or first_child(class_node, "identifier")
        body_node = first_child(class_node, "class_body")

        # The analyzer keeps only structure that is later useful for auth rules:
        # class hierarchy, fields, and method-level facts.
        fields: list[FieldInfo] = []
        methods: list[MethodInfo] = []
        if body_node is not None:
            for child in body_node.children:
                if child.type == "field_declaration":
                    fields.append(self._parse_field(child, source))
                elif child.type == "method_declaration":
                    methods.append(self._parse_method(child, source))

        return ClassInfo(
            name=text_of(name_node, source) if name_node is not None else "<unknown>",
            line=class_node.start_point[0] + 1,
            kind=class_node.type.replace("_declaration", ""),
            modifiers=self._extract_modifiers(modifiers_node, source),
            annotations=self._extract_annotations(modifiers_node, source),
            extends_types=self._extract_inherited_types(class_node, source),
            implements_types=self._extract_implemented_types(class_node, source),
            fields=fields,
            methods=methods,
        )

    def _parse_field(self, field_node: Node, source: bytes) -> FieldInfo:
        modifiers_node = first_child(field_node, "modifiers")
        type_node = first_child(field_node, "type_identifier") or first_child_of_types(
            field_node,
            TYPE_NODE_CANDIDATES,
        )

        declarator = first_child(field_node, "variable_declarator")
        name_node = declarator.child_by_field_name("name") if declarator is not None else None
        if name_node is None and declarator is not None:
            name_node = first_child(declarator, "identifier")

        return FieldInfo(
            name=text_of(name_node, source) if name_node is not None else "<unknown>",
            line=field_node.start_point[0] + 1,
            field_type=text_of(type_node, source) if type_node is not None else "<unknown>",
            modifiers=self._extract_modifiers(modifiers_node, source),
            annotations=self._extract_annotations(modifiers_node, source),
        )

    def _parse_method(self, method_node: Node, source: bytes) -> MethodInfo:
        modifiers_node = first_child(method_node, "modifiers")
        return_type_node = method_node.child_by_field_name("type") or first_child_of_types(
            method_node,
            TYPE_NODE_CANDIDATES,
        )
        name_node = method_node.child_by_field_name("name") or first_child(method_node, "identifier")
        params_node = first_child(method_node, "formal_parameters")
        throws_node = first_child(method_node, "throws")
        body_node = first_child(method_node, "block")

        # Besides the visible signature, we also persist lightweight body facts
        # that later drive auth heuristics: calls, exceptions, literals, types.
        return MethodInfo(
            name=text_of(name_node, source) if name_node is not None else "<unknown>",
            line=method_node.start_point[0] + 1,
            return_type=text_of(return_type_node, source)
            if return_type_node is not None
            else "<unknown>",
            parameters=self._extract_parameters(params_node, source),
            modifiers=self._extract_modifiers(modifiers_node, source),
            annotations=self._extract_annotations(modifiers_node, source),
            calls=self._extract_method_calls(body_node, source),
            thrown_exceptions=self._extract_method_exceptions(throws_node, body_node, source),
            string_literals=self._extract_string_literals(body_node, source),
            type_references=self._extract_type_references(body_node, source),
        )

    def _extract_parameters(self, params_node: Node | None, source: bytes) -> list[str]:
        if params_node is None:
            return []

        parameters: list[str] = []
        for child in params_node.children:
            if child.type == "formal_parameter":
                parameters.append(text_of(child, source))
        return parameters

    def _extract_method_calls(self, block_node: Node | None, source: bytes) -> list[MethodCallInfo]:
        if block_node is None:
            return []

        calls: list[MethodCallInfo] = []
        for node in walk_descendants(block_node):
            if node.type != "method_invocation":
                continue

            # The Java grammar is not fully uniform across invocation shapes,
            # so keep the fallback to the full invocation text when needed.
            name_node = node.child_by_field_name("name")
            object_node = node.child_by_field_name("object")
            calls.append(
                MethodCallInfo(
                    name=text_of(name_node, source) if name_node is not None else text_of(node, source),
                    receiver=text_of(object_node, source) if object_node is not None else None,
                    line=node.start_point[0] + 1,
                )
            )
        return calls

    def _extract_method_exceptions(
        self,
        throws_node: Node | None,
        block_node: Node | None,
        source: bytes,
    ) -> list[str]:
        # Combine declared exceptions and explicit throw sites so downstream rules
        # can detect both API-level and in-body access denial patterns.
        declared = self._extract_type_names(throws_node, source)
        thrown: list[str] = []
        if block_node is not None:
            for node in walk_descendants(block_node):
                if node.type != "throw_statement":
                    continue
                creation = first_child(node, "object_creation_expression")
                if creation is not None:
                    thrown.extend(self._extract_type_names(creation, source))
        return unique_texts([*declared, *thrown])

    def _extract_string_literals(self, block_node: Node | None, source: bytes) -> list[str]:
        if block_node is None:
            return []

        literals: list[str] = []
        for node in walk_descendants(block_node):
            if node.type != "string_literal":
                continue
            literal = text_of(node, source).strip()
            if literal.startswith('"') and literal.endswith('"') and len(literal) >= 2:
                literal = literal[1:-1]
            literals.append(literal)
        return unique_texts(literals)

    def _extract_type_references(self, block_node: Node | None, source: bytes) -> list[str]:
        if block_node is None:
            return []

        type_names: list[str] = []
        for node in walk_descendants(block_node):
            if node.type in TYPE_REFERENCE_NODE_TYPES:
                type_names.append(text_of(node, source))
        return unique_texts(type_names)

    def _extract_annotations(self, modifiers_node: Node | None, source: bytes) -> list[str]:
        if modifiers_node is None:
            return []

        annotations: list[str] = []
        for child in modifiers_node.children:
            if child.type in ANNOTATION_NODE_TYPES:
                annotations.append(self._extract_annotation_name(child, source))
        return annotations

    def _extract_modifiers(self, modifiers_node: Node | None, source: bytes) -> list[str]:
        if modifiers_node is None:
            return []

        modifiers: list[str] = []
        for child in modifiers_node.children:
            if child.type in ANNOTATION_NODE_TYPES:
                continue
            value = text_of(child, source).strip()
            if value:
                modifiers.append(value)
        return modifiers

    def _extract_annotation_name(self, annotation_node: Node, source: bytes) -> str:
        name_node = annotation_node.child_by_field_name("name")
        if name_node is None:
            name_node = self._find_named_child(annotation_node, {"identifier", "scoped_identifier"})

        if name_node is None:
            return text_of(annotation_node, source).lstrip("@")

        return text_of(name_node, source).split(".")[-1]

    def _extract_inherited_types(self, class_node: Node, source: bytes) -> list[str]:
        return self._extract_type_names(first_child(class_node, "superclass"), source)

    def _extract_implemented_types(self, class_node: Node, source: bytes) -> list[str]:
        implemented_types: list[str] = []
        # Tree-sitter uses different node labels for different declaration forms,
        # so we probe the common variants instead of assuming a single one.
        for child_type in ("super_interfaces", "interfaces", "extends_interfaces"):
            implemented_types.extend(self._extract_type_names(first_child(class_node, child_type), source))
        return unique_texts(implemented_types)

    def _extract_type_names(self, node: Node | None, source: bytes) -> list[str]:
        if node is None:
            return []

        type_names: list[str] = []
        # Nested generic and scoped types appear as multiple AST nodes; collect
        # all of them first, then de-duplicate while keeping the original order.
        for child in walk_descendants(node):
            if child.type in TYPE_REFERENCE_NODE_TYPES:
                type_names.append(text_of(child, source))
        if node.type in TYPE_REFERENCE_NODE_TYPES:
            type_names.insert(0, text_of(node, source))
        return unique_texts(type_names)

    @staticmethod
    def _find_named_child(node: Node, node_types: set[str]) -> Node | None:
        for child in node.children:
            if child.type in node_types:
                return child
        return None
