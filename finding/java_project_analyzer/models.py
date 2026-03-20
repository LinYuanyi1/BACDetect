from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnnotationInfo:
    name: str
    line: int
    raw_text: str
    argument_text: str | None = None


@dataclass
class MethodCallInfo:
    name: str
    line: int
    receiver: str | None = None


@dataclass
class BranchActionInfo:
    kind: str
    detail: str
    line: int


@dataclass
class IfStatementInfo:
    line: int
    condition_text: str
    identifiers: list[str] = field(default_factory=list)
    method_calls: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    comparison_ops: list[str] = field(default_factory=list)
    branch_actions: list[BranchActionInfo] = field(default_factory=list)
    else_branch_actions: list[BranchActionInfo] = field(default_factory=list)


@dataclass
class MethodInfo:
    name: str
    line: int
    return_type: str
    parameters: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    annotation_infos: list[AnnotationInfo] = field(default_factory=list)
    calls: list[MethodCallInfo] = field(default_factory=list)
    thrown_exceptions: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    type_references: list[str] = field(default_factory=list)
    if_statements: list[IfStatementInfo] = field(default_factory=list)


@dataclass
class FieldInfo:
    name: str
    line: int
    field_type: str
    modifiers: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)


@dataclass
class ClassInfo:
    name: str
    line: int
    kind: str
    modifiers: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    annotation_infos: list[AnnotationInfo] = field(default_factory=list)
    extends_types: list[str] = field(default_factory=list)
    implements_types: list[str] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    methods: list[MethodInfo] = field(default_factory=list)


@dataclass
class FileAnalysis:
    path: str
    package: str | None
    imports: list[str]
    classes: list[ClassInfo]


@dataclass
class AuthEvidence:
    kind: str
    detail: str
    weight: int
    line: int | None = None


@dataclass
class AuthFinding:
    path: str
    package: str | None
    class_name: str
    method_name: str
    signature: str
    line: int
    category: str
    score: int
    tags: list[str] = field(default_factory=list)
    evidences: list[AuthEvidence] = field(default_factory=list)
