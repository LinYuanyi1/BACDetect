from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MethodCallInfo:
    name: str
    line: int
    receiver: str | None = None


@dataclass
class MethodInfo:
    name: str
    line: int
    return_type: str
    parameters: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    calls: list[MethodCallInfo] = field(default_factory=list)


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
    fields: list[FieldInfo] = field(default_factory=list)
    methods: list[MethodInfo] = field(default_factory=list)


@dataclass
class FileAnalysis:
    path: str
    package: str | None
    imports: list[str]
    classes: list[ClassInfo]
