from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import re

from java_project_analyzer.auth_patterns import (
    AUTH_CALL_KEYWORDS,
    AUTH_CLASS_NAME_KEYWORDS,
    AUTH_EXCEPTION_TYPES,
    AUTH_GUARD_ANNOTATIONS,
    AUTH_LITERAL_KEYWORDS,
    AUTH_METHOD_NAME_KEYWORDS,
    AUTH_TYPE_HINTS,
    DEFAULT_AUTH_MIN_SCORE,
    FRAMEWORK_SECURITY_METHODS,
    FRAMEWORK_SECURITY_TYPES,
    SECURITY_CONFIG_RETURN_TYPES,
    SECURITY_IMPORT_KEYWORDS,
    TOKEN_CALL_KEYWORDS,
    WEB_ENDPOINT_ANNOTATIONS,
)
from java_project_analyzer.models import AuthEvidence, AuthFinding, ClassInfo, FileAnalysis, MethodInfo


@dataclass
class _DetectionState:
    # 数据类，表示认证授权检测的状态，包括方法信息、各类信号的分数、证据列表和已见过的 Fact 集合
    # 用于记录单个方法的检测状态，累积不同类型的信号分数，并存储相关证据以供后续分析和输出
    method: MethodInfo
    category_scores: Counter[str] = field(default_factory=Counter)
    evidences: list[AuthEvidence] = field(default_factory=list)
    # The same AST fact can be seen by multiple heuristics; de-duplicate it so
    # a single signal does not inflate the score accidentally.
    seen_evidence: set[tuple[str, str, int | None]] = field(default_factory=set)

    @property
    def score(self) -> int:
        return sum(evidence.weight for evidence in self.evidences)

    def add(self, category: str, kind: str, detail: str, weight: int, line: int | None) -> None:
        evidence_key = (kind, detail, line)
        if evidence_key in self.seen_evidence:
            return
        self.seen_evidence.add(evidence_key)
        self.evidences.append(AuthEvidence(kind=kind, detail=detail, weight=weight, line=line))
        self.category_scores[category] += weight

    def category(self) -> str:
        if not self.category_scores:
            return "security_logic"
        return max(
            self.category_scores.items(),
            key=lambda item: (item[1], item[0]),
        )[0]

    def tags(self) -> list[str]:
        return [
            category
            for category, _score in sorted(
                self.category_scores.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]


def locate_auth_findings(#
    analyses: list[FileAnalysis],
    min_score: int = DEFAULT_AUTH_MIN_SCORE,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []

    for file_info in analyses:
        # Imports alone do not create findings, but they act as a small prior
        # when a method already looks security-related.
        has_security_imports = any(
            keyword in imported_name.lower()
            for imported_name in file_info.imports
            for keyword in SECURITY_IMPORT_KEYWORDS
        )

        for class_info in file_info.classes:
            # 递归分析单个文件内部类
            for method_info in class_info.methods:
                # 递归分析单个类内部方法
                state = _detect_method(
                    file_info=file_info,
                    class_info=class_info,
                    method_info=method_info,
                    has_security_imports=has_security_imports,
                )
                if state.score < min_score:
                    continue

                findings.append(
                    AuthFinding(
                        path=file_info.path,
                        package=file_info.package,
                        class_name=class_info.name,
                        method_name=method_info.name,
                        signature=_build_signature(file_info, class_info, method_info),
                        line=method_info.line,
                        category=state.category(),
                        score=state.score,
                        tags=state.tags(),
                        evidences=sorted(
                            state.evidences,
                            key=lambda evidence: (
                                -(evidence.weight),
                                evidence.line if evidence.line is not None else -1,
                                evidence.kind,
                                evidence.detail,
                            ),
                        ),
                    )
                )

    return sorted(
        findings,
        key=lambda finding: (
            -finding.score,
            finding.path,
            finding.line,
            finding.class_name,
            finding.method_name,
        ),
    )


def _detect_method(
    # 检测单个方法是否包含认证授权逻辑，返回检测状态对象
    file_info: FileAnalysis,
    class_info: ClassInfo,
    method_info: MethodInfo,
    has_security_imports: bool,
) -> _DetectionState:
    # The detector intentionally combines multiple weak hints into a score
    # instead of requiring a single exact framework pattern.
    state = _DetectionState(method=method_info)

    # judge if the method is a web endpoint by checking its annotations and its class annotations
    is_endpoint = _is_endpoint(class_info, method_info)
    # judge if the method is a security configuration
    # 即获取类的继承和实现的名字，如 extend xxx 获得的是 xxx
    class_component_types = _security_component_types(class_info)
    # judge if the method returns a common security framework type.
    method_return_type = _base_type_name(method_info.return_type)
    # 判断方法是否具有安全配置的特征：所在类被@Configuration注解标记，方法被@Bean注解标记，并且方法返回一个常见的安全组件类型。这些条件结合在一起可以较为准确地识别出Spring Security等框架中的安全配置方法。
    # 但是否会漏报一些不符合这些条件但仍然是安全配置的方法，或者误报一些偶然满足这些条件但实际上与安全配置无关的方法，则取决于项目的具体代码风格和使用的框架特征。
    # 还需要考虑是否满足要求 ！！！！！！
    is_security_config = (
        "Configuration" in class_info.annotations
        and "Bean" in method_info.annotations
        and method_return_type in SECURITY_CONFIG_RETURN_TYPES
    )

    # 添加注解可信度，根据注解判断是否与鉴权相关
    _add_annotation_signals(state, class_info, method_info, is_endpoint)
    # 添加方法和类名关键词可信度，根据关键词来添加部分置信度
    _add_name_signals(state, class_info, method_info)
    # 添加框架相关类型和方法的可信度
    _add_framework_signals(state, class_info, method_info, class_component_types)
    # 添加调用、异常、字符串字面量、类型引用等多种信号的可信度
    _add_call_signals(state, method_info)
    # 添加方法声明的异常类型信号的可信度
    _add_exception_signals(state, method_info)
    # 添加字符串字面量信号的可信度
    _add_literal_signals(state, method_info)
    # 添加类型引用信号的可信度
    _add_type_reference_signals(state, method_info)
    # 添加安全配置相关信号的可信度
    _add_security_config_signals(state, class_info, method_info, is_security_config)

    if has_security_imports and state.score > 0:
        # 文件导入了安全相关的库，并且方法有其他安全信号，那么导入本身也增加一点可信度，帮助区分安全相关代码和偶尔使用了安全相关词的普通代码。
        state.add(
            category="security_logic",
            kind="import",
            detail="File imports common security framework packages",
            weight=1,
            line=method_info.line,
        )

    return state


def _add_annotation_signals(
    state: _DetectionState,
    class_info: ClassInfo,
    method_info: MethodInfo,
    is_endpoint: bool,
) -> None:
    class_guard_annotations = sorted(
        annotation for annotation in class_info.annotations if annotation in AUTH_GUARD_ANNOTATIONS
    )
    method_guard_annotations = sorted(
        annotation for annotation in method_info.annotations if annotation in AUTH_GUARD_ANNOTATIONS
    )

    for annotation in class_guard_annotations:
        state.add(
            category="endpoint_guard" if is_endpoint else "permission_checker",
            kind="annotation",
            detail=f"Class annotation @{annotation}",
            weight=4,
            line=class_info.line,
        )

    for annotation in method_guard_annotations:
        state.add(
            category="endpoint_guard" if is_endpoint else "permission_checker",
            kind="annotation",
            detail=f"Method annotation @{annotation}",
            weight=7,
            line=method_info.line,
        )

    if is_endpoint and method_guard_annotations:
        # The same annotation is more interesting when it protects a request
        # handler than when it sits on an internal helper.
        state.add(
            category="endpoint_guard",
            kind="endpoint",
            detail="Endpoint method guarded by authorization annotation",
            weight=2,
            line=method_info.line,
        )


def _add_name_signals(
    state: _DetectionState,
    class_info: ClassInfo,
    method_info: MethodInfo,
) -> None:
    method_name = method_info.name.lower()
    class_name = class_info.name.lower()

    if any(keyword in method_name for keyword in AUTH_METHOD_NAME_KEYWORDS):
        category = "token_handler" if any(token in method_name for token in {"jwt", "token"}) else "permission_checker"
        state.add(
            category=category,
            kind="name",
            detail=f"Method name '{method_info.name}' suggests security logic",
            weight=2,
            line=method_info.line,
        )

    if any(keyword in class_name for keyword in AUTH_CLASS_NAME_KEYWORDS):
        category = "token_handler" if any(token in class_name for token in {"jwt", "token"}) else "security_logic"
        state.add(
            category=category,
            kind="class_name",
            detail=f"Class name '{class_info.name}' suggests security logic",
            weight=1,
            line=class_info.line,
        )

    if method_info.return_type == "boolean" and any(
        keyword in method_name for keyword in {"access", "permission", "role", "auth", "allow"}
    ):
        state.add(
            category="permission_checker",
            kind="return_type",
            detail="Boolean return type fits permission-checking semantics",
            weight=1,
            line=method_info.line,
        )


def _add_framework_signals(
    state: _DetectionState,
    class_info: ClassInfo,
    method_info: MethodInfo,
    class_component_types: list[str],
) -> None:
    for component_type in class_component_types:
        category = "identity_resolver" if "ArgumentResolver" in component_type else "framework_guard"
        state.add(
            category=category,
            kind="framework_type",
            detail=f"Class uses security framework type '{component_type}'",
            weight=2,
            line=class_info.line,
        )

    if method_info.name in FRAMEWORK_SECURITY_METHODS:
        category = "identity_resolver" if method_info.name == "resolveArgument" else "framework_guard"
        state.add(
            category=category,
            kind="framework_method",
            detail=f"Method '{method_info.name}' is a common security framework hook",
            # "supportsParameter" is usually just capability declaration, so it
            # gets a lower weight than request-processing hooks.
            weight=1 if method_info.name == "supportsParameter" else 3,
            line=method_info.line,
        )


def _add_call_signals(state: _DetectionState, method_info: MethodInfo) -> None:
    for call_info in method_info.calls:
        # Tree-sitter may give chained or partially qualified call text. Reduce
        # it to stable receiver/method tokens before matching keywords.
        call_name = _normalize_call_name(call_info.name)
        receiver_name = _normalize_receiver_name(call_info.receiver)
        joined_call = ".".join(filter(None, [receiver_name, call_name]))

        if any(keyword in call_name for keyword in AUTH_CALL_KEYWORDS):
            state.add(
                category="permission_checker",
                kind="call",
                detail=f"Call to '{joined_call or call_info.name}'",
                weight=4,
                line=call_info.line,
            )

        if (
            any(keyword in call_name for keyword in TOKEN_CALL_KEYWORDS)
            or (
                receiver_name in {"jwt", "jwthelper", "usertokenmanager", "tokenmanager"}
                and any(keyword in call_name for keyword in {"create", "decode", "generate", "parse", "verify", "validate", "require"})
            )
        ):
            state.add(
                category="token_handler",
                kind="call",
                detail=f"Token-related call '{joined_call or call_info.name}'",
                weight=4,
                line=call_info.line,
            )

        if receiver_name in {
            "securitycontextholder",
            "securityutils",
            "subject",
            "principal",
            "authentication",
            "currentuser",
        } or call_name in {"getprincipal", "getauthentication"}:
            state.add(
                category="permission_checker",
                kind="call",
                detail=f"Identity or security-context access through '{joined_call or call_info.name}'",
                weight=4,
                line=call_info.line,
            )


def _add_exception_signals(state: _DetectionState, method_info: MethodInfo) -> None:
    for exception_name in method_info.thrown_exceptions:
        base_name = _base_type_name(exception_name)
        normalized_name = base_name.lower()
        if base_name in AUTH_EXCEPTION_TYPES or any(
            keyword in normalized_name for keyword in {"denied", "forbidden", "unauthorized", "auth"}
        ):
            state.add(
                category="permission_checker",
                kind="exception",
                detail=f"Throws or declares '{base_name}'",
                weight=4,
                line=method_info.line,
            )


def _add_literal_signals(state: _DetectionState, method_info: MethodInfo) -> None:
    for literal in method_info.string_literals:
        normalized_literal = literal.lower()
        if not any(keyword in normalized_literal for keyword in AUTH_LITERAL_KEYWORDS):
            continue

        # Separate token headers from filter-chain literals so the output tags
        # are easier to understand during triage.
        if any(keyword in normalized_literal for keyword in {"authorization", "bearer", "token", "jwt", "x-token", "x-litemall-token"}):
            category = "token_handler"
        elif normalized_literal in {"authc", "anon"}:
            category = "security_config"
        else:
            category = "permission_checker"

        state.add(
            category=category,
            kind="literal",
            detail=f"Security-related string literal '{literal}'",
            weight=2,
            line=method_info.line,
        )


def _add_type_reference_signals(state: _DetectionState, method_info: MethodInfo) -> None:
    for type_name in method_info.type_references:
        base_name = _base_type_name(type_name)
        normalized_name = base_name.lower()
        if base_name in AUTH_TYPE_HINTS or any(
            keyword in normalized_name for keyword in {"security", "jwt", "token", "principal", "permission", "role", "auth"}
        ):
            category = "token_handler" if any(keyword in normalized_name for keyword in {"jwt", "token"}) else "security_logic"
            state.add(
                category=category,
                kind="type_reference",
                detail=f"Uses security-related type '{base_name}'",
                weight=2,
                line=method_info.line,
            )


def _add_security_config_signals(
    state: _DetectionState,
    class_info: ClassInfo,
    method_info: MethodInfo,
    is_security_config: bool,
) -> None:
    return_type = _base_type_name(method_info.return_type)
    if return_type in SECURITY_CONFIG_RETURN_TYPES:
        state.add(
            category="security_config",
            kind="return_type",
            detail=f"Returns security component '{return_type}'",
            weight=5 if is_security_config else 3,
            line=method_info.line,
        )

    if "Configuration" in class_info.annotations and "Bean" in method_info.annotations:
        state.add(
            category="security_config",
            kind="configuration",
            detail="Bean method declared inside a configuration class",
            weight=2,
            line=method_info.line,
        )


def _is_endpoint(class_info: ClassInfo, method_info: MethodInfo) -> bool:
    combined_annotations = set(class_info.annotations) | set(method_info.annotations)
    return bool(combined_annotations & WEB_ENDPOINT_ANNOTATIONS)


def _security_component_types(class_info: ClassInfo) -> list[str]:
    # get the base name of all extended and implemented types.
    matched: list[str] = []
    for type_name in [*class_info.extends_types, *class_info.implements_types]:
        base_name = _base_type_name(type_name)
        if base_name in FRAMEWORK_SECURITY_TYPES:
            matched.append(base_name)
    return sorted(set(matched))


def _base_type_name(type_name: str) -> str:
    stripped = type_name.split("<", maxsplit=1)[0].rstrip("[]")
    return stripped.split(".")[-1]


def _build_signature(file_info: FileAnalysis, class_info: ClassInfo, method_info: MethodInfo) -> str:
    # return a signature string like "com.example.MyClass#myMethod(2)" for a method with 2 parameters.
    package_prefix = f"{file_info.package}." if file_info.package else ""
    return f"{package_prefix}{class_info.name}#{method_info.name}({len(method_info.parameters)})"


_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _normalize_call_name(raw_name: str) -> str:
    # For chained invocations like "jwt.create().withIssuer", only the tail
    # method name is useful for keyword matching.
    matches = _IDENTIFIER_PATTERN.findall(raw_name)
    return matches[-1].lower() if matches else raw_name.lower()


def _normalize_receiver_name(raw_receiver: str | None) -> str:
    if not raw_receiver:
        return ""
    # The first identifier is usually enough to distinguish helpers such as
    # SecurityUtils, jwtHelper, or userTokenManager.
    matches = _IDENTIFIER_PATTERN.findall(raw_receiver)
    return matches[0].lower() if matches else raw_receiver.lower()
