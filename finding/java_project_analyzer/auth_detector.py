from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import re

from java_project_analyzer.auth_patterns import (
    AOP_ADVICE_ANNOTATIONS,
    AOP_CLASS_ANNOTATIONS,
    AOP_IMPORT_KEYWORDS,
    AOP_JOINPOINT_TYPES,
    AOP_POINTCUT_REFERENCE_BLACKLIST,
    AOP_SECURITY_KEYWORDS,
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
    INLINE_AUTH_CALL_KEYWORDS,
    INLINE_AUTH_IDENTIFIER_KEYWORDS,
    INLINE_DENY_ACTION_KEYWORDS,
    INLINE_DENY_RETURN_TEXT_KEYWORDS,
    SECURITY_CONFIG_RETURN_TYPES,
    SECURITY_IMPORT_KEYWORDS,
    TOKEN_CALL_KEYWORDS,
    WEB_ENDPOINT_ANNOTATIONS,
)
from java_project_analyzer.models import (
    AuthEvidence,
    AuthFinding,
    BranchActionInfo,
    ClassInfo,
    FileAnalysis,
    IfStatementInfo,
    MethodInfo,
)


@dataclass
class _AnnotationIndex:
    method_targets: dict[str, list[str]]
    class_targets: dict[str, list[str]]


@dataclass
class _DetectionState:
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


_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_POINTCUT_TARGET_PATTERN = re.compile(r"@(annotation|within|target)\(([^)]+)\)")
_POINTCUT_REFERENCE_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\)")
_IMPLEMENTATION_CATEGORIES = {
    "aop_guard",
    "framework_guard",
    "identity_resolver",
    "inline_guard",
    "security_config",
}
_IMPLEMENTATION_EVIDENCE_KINDS = {
    "advice_annotation",
    "aspect_class",
    "configuration",
    "exception",
    "framework_method",
    "framework_type",
    "guard_call",
    "if_guard",
    "joinpoint_param",
    "pointcut",
    "pointcut_binding",
    "pointcut_hint",
    "pointcut_target",
    "token_call",
}
_INLINE_SUBJECT_KEYWORDS = {
    "adminid",
    "auth",
    "authentication",
    "bearer",
    "currentuser",
    "jwt",
    "login",
    "loginuser",
    "owner",
    "password",
    "principal",
    "subject",
    "tenant",
    "token",
    "userid",
    "username",
}
_INLINE_DECISION_KEYWORDS = {
    "admin",
    "authority",
    "permission",
    "permitted",
    "role",
    "scope",
}


def locate_auth_findings(
    analyses: list[FileAnalysis],
    min_score: int = DEFAULT_AUTH_MIN_SCORE,
) -> list[AuthFinding]:
    findings: list[AuthFinding] = []
    annotation_index = _build_annotation_index(analyses)

    for file_info in analyses:
        # Imports alone do not create findings, but they act as a small prior
        # when a method already looks security-related.
        has_security_imports = any(
            keyword in imported_name.lower()
            for imported_name in file_info.imports
            for keyword in SECURITY_IMPORT_KEYWORDS
        )
        has_aop_imports = any(
            keyword in imported_name.lower()
            for imported_name in file_info.imports
            for keyword in AOP_IMPORT_KEYWORDS
        )

        for class_info in file_info.classes:
            pointcut_map = _build_pointcut_map(class_info)
            for method_info in class_info.methods:
                state = _detect_method(
                    file_info=file_info,
                    class_info=class_info,
                    method_info=method_info,
                    has_security_imports=has_security_imports,
                    has_aop_imports=has_aop_imports,
                    annotation_index=annotation_index,
                    pointcut_map=pointcut_map,
                )
                if state.score < min_score:
                    continue
                if not _is_concrete_auth_implementation(state):
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


def _build_annotation_index(analyses: list[FileAnalysis]) -> _AnnotationIndex:
    method_targets: defaultdict[str, list[str]] = defaultdict(list)
    class_targets: defaultdict[str, list[str]] = defaultdict(list)

    for file_info in analyses:
        for class_info in file_info.classes:
            class_signature = _build_class_signature(file_info, class_info)
            for annotation in class_info.annotation_infos:
                class_targets[annotation.name].append(class_signature)

            for method_info in class_info.methods:
                method_signature = _build_signature(file_info, class_info, method_info)
                for annotation in method_info.annotation_infos:
                    method_targets[annotation.name].append(method_signature)

    return _AnnotationIndex(
        method_targets={key: sorted(set(value)) for key, value in method_targets.items()},
        class_targets={key: sorted(set(value)) for key, value in class_targets.items()},
    )


def _build_pointcut_map(class_info: ClassInfo) -> dict[str, list[str]]:
    pointcut_map: dict[str, list[str]] = {}
    for method_info in class_info.methods:
        expressions = [
            annotation.argument_text
            for annotation in method_info.annotation_infos
            if annotation.name == "Pointcut" and annotation.argument_text
        ]
        if expressions:
            pointcut_map[method_info.name] = expressions
    return pointcut_map


def _detect_method(
    file_info: FileAnalysis,
    class_info: ClassInfo,
    method_info: MethodInfo,
    has_security_imports: bool,
    has_aop_imports: bool,
    annotation_index: _AnnotationIndex,
    pointcut_map: dict[str, list[str]],
) -> _DetectionState:
    # The detector intentionally combines multiple weak hints into a score
    # instead of requiring a single exact framework pattern.
    state = _DetectionState(method=method_info)

    is_endpoint = _is_endpoint(class_info, method_info)
    class_component_types = _security_component_types(class_info)
    method_return_type = _base_type_name(method_info.return_type)
    is_security_config = (
        "Configuration" in class_info.annotations
        and "Bean" in method_info.annotations
        and method_return_type in SECURITY_CONFIG_RETURN_TYPES
    )

    _add_annotation_signals(state, class_info, method_info, is_endpoint)
    _add_name_signals(state, class_info, method_info)
    _add_framework_signals(state, class_info, method_info, class_component_types)
    _add_call_signals(state, method_info)
    _add_exception_signals(state, method_info)
    _add_literal_signals(state, method_info)
    _add_type_reference_signals(state, method_info)
    _add_security_config_signals(state, class_info, method_info, is_security_config)
    _add_inline_guard_signals(state, method_info)
    _add_aop_signals(
        state=state,
        file_info=file_info,
        class_info=class_info,
        method_info=method_info,
        has_aop_imports=has_aop_imports,
        annotation_index=annotation_index,
        pointcut_map=pointcut_map,
    )

    if has_security_imports and state.score > 0:
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
        # Reading Subject/Principal frequently happens inside endpoints and log
        # helpers, so treat it as identity access instead of proof that this
        # method performs the authorization decision itself.
        is_identity_call = receiver_name in {
            "securitycontextholder",
            "securityutils",
            "subject",
            "principal",
            "authentication",
            "currentuser",
        } or call_name in {"getprincipal", "getauthentication", "getsubject"}

        if any(keyword in call_name for keyword in AUTH_CALL_KEYWORDS) and not is_identity_call:
            state.add(
                category="permission_checker",
                kind="guard_call",
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
                kind="token_call",
                detail=f"Token-related call '{joined_call or call_info.name}'",
                weight=4,
                line=call_info.line,
            )

        if is_identity_call:
            state.add(
                category="permission_checker",
                kind="identity_call",
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


def _add_inline_guard_signals(state: _DetectionState, method_info: MethodInfo) -> None:
    for if_info in method_info.if_statements:
        identifier_hits = [
            identifier
            for identifier in if_info.identifiers
            if any(keyword in identifier.lower() for keyword in INLINE_AUTH_IDENTIFIER_KEYWORDS)
        ]
        call_hits = [
            call
            for call in if_info.method_calls
            if any(keyword in call.lower() for keyword in INLINE_AUTH_CALL_KEYWORDS)
        ]
        literal_hits = [
            literal
            for literal in if_info.string_literals
            if any(keyword in literal.lower() for keyword in AUTH_LITERAL_KEYWORDS)
        ]
        deny_actions = [
            action
            for action in [*if_info.branch_actions, *if_info.else_branch_actions]
            if _is_deny_action(action)
        ]
        strong_identifier_hits = [
            identifier
            for identifier in identifier_hits
            if any(keyword in identifier.lower() for keyword in _INLINE_SUBJECT_KEYWORDS)
        ]
        decision_identifier_hits = [
            identifier
            for identifier in identifier_hits
            if any(keyword in identifier.lower() for keyword in _INLINE_DECISION_KEYWORDS)
        ]
        condition_text_lower = if_info.condition_text.lower()
        has_decision_pattern = (
            any(token in condition_text_lower for token in {"contains(", "equals(", "hasrole", "hasauthority", "haspermission"})
            or bool(if_info.string_literals)
        )
        is_simple_validation = (
            "null" in condition_text_lower
            and not call_hits
            and not strong_identifier_hits
        )

        if not (
            call_hits
            or strong_identifier_hits
            or (decision_identifier_hits and has_decision_pattern)
            or literal_hits
        ):
            continue
        if is_simple_validation and not literal_hits:
            continue

        summary_parts: list[str] = []
        if strong_identifier_hits:
            summary_parts.append(f"identifiers={strong_identifier_hits[:3]}")
        elif decision_identifier_hits:
            summary_parts.append(f"identifiers={decision_identifier_hits[:3]}")
        if call_hits:
            summary_parts.append(f"calls={call_hits[:2]}")
        if literal_hits:
            summary_parts.append(f"literals={literal_hits[:2]}")
        summary = ", ".join(summary_parts)

        if deny_actions:
            state.add(
                category="inline_guard",
                kind="if_guard",
                detail=(
                    f"If condition '{if_info.condition_text}' looks security-related "
                    f"and leads to deny actions ({_summarize_actions(deny_actions)})"
                ),
                weight=5,
                line=if_info.line,
            )
            state.add(
                category="inline_guard",
                kind="if_signal",
                detail=f"Inline auth signals: {summary}",
                weight=2,
                line=if_info.line,
            )
        elif _has_guarded_proceed(if_info):
            state.add(
                category="inline_guard",
                kind="if_guard",
                detail=(
                    f"If condition '{if_info.condition_text}' gates a proceed path "
                    f"inside the method"
                ),
                weight=4,
                line=if_info.line,
            )
            state.add(
                category="inline_guard",
                kind="if_signal",
                detail=f"Inline auth signals: {summary}",
                weight=1,
                line=if_info.line,
            )


def _add_aop_signals(
    state: _DetectionState,
    file_info: FileAnalysis,
    class_info: ClassInfo,
    method_info: MethodInfo,
    has_aop_imports: bool,
    annotation_index: _AnnotationIndex,
    pointcut_map: dict[str, list[str]],
) -> None:
    class_is_aspect = bool(set(class_info.annotations) & AOP_CLASS_ANNOTATIONS) or (
        has_aop_imports
        and any(
            annotation.name in AOP_ADVICE_ANNOTATIONS
            for method in class_info.methods
            for annotation in method.annotation_infos
        )
    )
    advice_annotations = [
        annotation
        for annotation in method_info.annotation_infos
        if annotation.name in AOP_ADVICE_ANNOTATIONS
    ]
    joinpoint_types = _extract_joinpoint_types(method_info)
    resolved_pointcuts = _resolve_pointcut_expressions(method_info, pointcut_map)

    target_annotations = [
        annotation_name
        for expression in resolved_pointcuts
        for annotation_name in _extract_pointcut_annotation_targets(expression, method_info)
    ]
    has_security_target = any(_looks_security_related(name) for name in target_annotations)
    has_security_pointcut = any(
        any(keyword in expression.lower() for keyword in AOP_SECURITY_KEYWORDS)
        for expression in resolved_pointcuts
    )
    has_inline_guard = state.category_scores.get("inline_guard", 0) > 0
    has_security_name = any(
        keyword in value.lower()
        for value in (class_info.name, method_info.name)
        for keyword in AOP_SECURITY_KEYWORDS
    )
    has_security_binding = has_security_target or has_security_pointcut
    has_security_advice = bool(advice_annotations) and (
        has_security_binding
        or has_inline_guard
        or has_security_name
    )

    if not class_is_aspect and not advice_annotations and not joinpoint_types:
        return
    # Ordinary tracing/logging aspects are common. Only score the advice when
    # the aspect shape is backed by a security-oriented pointcut, method body,
    # or naming signal.
    if not (has_security_advice or has_inline_guard or has_security_name):
        return

    if class_is_aspect:
        state.add(
            category="aop_guard",
            kind="aspect_class",
            detail=f"Class '{class_info.name}' looks like an AOP aspect",
            weight=4,
            line=class_info.line,
        )

    for joinpoint_type in joinpoint_types:
        state.add(
            category="aop_guard",
            kind="joinpoint_param",
            detail=f"Method parameter uses AOP join point type '{joinpoint_type}'",
            weight=3,
            line=method_info.line,
        )

    for annotation in advice_annotations:
        weight = 2 if annotation.name == "Pointcut" else 4
        state.add(
            category="aop_guard",
            kind="advice_annotation",
            detail=f"Advice annotation @{annotation.name}",
            weight=weight,
            line=annotation.line,
        )

    for expression in resolved_pointcuts:
        lowered_expression = expression.lower()
        state.add(
            category="aop_guard",
            kind="pointcut",
            detail=f"Pointcut expression '{expression}'",
            weight=2,
            line=method_info.line,
        )

        if any(keyword in lowered_expression for keyword in AOP_SECURITY_KEYWORDS):
            state.add(
                category="aop_guard",
                kind="pointcut_hint",
                detail=f"Pointcut expression '{expression}' contains security-related keywords",
                weight=2,
                line=method_info.line,
            )

        for annotation_name in _extract_pointcut_annotation_targets(expression, method_info):
            weight = 4 if annotation_name in AUTH_GUARD_ANNOTATIONS or _looks_security_related(annotation_name) else 2
            state.add(
                category="aop_guard",
                kind="pointcut_target",
                detail=f"Pointcut targets annotation '{annotation_name}'",
                weight=weight,
                line=method_info.line,
            )

            matched_methods = len(annotation_index.method_targets.get(annotation_name, []))
            matched_classes = len(annotation_index.class_targets.get(annotation_name, []))
            matched_total = matched_methods + matched_classes
            if matched_total:
                state.add(
                    category="aop_guard",
                    kind="pointcut_binding",
                    detail=(
                        f"Pointcut can bind to {matched_total} project target(s) "
                        f"through annotation '{annotation_name}'"
                    ),
                    weight=min(4, matched_total),
                    line=method_info.line,
                )


def _resolve_pointcut_expressions(
    method_info: MethodInfo,
    pointcut_map: dict[str, list[str]],
) -> list[str]:
    expressions: list[str] = []
    queue = [
        annotation.argument_text
        for annotation in method_info.annotation_infos
        if annotation.name in AOP_ADVICE_ANNOTATIONS and annotation.argument_text
    ]
    seen: set[str] = set()

    while queue:
        expression = queue.pop(0)
        if expression in seen:
            continue
        seen.add(expression)
        expressions.append(expression)

        for reference in _POINTCUT_REFERENCE_PATTERN.findall(expression):
            if reference in AOP_POINTCUT_REFERENCE_BLACKLIST or reference not in pointcut_map:
                continue
            queue.extend(pointcut_map[reference])

    return expressions


def _extract_pointcut_annotation_targets(
    pointcut_expression: str,
    method_info: MethodInfo,
) -> list[str]:
    parameter_types = _parameter_type_map(method_info)
    targets: list[str] = []

    for _kind, raw_target in _POINTCUT_TARGET_PATTERN.findall(pointcut_expression):
        cleaned_target = raw_target.strip().lstrip("@")
        cleaned_target = cleaned_target.split("=", maxsplit=1)[-1].strip()
        base_name = cleaned_target.split(".")[-1]
        if base_name and base_name[0].islower():
            base_name = parameter_types.get(base_name, base_name)
        targets.append(base_name)

    return sorted(set(target for target in targets if target))


def _parameter_type_map(method_info: MethodInfo) -> dict[str, str]:
    parameter_map: dict[str, str] = {}
    for parameter in method_info.parameters:
        tokens = _IDENTIFIER_PATTERN.findall(parameter)
        if len(tokens) < 2:
            continue
        parameter_map[tokens[-1]] = tokens[-2]
    return parameter_map


def _extract_joinpoint_types(method_info: MethodInfo) -> list[str]:
    joinpoint_types: list[str] = []
    for parameter in method_info.parameters:
        tokens = _IDENTIFIER_PATTERN.findall(parameter)
        if len(tokens) < 2:
            continue
        parameter_type = tokens[-2]
        if parameter_type in AOP_JOINPOINT_TYPES:
            joinpoint_types.append(parameter_type)
    return sorted(set(joinpoint_types))


def _is_concrete_auth_implementation(state: _DetectionState) -> bool:
    if any(category in _IMPLEMENTATION_CATEGORIES for category in state.category_scores):
        return True

    evidence_kinds = {evidence.kind for evidence in state.evidences}
    if evidence_kinds & _IMPLEMENTATION_EVIDENCE_KINDS:
        return True

    # Annotation-only endpoints are "protected entry points", not the place
    # where authorization is actually implemented.
    return False


def _is_endpoint(class_info: ClassInfo, method_info: MethodInfo) -> bool:
    combined_annotations = set(class_info.annotations) | set(method_info.annotations)
    return bool(combined_annotations & WEB_ENDPOINT_ANNOTATIONS)


def _security_component_types(class_info: ClassInfo) -> list[str]:
    # Reduce inherited and implemented types to their simple names before
    # matching framework components.
    matched: list[str] = []
    for type_name in [*class_info.extends_types, *class_info.implements_types]:
        base_name = _base_type_name(type_name)
        if base_name in FRAMEWORK_SECURITY_TYPES:
            matched.append(base_name)
    return sorted(set(matched))


def _is_deny_action(action: BranchActionInfo) -> bool:
    detail = action.detail.lower()
    if action.kind == "throw":
        return True
    if action.kind == "return":
        return any(keyword in detail for keyword in INLINE_DENY_RETURN_TEXT_KEYWORDS)
    if action.kind == "call":
        normalized_call = _normalize_call_name(action.detail)
        return any(keyword in normalized_call for keyword in INLINE_DENY_ACTION_KEYWORDS)
    return False


def _has_guarded_proceed(if_info: IfStatementInfo) -> bool:
    branch_calls = [action.detail.lower() for action in if_info.branch_actions if action.kind == "call"]
    else_calls = [action.detail.lower() for action in if_info.else_branch_actions if action.kind == "call"]
    return any("proceed" in call for call in [*branch_calls, *else_calls])


def _summarize_actions(actions: list[BranchActionInfo]) -> str:
    return ", ".join(action.detail for action in actions[:3])


def _base_type_name(type_name: str) -> str:
    stripped = type_name.split("<", maxsplit=1)[0].rstrip("[]")
    return stripped.split(".")[-1]


def _looks_security_related(value: str) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in AOP_SECURITY_KEYWORDS)


def _build_signature(file_info: FileAnalysis, class_info: ClassInfo, method_info: MethodInfo) -> str:
    package_prefix = f"{file_info.package}." if file_info.package else ""
    return f"{package_prefix}{class_info.name}#{method_info.name}({len(method_info.parameters)})"


def _build_class_signature(file_info: FileAnalysis, class_info: ClassInfo) -> str:
    package_prefix = f"{file_info.package}." if file_info.package else ""
    return f"{package_prefix}{class_info.name}"


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
