from __future__ import annotations

from collections.abc import Iterable

from java_project_analyzer.models import ClassInfo, FileAnalysis


def has_target_annotation(annotations: Iterable[str], targets: set[str]) -> bool:
    # return True if any annotation in the target, otherwise False.
    return any(annotation in targets for annotation in annotations)


def filter_analysis(
    analyses: list[FileAnalysis],
    annotation_filters: set[str] | None,
    methods_only: bool,
) -> list[FileAnalysis]:
    # An Filter in order to filter the result based on the provided args.
    # If no annotation filters are specified and methods_only is not set, return the original analysis.
    if annotation_filters is None and not methods_only:
        return analyses

    filtered_files: list[FileAnalysis] = []
    for file_info in analyses:
        filtered_classes: list[ClassInfo] = []
        for class_info in file_info.classes:
            matched_methods = class_info.methods
            if annotation_filters is not None:
                matched_methods = [
                    method
                    for method in matched_methods
                    if has_target_annotation(method.annotations, annotation_filters)
                ]

            if methods_only and not matched_methods:
                continue

            keep_class = bool(matched_methods)
            if annotation_filters is not None and has_target_annotation(
                class_info.annotations,
                annotation_filters,
            ):
                keep_class = True

            if keep_class:
                filtered_classes.append(
                    ClassInfo(
                        name=class_info.name,
                        line=class_info.line,
                        kind=class_info.kind,
                        modifiers=class_info.modifiers,
                        annotations=class_info.annotations,
                        annotation_infos=class_info.annotation_infos,
                        extends_types=class_info.extends_types,
                        implements_types=class_info.implements_types,
                        fields=class_info.fields,
                        methods=matched_methods,
                    )
                )

        if filtered_classes:
            filtered_files.append(
                FileAnalysis(
                    path=file_info.path,
                    package=file_info.package,
                    imports=file_info.imports,
                    classes=filtered_classes,
                )
            )
    return filtered_files
