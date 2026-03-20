from __future__ import annotations

import argparse
from pathlib import Path

from java_project_analyzer.analyzer import JavaProjectAnalyzer
from java_project_analyzer.auth_detector import locate_auth_findings
from java_project_analyzer.auth_patterns import DEFAULT_AUTH_MIN_SCORE
from java_project_analyzer.constants import DEFAULT_SECURITY_ANNOTATIONS
from java_project_analyzer.filters import filter_analysis
from java_project_analyzer.renderers import (
    render_auth_findings_json,
    render_auth_findings_text,
    render_json,
    render_text,
)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Use tree-sitter Python bindings to analyze a Java project."
    )
    parser.add_argument("project_root", type=Path, help="Java project root directory")
    parser.add_argument("--json", action="store_true", help="Print analysis result as JSON")
    parser.add_argument(
        "--annotations",
        nargs="*",
        help="Only keep classes or methods containing these annotations",
    )
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="Shortcut for common security and web-entry annotations",
    )
    parser.add_argument(
        "--methods-only",
        action="store_true",
        help="Only keep files or classes that contain matched methods",
    )
    parser.add_argument(
        "--locate-auth",
        action="store_true",
        help="Locate concrete Java authorization and authentication implementation points",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=DEFAULT_AUTH_MIN_SCORE,
        help="Minimum score for auth findings when --locate-auth is enabled",
    )
    return parser


def resolve_annotation_filters(args: argparse.Namespace) -> set[str] | None:
    annotation_filters: set[str] | None = None
    if args.security_only:
        annotation_filters = set(DEFAULT_SECURITY_ANNOTATIONS)
    if args.annotations:
        # User-specified annotations extend the built-in shortcut instead of
        # replacing it, which keeps the CLI convenient for mixed projects.
        user_annotations = set(args.annotations)
        annotation_filters = user_annotations if annotation_filters is None else (
            annotation_filters | user_annotations
        )
    return annotation_filters


def main() -> None:
    # receive the args
    args = build_argument_parser().parse_args()
    project_root = args.project_root.resolve()
    if not project_root.exists():
        raise SystemExit(f"[-] Project root does not exist: {project_root}")

    analyzer = JavaProjectAnalyzer()
    analyses = analyzer.analyze_project(project_root)
    if args.locate_auth:
        # Auth-location mode consumes the same AST facts, then keeps concrete
        # implementation points instead of merely listing protected endpoints.
        findings = locate_auth_findings(analyses=analyses, min_score=args.min_score)
        print(render_auth_findings_json(findings) if args.json else render_auth_findings_text(findings))
        return

    analyses = filter_analysis(
        analyses=analyses,
        annotation_filters=resolve_annotation_filters(args),
        methods_only=args.methods_only,
    )
    print(render_json(analyses) if args.json else render_text(analyses))
