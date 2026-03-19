"""Utilities for analyzing Java projects with tree-sitter."""

from java_project_analyzer.analyzer import JavaProjectAnalyzer
from java_project_analyzer.auth_detector import locate_auth_findings

__all__ = ["JavaProjectAnalyzer", "locate_auth_findings"]
