from __future__ import annotations

import json
from dataclasses import asdict

from java_project_analyzer.models import AuthFinding, FileAnalysis


def render_text(analyses: list[FileAnalysis]) -> str:
    if not analyses:
        return "No matching Java files found."

    lines: list[str] = []
    for file_info in analyses:
        lines.append(">>>>" + "-"  * 20 + "FILE Analysis Result" + "-" * 20 + "<<<<")
        lines.append(f"[+] File: {file_info.path}")
        lines.append(f"      >PACKAGE: {file_info.package or '<default>'}\n")
        if file_info.imports:
            lines.append(f"      >IMPORT: {', '.join(file_info.imports)}\n")

        for class_info in file_info.classes:
            class_meta = f"    {class_info.kind} {class_info.name} (line {class_info.line})"
            if class_info.annotations:
                class_meta += f" annotations={class_info.annotations}"
            lines.append(f"  {class_meta}")

            for field_info in class_info.fields:
                field_meta = (
                    f"        Field {' '.join(field_info.modifiers)} {field_info.field_type} {field_info.name} "
                    f"(line {field_info.line})"
                )
                if field_info.annotations:
                    field_meta += f" annotations={field_info.annotations}"
                lines.append(field_meta)

            for method_info in class_info.methods:
                method_meta = (
                    f"        Method {' '.join(method_info.modifiers)} {method_info.return_type} {method_info.name}"
                    f"({', '.join(method_info.parameters)})"
                    f" (line {method_info.line})"
                )
                if method_info.annotations:
                    method_meta += f" annotations={method_info.annotations}"
                lines.append(method_meta)

                for call_info in method_info.calls:
                    if call_info.receiver:
                        lines.append(
                            f"          Call {call_info.receiver}.{call_info.name} "
                            f"(line {call_info.line})"
                        )
                    else:
                        lines.append(f"          Call {call_info.name} (line {call_info.line})")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_json(analyses: list[FileAnalysis]) -> str:
    return json.dumps(
        [asdict(file_info) for file_info in analyses],
        ensure_ascii=False,
        indent=2,
    )


def render_auth_findings_text(findings: list[AuthFinding]) -> str:
    if not findings:
        return "No common authorization or authentication logic was detected."

    sequence = 0
    lines: list[str] = []
    for finding in findings:
        sequence += 1
        lines.append(">>>>" + "-" * 20 + "AUTH Finding" + f"{sequence}" + "-" * 20 + "<<<<")
        lines.append(f"[+] Category: {finding.category} | Score: {finding.score}")
        lines.append(f"    Signature: {finding.signature}")
        lines.append(f"    Location : {finding.path}:{finding.line}")
        if finding.tags:
            lines.append(f"    Tags     : {', '.join(finding.tags)}")
        lines.append("    Evidence :")
        for evidence in finding.evidences:
            line_suffix = f" line {evidence.line}" if evidence.line is not None else ""
            lines.append(
                f"      - [+{evidence.weight}] {evidence.kind}: {evidence.detail}{line_suffix}"
            )
        lines.append("")
        
    lines.append(f"Total {len(findings)} findings.")
    return "\n".join(lines).rstrip()


def render_auth_findings_json(findings: list[AuthFinding]) -> str:
    return json.dumps(
        [asdict(finding) for finding in findings],
        ensure_ascii=False,
        indent=2,
    )
