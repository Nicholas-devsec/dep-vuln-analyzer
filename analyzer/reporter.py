from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import AnalysisResult, DependencyReport, Vulnerability, Severity


def _severity_counts_line(summary) -> str:
    return (
        f"Critical: {summary.critical}  |  "
        f"High: {summary.high}  |  "
        f"Medium: {summary.medium}  |  "
        f"Low: {summary.low}"
    )


def write_json_report(result: AnalysisResult, output_path: str) -> None:
    path = Path(output_path)
    payload = {
        "summary": {
            "total_dependencies": result.summary.total_dependencies,
            "total_vulnerabilities": result.summary.total_vulnerabilities,
            "critical": result.summary.critical,
            "high": result.summary.high,
            "medium": result.summary.medium,
            "low": result.summary.low,
        },
        "dependencies": [],
        "metadata": result.metadata,
    }

    for dep_report in result.dependency_reports:
        dep_entry = {
            "name": dep_report.dependency.name,
            "version": dep_report.dependency.version,
            "vulnerabilities": [],
        }
        for vuln in dep_report.vulnerabilities:
            dep_entry["vulnerabilities"].append(
                {
                    "cve_id": vuln.cve_id,
                    "osv_id": vuln.osv_id,
                    "summary": vuln.summary,
                    "affected_ranges": vuln.affected_ranges,
                    "cvss_score": vuln.cvss_score,
                    "severity": vuln.severity.value,
                    "raw_severity": vuln.raw_severity,
                    "references": vuln.references,
                }
            )
        payload["dependencies"].append(dep_entry)

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _render_vuln_markdown(v: Vulnerability) -> str:
    cvss_str = (
        f"{v.cvss_score:.1f}"
        if v.cvss_score is not None
        else "Unknown CVSS (defaulted to Medium)"
    )
    ranges_str = ", ".join(v.affected_ranges) if v.affected_ranges else "N/A"
    refs_lines: List[str] = []
    for ref in v.references:
        refs_lines.append(f"- {ref}")
    refs_block = "\n".join(refs_lines) if refs_lines else "N/A"

    identifier = v.cve_id or v.osv_id or "N/A"

    return (
        f"**CVE / ID**: {identifier}\n"
        f"**Severity**: {v.severity.value} ({cvss_str})\n"
        f"**Affected ranges**: {ranges_str}\n"
        f"**Description**:\n\n"
        f"{v.summary}\n\n"
        f"**References**:\n{refs_block}\n"
    )


def write_markdown_report(result: AnalysisResult, output_path: str) -> None:
    path = Path(output_path)

    lines: List[str] = []
    lines.append("# Dependency Vulnerability Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Total Dependencies**: {result.summary.total_dependencies}")
    lines.append(f"**Total Vulnerabilities**: {result.summary.total_vulnerabilities}")
    lines.append(
        f"**Critical**: {result.summary.critical}  "
        f"**High**: {result.summary.high}  "
        f"**Medium**: {result.summary.medium}  "
        f"**Low**: {result.summary.low}"
    )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result.dependency_reports:
        lines.append("No dependencies were analyzed.")
    else:
        for dep_report in result.dependency_reports:
            lines.append(
                f"### {dep_report.dependency.name}=={dep_report.dependency.version}"
            )
            lines.append("")
            if not dep_report.vulnerabilities:
                lines.append("_No known vulnerabilities found for this dependency._")
                lines.append("")
                continue

            for vuln in dep_report.vulnerabilities:
                lines.append(_render_vuln_markdown(vuln))
                lines.append("---")
                lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")

