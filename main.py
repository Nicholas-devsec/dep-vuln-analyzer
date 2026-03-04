from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

try:
    from rich.console import Console
    from rich.table import Table
except Exception:  # pragma: no cover - optional dependency
    Console = None
    Table = None

from analyzer.classifier import classify_severity_from_cvss
from analyzer.models import (
    AnalysisResult,
    DependencyReport,
    SummaryStats,
    Vulnerability,
)
from analyzer.osv_client import OSVClient, extract_vulns_from_osv_response, OSVClientError
from analyzer.parser import parse_requirements, RequirementsParserError
from analyzer.reporter import write_json_report, write_markdown_report


def analyze(requirements_file: str) -> AnalysisResult:
    dependencies = parse_requirements(requirements_file)
    client = OSVClient()

    dep_reports: List[DependencyReport] = []
    summary = SummaryStats(total_dependencies=len(dependencies))

    for dep in dependencies:
        try:
            resp = client.query(dep.name, dep.version)
        except OSVClientError as exc:
            # On API failure we keep going but record no vulnerabilities for this dep.
            # In a real tool we might surface this more prominently.
            dep_reports.append(DependencyReport(dependency=dep, vulnerabilities=[]))
            continue

        vulns_raw = extract_vulns_from_osv_response(resp)
        vulns: List[Vulnerability] = []
        for v in vulns_raw:
            cve_id = None
            if isinstance(v.get("aliases"), list):
                for alias in v["aliases"]:
                    if isinstance(alias, str) and alias.startswith("CVE-"):
                        cve_id = alias
                        break

            osv_id = v.get("id")
            summary_text = v.get("summary") or v.get("details") or "No summary provided."

            affected_ranges: List[str] = []
            for affected in v.get("affected") or []:
                if not isinstance(affected, dict):
                    continue
                for r in affected.get("ranges") or []:
                    if not isinstance(r, dict):
                        continue
                    t = r.get("type")
                    if t == "ECOSYSTEM":
                        fixed = (
                            ", ".join(r.get("fixed") or [])
                            if isinstance(r.get("fixed"), list)
                            else r.get("fixed") or ""
                        )
                        introduced = (
                            ", ".join(r.get("introduced") or [])
                            if isinstance(r.get("introduced"), list)
                            else r.get("introduced") or ""
                        )
                        desc = f"type={t}, introduced={introduced}, fixed={fixed}"
                    else:
                        desc = str(r)
                    affected_ranges.append(desc)

            cvss_score = None
            raw_severity = None
            for sev in v.get("severity") or []:
                if not isinstance(sev, dict):
                    continue
                raw_type = sev.get("type")
                if raw_type and raw_type.upper().startswith("CVSS"):
                    raw_score = sev.get("score")
                    raw_severity = str(raw_score)
                    try:
                        cvss_score = float(str(raw_score).split("/")[0])
                    except (TypeError, ValueError):
                        cvss_score = None
                    break

            severity = classify_severity_from_cvss(cvss_score)

            references: List[str] = []
            for ref in v.get("references") or []:
                if not isinstance(ref, dict):
                    continue
                url = ref.get("url")
                if isinstance(url, str):
                    references.append(url)

            vuln = Vulnerability(
                package=dep,
                cve_id=cve_id,
                osv_id=osv_id,
                summary=summary_text,
                affected_ranges=affected_ranges,
                cvss_score=cvss_score,
                severity=severity,
                raw_severity=raw_severity,
                references=references,
            )
            vulns.append(vuln)

            summary.total_vulnerabilities += 1
            if severity.value == "Critical":
                summary.critical += 1
            elif severity.value == "High":
                summary.high += 1
            elif severity.value == "Medium":
                summary.medium += 1
            else:
                summary.low += 1

        dep_reports.append(DependencyReport(dependency=dep, vulnerabilities=vulns))

    return AnalysisResult(
        dependency_reports=dep_reports,
        summary=summary,
        metadata={"source": "OSV", "ecosystem": "PyPI"},
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lightweight dependency vulnerability analyzer (OSV-based)."
    )
    parser.add_argument(
        "--file",
        "-f",
        required=True,
        help="Path to requirements.txt to scan.",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Path to JSON report file to write.",
    )
    parser.add_argument(
        "--md-output",
        help="Optional path to Markdown report file. "
        "Defaults to <output>.md if not specified.",
    )
    return parser


def _print_console_summary(result: AnalysisResult) -> None:
    if Console is None or Table is None:
        print("Dependency Vulnerability Summary")
        print("--------------------------------")
        print(f"Total dependencies: {result.summary.total_dependencies}")
        print(f"Total vulnerabilities: {result.summary.total_vulnerabilities}")
        print(f"Critical: {result.summary.critical}")
        print(f"High: {result.summary.high}")
        print(f"Medium: {result.summary.medium}")
        print(f"Low: {result.summary.low}")
        return

    console = Console()
    console.rule("[bold red]Dependency Vulnerability Summary[/bold red]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metric")
    table.add_column("Count", justify="right")

    table.add_row("Total dependencies", str(result.summary.total_dependencies))
    table.add_row("Total vulnerabilities", str(result.summary.total_vulnerabilities))
    table.add_row("Critical", str(result.summary.critical))
    table.add_row("High", str(result.summary.high))
    table.add_row("Medium", str(result.summary.medium))
    table.add_row("Low", str(result.summary.low))

    console.print(table)


def main(argv: List[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    req_path = Path(args.file)
    if not req_path.is_file():
        parser.error(f"Requirements file not found: {req_path}")

    try:
        result = analyze(str(req_path))
    except RequirementsParserError as exc:
        print(f"Error parsing requirements file: {exc}", file=sys.stderr)
        return 1
    except OSVClientError as exc:
        print(f"Error communicating with OSV API: {exc}", file=sys.stderr)
        return 1

    _print_console_summary(result)

    json_output = args.output
    md_output = args.md_output or (args.output + ".md")

    try:
        write_json_report(result, json_output)
        write_markdown_report(result, md_output)
    except OSError as exc:
        print(f"Failed to write report(s): {exc}", file=sys.stderr)
        return 1

    # Exit code 1 if any critical vulnerabilities (for CI integration).
    if result.summary.critical > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

