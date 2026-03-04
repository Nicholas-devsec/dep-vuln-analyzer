## dep-vuln-analyzer

`dep-vuln-analyzer` is a lightweight, Python-based dependency vulnerability analysis tool.
It simulates core Software Composition Analysis (SCA) behavior by reading a `requirements.txt`,
querying the public OSV vulnerability database, and producing both machine-readable and
human-friendly reports. The project is structured to look and feel like a realistic
security engineering utility suitable for CI/CD pipelines.

---

### Reasons for building tool

- **Supply chain risk**: Modern applications depend heavily on third‑party libraries. A single
  vulnerable package can compromise an entire system.
- **SCA simulation**: This tool demonstrates how commercial SCA products work at a basic level:
  dependency enumeration, vulnerability lookups, risk classification, and reporting.
- **Security engineering mindset**: The code emphasizes clean architecture, defensive parsing,
  graceful failure modes, and CI integration – all core to product security work.

---

### Architecture overview

High-level module layout:

```text
                       +-----------------------+
                       |      main.py CLI      |
                       |  - arg parsing        |
                       |  - orchestrates flow  |
                       +-----------+-----------+
                                   |
                                   v
                        +----------+-----------+
                        |       analyzer       |
                        |  (Python package)    |
                        +----------+-----------+
                                   |
        +--------------------------+--------------------------+
        |                          |                          |
        v                          v                          v
+---------------+        +----------------+        +------------------+
| parser.py     |        | osv_client.py  |        | reporter.py       |
| - read &      |        | - OSV API      |        | - JSON report     |
|   validate    |        |   queries      |        | - Markdown report |
|   requirements|        | - retry,       |        |   generation      |
|               |        |   timeouts     |        +------------------+
+-------+-------+        +--------+-------+
        |                         |
        v                         v
 +------+--------+        +-------+--------+
 | models.py     |        | classifier.py  |
 | - dataclasses |        | - CVSS ->      |
 |   (deps,      |        |   severity     |
 |   vulns,      |        |   mapping      |
 |   summary)    |        +----------------+
 +---------------+
```

---

### Core features

- **Input**: Accepts a `requirements.txt` file with exact version pins (`package==version`).
- **OSV integration**: Uses the OSV API (`https://api.osv.dev/v1/query`) to look up
  known vulnerabilities per dependency and version.
- **Risk classification**:
  - Critical: CVSS ≥ 9.0
  - High: 7.0–8.9
  - Medium: 4.0–6.9
  - Low: < 4.0
  - Missing CVSS scores default to **Medium** and are clearly marked as unknown.
- **Output formats**:
  - Console summary (optionally with rich, colored tables if `rich` is installed).
  - JSON report for downstream automation.
  - Markdown remediation report for human review and ticketing.
- **CI-friendly**:
  - Non-zero exit code when critical vulnerabilities are found.
  - GitHub Actions workflow included for PR scanning.

---

### Installation and setup

**Prerequisites**

- Python **3.11+**
- Network access to `https://api.osv.dev`

**Install dependencies**

```bash
cd /home/admin1/Desktop/python_daily/project_17
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

### How to run locally

Scan a requirements file and generate reports:

```bash
python main.py --file sample_requirements.txt --output report.json
```

Flags:

- **`--file` / `-f`**: Path to the `requirements.txt` file to analyze.
- **`--output` / `-o`**: Path where the JSON report will be written.
- **`--md-output`**: Optional explicit path for the Markdown report.
  - If omitted, the tool will write `<output>.md` next to the JSON report.

Example:

```bash
python main.py \
  --file sample_requirements.txt \
  --output out/dep-report.json \
  --md-output out/dep-report.md
```

The command will:

- Parse dependencies from `sample_requirements.txt`.
- Query OSV for each `name==version`.
- Classify vulnerabilities by severity using CVSS when available.
- Print a summarized view to the console.
- Write:
  - `out/dep-report.json`
  - `out/dep-report.md`

---

### Example console output

With `rich` installed, a typical run might look like:

```text
──────────────── Dependency Vulnerability Summary ────────────────

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric               ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total dependencies   │ 3     │
│ Total vulnerabilities│ 5     │
│ Critical             │ 1     │
│ High                 │ 2     │
│ Medium               │ 2     │
│ Low                  │ 0     │
└──────────────────────┴───────┘
```

---

### Example JSON output (excerpt)

```json
{
  "summary": {
    "total_dependencies": 3,
    "total_vulnerabilities": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "dependencies": [
    {
      "name": "django",
      "version": "3.2.0",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2021-XXXX",
          "osv_id": "PYSEC-2021-YYY",
          "summary": "Example vulnerability summary...",
          "affected_ranges": ["type=ECOSYSTEM, introduced=3.0.0, fixed=3.2.2"],
          "cvss_score": 8.1,
          "severity": "High",
          "raw_severity": "CVSS:3.1/AV:N/...",
          "references": ["https://example.com/advisory"]
        }
      ]
    }
  ],
  "metadata": {
    "source": "OSV",
    "ecosystem": "PyPI"
  }
}
```

---

### Example Markdown remediation report (excerpt)

```markdown
# Dependency Vulnerability Report

## Summary

**Total Dependencies**: 3  
**Total Vulnerabilities**: 5  
**Critical**: 1  **High**: 2  **Medium**: 2  **Low**: 0

## Findings

### django==3.2.0

**CVE / ID**: CVE-2021-XXXX  
**Severity**: High (8.1)  
**Affected ranges**: type=ECOSYSTEM, introduced=3.0.0, fixed=3.2.2  
**Description**:

Example vulnerability summary...

**References**:
- https://example.com/advisory
```

---

### CI/CD integration (GitHub Actions)

A GitHub Actions workflow is provided at `.github/workflows/scan.yml`.
It:

- Triggers on `pull_request`.
- Sets up Python and installs dependencies.
- Runs `dep-vuln-analyzer` against a requirements file.
- Fails the workflow if the tool exits with a non-zero code.
  - This includes the case where **critical vulnerabilities are found**, enforcing
    a policy gate in CI.

Key behavior:

- **Exit code 1 if any Critical vulnerabilities** are discovered.
- Exit code 1 on parsing errors or OSV communication issues.

In a real deployment, the JSON and Markdown reports could be:

- Uploaded as CI artifacts.
- Parsed to create tickets or comments.
- Consumed by additional quality gates or dashboards.

---

### Security engineering considerations

- **Defensive parsing**:
  - Only accepts simple `package==version` lines.
  - Any unsupported syntax results in a clear `RequirementsParserError`.
- **API robustness**:
  - Explicit timeouts on HTTP calls.
  - Basic retry logic with exponential backoff for transient network/5xx errors.
  - Simple handling of HTTP 429 (rate limiting) with retries.
- **Error handling**:
  - Clean, explicit error messages for missing files, parse errors, and API issues.
  - On a per-dependency basis, OSV failures do not crash the entire scan.
- **No secrets**:
  - The OSV API is unauthenticated; no keys or secrets are required or stored. Keeps the .gitignore file pretty minimial :)

---

### Future improvements

- **NVD integration**:
  - Enrich OSV findings with NVD metadata (CWEs, more detailed CVSS, configuration info).
- **SBOM support**:
  - Accept SPDX or CycloneDX SBOMs as input, not just `requirements.txt`.
- **CI/CD Security Gate**:
  - All custom policy set so user can select to fail pipeline not only on criticals
- **Parallel API queries**:
  - Use concurrent HTTP calls for large dependency trees while respecting OSV rate limits.
- **Docker containerization**:
  - Provide a container image for consistent execution in CI and local environments.

---

### Notes

This project is intentionally minimal but structured like a production tool:

- Modular Python package with clear separation of concerns.
- Type hints and dataclasses for clarity and maintainability.
- Clean CLI interface designed for both humans and CI systems.



