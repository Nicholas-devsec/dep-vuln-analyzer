from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class Dependency:
    name: str
    version: str


@dataclass
class Vulnerability:
    package: Dependency
    cve_id: Optional[str]
    osv_id: Optional[str]
    summary: str
    affected_ranges: List[str]
    cvss_score: Optional[float]
    severity: Severity
    raw_severity: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class DependencyReport:
    dependency: Dependency
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class SummaryStats:
    total_dependencies: int = 0
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


@dataclass
class AnalysisResult:
    dependency_reports: List[DependencyReport]
    summary: SummaryStats
    metadata: Dict[str, Any] = field(default_factory=dict)

