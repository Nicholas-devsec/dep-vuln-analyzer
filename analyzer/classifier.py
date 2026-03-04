from __future__ import annotations

from typing import Optional

from .models import Severity


def classify_severity_from_cvss(score: Optional[float]) -> Severity:
    """
    Map a CVSS score to a coarse severity band.

    If the score is None (missing) we default to MEDIUM but that should be
    marked to the user as "Unknown CVSS" by higher layers.
    """
    if score is None:
        return Severity.MEDIUM

    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW

