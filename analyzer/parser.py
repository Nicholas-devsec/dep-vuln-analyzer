from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from .models import Dependency

_REQ_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.\-]+)\s*==\s*(?P<version>[A-Za-z0-9_.\-]+)\s*$"
)


class RequirementsParserError(Exception):
    """Raised when the requirements file cannot be parsed safely."""


def _iter_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")


def parse_requirements(path_str: str) -> List[Dependency]:
    """
    Parse a minimal `requirements.txt` style file.

    Only supports exact pins in the form `package==version`.
    Lines that are empty or start with `#` are ignored.
    Any other unsupported directive will raise `RequirementsParserError`
    to avoid mis-scanning.
    """
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"Requirements file not found: {path}")

    dependencies: List[Dependency] = []
    unsupported_lines: List[str] = []

    for raw in _iter_lines(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        match = _REQ_LINE_RE.match(line)
        if not match:
            unsupported_lines.append(line)
            continue

        dependencies.append(
            Dependency(
                name=match.group("name"),
                version=match.group("version"),
            )
        )

    if unsupported_lines:
        raise RequirementsParserError(
            "Unsupported requirement line(s) encountered: "
            + "; ".join(unsupported_lines)
        )

    return dependencies

