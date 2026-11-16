"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import ScanReport


def render(report: ScanReport, include_suppressed: bool = False) -> str:
    document = report.to_dict()
    if not include_suppressed:
        for scanner in document.get("scanners") or []:
            scanner["findings"] = [
                finding
                for finding in scanner.get("findings") or []
                if not finding.get("suppressed")
            ]
        document["suppressedCount"] = sum(
            1 for finding in report.findings(include_suppressed=True) if finding.suppressed
        )
    return json.dumps(document, indent=2, default=str) + "\n"


def write(report: ScanReport, path: Path, include_suppressed: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(report, include_suppressed=include_suppressed), encoding="utf-8")
    return path
