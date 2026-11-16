"""SBOM scanner: collects components for CycloneDX output."""

from __future__ import annotations

from ..models import ScannerResult, utc_now
from .base import ScanContext, register
from .deps import collect_components


@register
class SbomScanner:
    name = "sbom"
    description = "Software bill of materials generation (CycloneDX 1.5)"

    def scan(self, context: ScanContext) -> ScannerResult:
        result = ScannerResult(scanner=self.name, started_at=utc_now())
        project = collect_components(context.root, exclude_paths=context.exclude_paths)
        result.components = project.components
        result.metadata = {
            "manifests": project.files,
            "components": len(project.components),
            "format": "CycloneDX 1.5",
        }
        if not project.files:
            result.skipped = True
            result.skip_reason = "no supported dependency manifests found"
        elif not project.components:
            result.skipped = True
            result.skip_reason = "manifests contain no resolvable components"
        return result
