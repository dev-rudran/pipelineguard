"""Dependency license compliance checks.

The scanner reuses the dependency parsers in :mod:`pipelineguard.scanners.deps`
so license metadata comes from the same lockfile resolution as the vulnerability
audit and the SBOM. Licenses are matched against a configurable SPDX denylist;
packages without usable license metadata can be reported as unknown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..models import Finding, ScannerResult, Severity, utc_now
from ..policy import DEFAULT_ALLOW_UNKNOWN, DEFAULT_DENY_LICENSES
from .base import ScanContext, register
from .deps import collect_components

SPDX_URL = "https://spdx.org/licenses/"
LICENSE_TOKENS = re.compile(r"\s+(?:OR|AND|WITH)\s+|[,/;]", re.IGNORECASE)
UNKNOWN_LICENSE_MARKERS = {
    "",
    "unknown",
    "none",
    "noassertion",
    "unlicensed",
    "not specified",
    "n/a",
}


@dataclass(frozen=True)
class LicenseRule:
    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    references: tuple[str, ...] = ()


LICENSE_RULES: dict[str, LicenseRule] = {
    "PIPE-LIC-001": LicenseRule(
        id="PIPE-LIC-001",
        name="Denylisted dependency license",
        severity=Severity.HIGH,
        description="A resolved dependency uses a license that the policy denies.",
        remediation=(
            "Replace or remove the dependency, obtain a compatible license, or record a "
            "time-bounded policy allowance with a documented reason."
        ),
        references=(SPDX_URL,),
    ),
    "PIPE-LIC-002": LicenseRule(
        id="PIPE-LIC-002",
        name="Unknown dependency license",
        severity=Severity.LOW,
        description="A resolved dependency has no usable license metadata.",
        remediation=(
            "Identify the upstream license, publish license metadata with the dependency, or "
            "record a time-bounded policy allowance with a documented reason."
        ),
        references=(SPDX_URL,),
    ),
}


def license_tokens(value: str | None) -> list[str]:
    """Split an SPDX expression into individual license identifiers."""
    if not value:
        return []
    cleaned = value.replace("(", " ").replace(")", " ")
    tokens: list[str] = []
    for part in LICENSE_TOKENS.split(cleaned):
        token = part.strip().strip("'\"")
        if token:
            tokens.append(token)
    return tokens


def normalize_spdx(value: str) -> str:
    """Return a case-insensitive comparison form for an SPDX identifier.

    Deprecated ``-only`` and ``-or-later`` suffixes and the legacy ``+`` form are
    folded onto the base identifier so ``GPL-3.0``, ``GPL-3.0-only`` and
    ``GPL-3.0-or-later`` share one policy entry.
    """
    token = value.strip().strip("'\"").lower()
    for suffix in ("-or-later", "-only"):
        if token.endswith(suffix):
            token = token[: -len(suffix)]
            break
    return token.rstrip("+")


def denied_license(value: str | None, deny: list[str]) -> str | None:
    """Return the configured deny entry that matches, if any."""
    denied = {normalize_spdx(item) for item in deny if item and item.strip()}
    if not denied:
        return None
    for token in license_tokens(value):
        if normalize_spdx(token) in denied:
            return token
    return None


def is_unknown_license(value: str | None) -> bool:
    """Whether a component has no usable license metadata."""
    if value is None:
        return True
    cleaned = value.strip()
    if not cleaned:
        return True
    lowered = cleaned.lower()
    if lowered.startswith("see license in"):
        return True
    tokens = license_tokens(cleaned)
    if not tokens:
        return True
    return all(token.lower() in UNKNOWN_LICENSE_MARKERS for token in tokens)


def _component_label(name: str, version: str) -> str:
    return f"{name} {version}".strip()


@register
class LicenseScanner:
    name = "licenses"
    description = "Dependency license compliance against an SPDX policy"

    def scan(self, context: ScanContext) -> ScannerResult:
        result = ScannerResult(scanner=self.name, started_at=utc_now())
        project = collect_components(context.root, exclude_paths=context.exclude_paths)
        result.components = project.components

        raw_options = context.options.get("licenses")
        options: dict[str, Any] = raw_options if isinstance(raw_options, dict) else {}
        raw_deny = options.get("deny", list(DEFAULT_DENY_LICENSES))
        if isinstance(raw_deny, list):
            deny = [str(item).strip() for item in raw_deny if str(item).strip()]
        else:
            deny = list(DEFAULT_DENY_LICENSES)
        raw_allow_unknown = options.get("allow_unknown", DEFAULT_ALLOW_UNKNOWN)
        allow_unknown = (
            raw_allow_unknown if isinstance(raw_allow_unknown, bool) else DEFAULT_ALLOW_UNKNOWN
        )

        metadata: dict[str, Any] = {
            "manifests": project.files,
            "components": len(project.components),
            "deny": deny,
            "allowUnknown": allow_unknown,
            "deniedLicenses": 0,
            "unknownLicenses": 0,
        }
        if project.warnings:
            metadata["warnings"] = project.warnings[:20]

        if not project.files:
            result.skipped = True
            result.skip_reason = "no supported dependency manifests found"
            result.metadata = metadata
            return result
        if not project.components:
            result.skipped = True
            result.skip_reason = "manifests contain no resolvable components"
            result.metadata = metadata
            return result

        for component in project.components:
            license_value = (component.license or "").strip()
            matched = denied_license(license_value, deny)
            if matched is not None:
                metadata["deniedLicenses"] += 1
                rule = LICENSE_RULES["PIPE-LIC-001"]
                label = _component_label(component.name, component.version)
                result.findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=rule.id,
                        title=rule.name,
                        severity=rule.severity,
                        message=(
                            f"{label} is licensed under {license_value}, which the license "
                            f"policy denies. {rule.remediation}"
                        ),
                        path=component.source or "requirements",
                        package=component.name,
                        version=component.version,
                        references=list(rule.references),
                        context=f"license:{component.key}:{normalize_spdx(matched)}",
                        metadata={
                            "remediation": rule.remediation,
                            "license": license_value,
                            "deniedLicense": matched,
                            "ecosystem": component.ecosystem,
                            "direct": component.direct,
                        },
                    )
                )
                continue

            if not is_unknown_license(license_value):
                continue
            metadata["unknownLicenses"] += 1
            if allow_unknown:
                continue
            rule = LICENSE_RULES["PIPE-LIC-002"]
            label = _component_label(component.name, component.version)
            result.findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=rule.id,
                    title=rule.name,
                    severity=rule.severity,
                    message=(
                        f"{label} has no usable license metadata; license compliance cannot "
                        f"be verified. {rule.remediation}"
                    ),
                    path=component.source or "requirements",
                    package=component.name,
                    version=component.version,
                    references=list(rule.references),
                    context=f"license-unknown:{component.key}",
                    metadata={
                        "remediation": rule.remediation,
                        "license": None,
                        "ecosystem": component.ecosystem,
                        "direct": component.direct,
                    },
                )
            )

        result.findings.sort(
            key=lambda item: (-item.severity.rank, item.package or "", item.rule_id)
        )
        result.metadata = metadata
        return result
