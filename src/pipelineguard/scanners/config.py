"""CI and repository configuration audit.

Covers Dockerfiles, GitHub Actions workflows and repository hygiene. Checks are
deliberately concrete: each finding maps to a documented check identifier with a
remediation. Everything here is static analysis of text or YAML; no CI job is
executed.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..gitutil import is_git_repo, is_tracked, workspace_files
from ..models import Finding, ScannerResult, Severity, utc_now
from ..util.entropy import is_placeholder, normalized_entropy
from ..util.text import (
    is_probably_binary,
    read_text,
    redact,
    safe_relpath,
)
from ..util.text import (
    snippet as make_snippet,
)
from .base import ScanContext, register


@dataclass(frozen=True)
class CheckDefinition:
    id: str
    name: str
    severity: Severity
    category: str
    description: str
    remediation: str
    references: tuple[str, ...] = ()


CONFIG_CHECKS: dict[str, CheckDefinition] = {
    "PIPE-CFG-001": CheckDefinition(
        id="PIPE-CFG-001",
        name="Container runs as root",
        severity=Severity.HIGH,
        category="dockerfile",
        description="The final stage has no USER instruction or explicitly runs as root.",
        remediation="Create an unprivileged user and switch to it with USER before the final CMD/ENTRYPOINT.",
        references=("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",),
    ),
    "PIPE-CFG-002": CheckDefinition(
        id="PIPE-CFG-002",
        name="Floating or untagged base image",
        severity=Severity.MEDIUM,
        category="dockerfile",
        description="The base image uses :latest or no tag, so builds are not reproducible.",
        remediation="Pin the base image to an explicit version and prefer an immutable digest.",
        references=("https://docs.docker.com/reference/dockerfile/#from",),
    ),
    "PIPE-CFG-003": CheckDefinition(
        id="PIPE-CFG-003",
        name="Base image is not digest pinned",
        severity=Severity.LOW,
        category="dockerfile",
        description="A tag is mutable; a digest guarantees the exact image bits.",
        remediation="Append @sha256:<digest> to the base image reference.",
        references=("https://docs.docker.com/reference/dockerfile/#from",),
    ),
    "PIPE-CFG-004": CheckDefinition(
        id="PIPE-CFG-004",
        name="ADD from a remote URL",
        severity=Severity.MEDIUM,
        category="dockerfile",
        description="ADD of a URL downloads unverified content and bypasses checksum pinning.",
        remediation="Download in a checked step with a checksum, or copy a vendored artifact with COPY.",
        references=("https://docs.docker.com/reference/dockerfile/#add",),
    ),
    "PIPE-CFG-005": CheckDefinition(
        id="PIPE-CFG-005",
        name="Secret in Dockerfile ARG or ENV",
        severity=Severity.CRITICAL,
        category="dockerfile",
        description="A credential is baked into an image layer and remains in image history.",
        remediation="Use BuildKit secrets or runtime environment injection; never bake credentials into images.",
        references=("https://docs.docker.com/build/building/secrets/",),
    ),
    "PIPE-CFG-006": CheckDefinition(
        id="PIPE-CFG-006",
        name="apt-get install without cleanup",
        severity=Severity.LOW,
        category="dockerfile",
        description="Missing --no-install-recommends or package list cleanup inflates the image.",
        remediation="Use apt-get install -y --no-install-recommends and remove /var/lib/apt/lists in the same layer.",
        references=("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",),
    ),
    "PIPE-CFG-007": CheckDefinition(
        id="PIPE-CFG-007",
        name="Remote script piped to a shell",
        severity=Severity.HIGH,
        category="dockerfile",
        description="curl or wget output is executed without integrity verification.",
        remediation="Download, verify a published checksum or signature, then execute the pinned artifact.",
        references=("https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",),
    ),
    "PIPE-CFG-008": CheckDefinition(
        id="PIPE-CFG-008",
        name="World-writable permissions",
        severity=Severity.MEDIUM,
        category="dockerfile",
        description="chmod 777 grants write access to every user in the container.",
        remediation="Grant the minimum permissions required, for example chmod 750 for binaries.",
        references=("https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",),
    ),
    "PIPE-CFG-009": CheckDefinition(
        id="PIPE-CFG-009",
        name="GitHub Action not pinned to a commit SHA",
        severity=Severity.MEDIUM,
        category="github-actions",
        description="Tags and branches are mutable; a compromised upstream tag can run arbitrary code.",
        remediation="Pin third-party actions to a full 40 character commit SHA, ideally with a version comment.",
        references=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        ),
    ),
    "PIPE-CFG-010": CheckDefinition(
        id="PIPE-CFG-010",
        name="Workflow token permissions are broad or absent",
        severity=Severity.MEDIUM,
        category="github-actions",
        description="write-all or absent top-level permissions give the workflow token more access than needed.",
        remediation="Declare a least-privilege top-level permissions block, for example contents: read.",
        references=(
            "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
        ),
    ),
    "PIPE-CFG-011": CheckDefinition(
        id="PIPE-CFG-011",
        name="pull_request_target checks out untrusted code",
        severity=Severity.CRITICAL,
        category="github-actions",
        description="pull_request_target runs with a write token and secrets; checking out PR head executes attacker code.",
        remediation="Use pull_request for untrusted code, or never check out PR head under pull_request_target.",
        references=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        ),
    ),
    "PIPE-CFG-012": CheckDefinition(
        id="PIPE-CFG-012",
        name="Expression interpolation in a run script",
        severity=Severity.HIGH,
        category="github-actions",
        description="github.event values are attacker controlled and are substituted into the shell script.",
        remediation="Pass untrusted values through env: and reference $ENV_VAR inside the script.",
        references=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable",
        ),
    ),
    "PIPE-CFG-013": CheckDefinition(
        id="PIPE-CFG-013",
        name="Secret echoed in a workflow",
        severity=Severity.HIGH,
        category="github-actions",
        description="A secret expression is printed, which leaks it into logs or build output.",
        remediation="Never echo secrets; mask values and write only non-sensitive metadata.",
        references=(
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
        ),
    ),
    "PIPE-CFG-014": CheckDefinition(
        id="PIPE-CFG-014",
        name="workflow_run executes pull request code",
        severity=Severity.HIGH,
        category="github-actions",
        description="workflow_run has secrets and a write token; checking out PR head code is equivalent to pull_request_target.",
        remediation="Do not check out PR head in workflow_run workflows; pass artifacts and treat them as untrusted.",
        references=(
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        ),
    ),
    "PIPE-CFG-015": CheckDefinition(
        id="PIPE-CFG-015",
        name="Committed environment file",
        severity=Severity.HIGH,
        category="hygiene",
        description="A .env file is present in the repository and may contain live credentials.",
        remediation="Remove the file from version control, rotate every value it contained and commit a template instead.",
        references=("https://12factor.net/config",),
    ),
    "PIPE-CFG-016": CheckDefinition(
        id="PIPE-CFG-016",
        name="Repository has no .gitignore",
        severity=Severity.MEDIUM,
        category="hygiene",
        description="Without .gitignore, local credentials and build output are easily committed.",
        remediation="Add a .gitignore that excludes environment files, caches and build artifacts.",
        references=(
            "https://docs.github.com/en/get-started/getting-started-with-git/ignoring-files",
        ),
    ),
    "PIPE-CFG-017": CheckDefinition(
        id="PIPE-CFG-017",
        name=".env is not ignored by git",
        severity=Severity.MEDIUM,
        category="hygiene",
        description="The .gitignore file does not exclude .env files, so a future secret can be committed.",
        remediation="Add .env and .env.* to .gitignore, keeping .env.example tracked.",
        references=(
            "https://docs.github.com/en/get-started/getting-started-with-git/ignoring-files",
        ),
    ),
    "PIPE-CFG-018": CheckDefinition(
        id="PIPE-CFG-018",
        name="Lockfile missing for a manifest",
        severity=Severity.MEDIUM,
        category="hygiene",
        description="A package manifest is present without a lockfile, so dependency resolution is not reproducible.",
        remediation="Commit the ecosystem lockfile and install with the locked resolution in CI.",
        references=("https://12factor.net/dependencies",),
    ),
    "PIPE-CFG-019": CheckDefinition(
        id="PIPE-CFG-019",
        name="Private key file committed",
        severity=Severity.CRITICAL,
        category="hygiene",
        description="A file contains private key material and is part of the repository.",
        remediation="Remove the key, rotate it, and store the replacement in a secret manager.",
        references=("https://csrc.nist.gov/glossary/term/private_key",),
    ),
}

DEP_RULES: dict[str, CheckDefinition] = {
    "PIPE-DEP-001": CheckDefinition(
        id="PIPE-DEP-001",
        name="Vulnerable dependency",
        severity=Severity.HIGH,
        category="dependencies",
        description="A resolved dependency version is listed in OSV with a known vulnerability.",
        remediation="Upgrade to a fixed version, remove the dependency, or document a time-bounded exception.",
        references=("https://osv.dev/",),
    ),
    "PIPE-DEP-002": CheckDefinition(
        id="PIPE-DEP-002",
        name="Unpinned dependency",
        severity=Severity.LOW,
        category="dependencies",
        description="A dependency constraint is a range or a URL, so audits cannot resolve one concrete version.",
        remediation="Pin an exact version in the manifest and let the lockfile record transitive versions.",
        references=("https://12factor.net/dependencies",),
    ),
}


CHECK_DEFINITIONS: dict[str, CheckDefinition] = {**CONFIG_CHECKS, **DEP_RULES}


def finding_from_check(
    check: CheckDefinition,
    path: str,
    message: str,
    context: str,
    line: int | None = None,
    snippet: str = "",
    severity: Severity | None = None,
    metadata: dict[str, Any] | None = None,
) -> Finding:
    payload = {"remediation": check.remediation, **(metadata or {})}
    return Finding(
        scanner="config" if check.id.startswith("PIPE-CFG") else "deps",
        rule_id=check.id,
        title=check.name,
        severity=severity or check.severity,
        message=message,
        path=path,
        line=line,
        snippet=make_snippet(snippet),
        context=context,
        references=list(check.references),
        metadata=payload,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _excluded(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(normalized, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(normalized, pattern[3:]):
            return True
    return False


def _is_dockerfile(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith("dockerfile") or name.endswith(".dockerfile")


def _is_workflow(path: Path, root: Path) -> bool:
    relative = safe_relpath(path, root).replace("\\", "/")
    return relative.startswith(".github/workflows/") and relative.endswith((".yml", ".yaml"))


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:24]


_DOCKER_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+[aA][sS]\s+(?P<stage>\S+))?\s*$",
    re.IGNORECASE,
)
_DOCKER_USER = re.compile(r"^\s*USER\s+(?P<user>\S+)", re.IGNORECASE)
_DOCKER_ADD = re.compile(r"^\s*ADD\s+(?P<source>\S+)", re.IGNORECASE)
_DOCKER_ENV = re.compile(r"^\s*(?P<kind>ARG|ENV)\s+(?P<body>.+)$", re.IGNORECASE)
_SENSITIVE_NAME = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key|auth)"
)
_CURL_PIPE = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
    re.IGNORECASE,
)
_CHMOD_777 = re.compile(r"\bchmod\s+(?:-\S+\s+)*0?777\b")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<action>[^\s#]+)")
_REFERENCE = re.compile(r"^\s*ref:\s*(?P<ref>.+?)\s*(?:#.*)?$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW_RUN_TRIGGER = re.compile(r"(?m)^\s*(?:-\s*)?(pull_request_target|workflow_run)\s*:")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


@register
class ConfigScanner:
    name = "config"
    description = "Dockerfile, GitHub Actions and repository hygiene audit"

    def scan(self, context: ScanContext) -> ScannerResult:
        result = ScannerResult(scanner=self.name, started_at=utc_now())
        metadata: dict[str, Any] = {
            "dockerfiles": 0,
            "workflows": 0,
            "filesScanned": 0,
            "workflowWarnings": [],
        }
        files = [
            path
            for path in workspace_files(context.root)
            if not _excluded(safe_relpath(path, context.root), context.exclude_paths)
        ]
        for path in files:
            relative = safe_relpath(path, context.root)
            try:
                if path.stat().st_size > context.max_file_bytes:
                    continue
            except OSError:
                continue
            if is_probably_binary(path):
                continue
            if _is_dockerfile(path):
                content = read_text(path, max_bytes=context.max_file_bytes)
                if content is None:
                    continue
                metadata["dockerfiles"] += 1
                metadata["filesScanned"] += 1
                result.findings.extend(self._audit_dockerfile(relative, content))
            elif _is_workflow(path, context.root):
                content = read_text(path, max_bytes=context.max_file_bytes)
                if content is None:
                    continue
                metadata["workflows"] += 1
                metadata["filesScanned"] += 1
                findings, warnings = self._audit_workflow(relative, content)
                result.findings.extend(findings)
                metadata["workflowWarnings"].extend(warnings)

        result.findings.extend(self._audit_hygiene(context))
        if metadata["workflowWarnings"]:
            metadata["workflowWarnings"] = metadata["workflowWarnings"][:20]
        else:
            metadata.pop("workflowWarnings")
        result.findings.sort(key=lambda item: (item.path, item.line or 0, item.rule_id))
        metadata["findings"] = len(result.findings)
        result.metadata = metadata
        return result

    # -- Dockerfile --------------------------------------------------------

    def _audit_dockerfile(self, relative: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        final_stage_line: int | None = None
        final_user: str | None = None
        has_user_line = False
        apt_cleanup = (
            "rm -rf /var/lib/apt/lists" in content or "rm -rf /var/lib/apt/lists/*" in content
        )

        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            upper = stripped.upper()
            if upper.startswith("FROM "):
                match = _DOCKER_FROM.match(line)
                if match:
                    final_stage_line = index
                    final_user = None
                    image = match.group("image")
                    findings.extend(self._check_base_image(relative, image, index, line))
            elif upper.startswith("USER "):
                match = _DOCKER_USER.match(line)
                if match:
                    final_user = match.group("user").strip().strip('"')
                    has_user_line = True
            elif upper.startswith("ADD "):
                match = _DOCKER_ADD.match(line)
                if match and re.match(r"^(?:https?://|git@|ssh://)", match.group("source")):
                    check = CONFIG_CHECKS["PIPE-CFG-004"]
                    findings.append(
                        finding_from_check(
                            check,
                            relative,
                            "ADD downloads a remote URL without checksum verification; use COPY with a verified artifact.",
                            context=f"add-remote:{match.group('source')}",
                            line=index,
                            snippet=line,
                        )
                    )
            elif upper.startswith(("ARG ", "ENV ")):
                finding = self._check_env_secret(relative, line, index)
                if finding:
                    findings.append(finding)
            elif "apt-get install" in stripped and not re.search(
                r"apt-get\s+install[^\n]*--no-install-recommends", stripped
            ):
                check = CONFIG_CHECKS["PIPE-CFG-006"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "apt-get install omits --no-install-recommends; add it to reduce image surface.",
                        context=f"apt-norecommends:{_hash_value(stripped)}",
                        line=index,
                        snippet=line,
                    )
                )
            if "apt-get install" in stripped and not apt_cleanup:
                check = CONFIG_CHECKS["PIPE-CFG-006"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "apt-get install leaves /var/lib/apt/lists in the image; remove it in the same RUN layer.",
                        context=f"apt-cleanup:{_hash_value(stripped)}",
                        line=index,
                        snippet=line,
                    )
                )
            if _CURL_PIPE.search(stripped):
                check = CONFIG_CHECKS["PIPE-CFG-007"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "A remote script is piped directly into a shell; verify a checksum or signature first.",
                        context=f"curl-pipe:{_hash_value(stripped)}",
                        line=index,
                        snippet=line,
                    )
                )
            if _CHMOD_777.search(stripped):
                check = CONFIG_CHECKS["PIPE-CFG-008"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "chmod 777 makes the path world-writable.",
                        context=f"chmod777:{_hash_value(stripped)}",
                        line=index,
                        snippet=line,
                    )
                )

        if final_stage_line is not None and (
            not has_user_line
            or final_user is None
            or final_user in {"root", "0", "0:0", "root:root"}
        ):
            check = CONFIG_CHECKS["PIPE-CFG-001"]
            findings.append(
                finding_from_check(
                    check,
                    relative,
                    "The final image stage runs as root; add an unprivileged USER before CMD or ENTRYPOINT.",
                    context="final-stage-user:root",
                    line=final_stage_line,
                    snippet=lines[final_stage_line - 1].strip(),
                )
            )
        return findings

    def _check_base_image(self, relative: str, image: str, index: int, line: str) -> list[Finding]:
        if "@sha256:" in image:
            return []
        if image == "scratch" or image.startswith("$"):
            return []
        tail = image.rsplit("/", 1)[-1]
        if ":" not in tail:
            check = CONFIG_CHECKS["PIPE-CFG-002"]
            return [
                finding_from_check(
                    check,
                    relative,
                    f"Base image {image} has no tag and resolves to latest.",
                    context=f"base-image:{image}",
                    line=index,
                    snippet=line,
                )
            ]
        tag = tail.rsplit(":", 1)[-1]
        if tag.lower() in {"latest", "edge", "master", "main"}:
            check = CONFIG_CHECKS["PIPE-CFG-002"]
            return [
                finding_from_check(
                    check,
                    relative,
                    f"Base image {image} uses the mutable tag {tag}.",
                    context=f"base-image:{image}",
                    line=index,
                    snippet=line,
                )
            ]
        check = CONFIG_CHECKS["PIPE-CFG-003"]
        return [
            finding_from_check(
                check,
                relative,
                f"Base image {image} is tag pinned but not digest pinned.",
                context=f"base-image-digest:{image}",
                line=index,
                snippet=line,
            )
        ]

    def _check_env_secret(self, relative: str, line: str, index: int) -> Finding | None:
        match = _DOCKER_ENV.match(line)
        if not match:
            return None
        kind = match.group("kind").upper()
        body = match.group("body")
        for assignment in re.split(r"\s+(?=[A-Za-z_][A-Za-z0-9_]*=)", body):
            key, separator, value = assignment.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if not separator or not value or not key:
                continue
            if value.startswith("$") or is_placeholder(value):
                continue
            sensitive = bool(_SENSITIVE_NAME.search(key))
            random_looking = len(value) >= 12 and normalized_entropy(value) >= 3.5
            if not sensitive and not random_looking:
                continue
            check = CONFIG_CHECKS["PIPE-CFG-005"]
            masked = redact(value)
            redacted_line = line.replace(value, masked)
            return finding_from_check(
                check,
                relative,
                f"{kind} bakes a credential into the image: {key}={masked}. Layers retain the value.",
                context=f"docker-secret:{key}:{_hash_value(value)}",
                line=index,
                snippet=redacted_line,
                metadata={"variable": key, "kind": kind},
            )
        return None

    # -- GitHub Actions ----------------------------------------------------

    def _audit_workflow(self, relative: str, content: str) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        warnings: list[str] = []
        lines = content.splitlines()
        document: dict[str, Any] = {}
        try:
            loaded = yaml.safe_load(content)
            if isinstance(loaded, dict):
                document = loaded
            elif loaded is not None:
                warnings.append(f"{relative}: workflow is not a mapping")
        except yaml.YAMLError as exc:
            warnings.append(f"{relative}: invalid YAML ({str(exc).splitlines()[0]})")

        triggers = _normalize_triggers(
            document.get("on") if "on" in document else document.get(True)
        )
        text_triggers = set(_WORKFLOW_RUN_TRIGGER.findall(content))
        triggers |= text_triggers

        for index, line in enumerate(lines, start=1):
            uses = _USES.match(line)
            if uses:
                action = uses.group("action").strip().strip("'\"")
                if action.startswith(("./", "docker://")):
                    continue
                finding = self._check_action_pin(relative, action, index, line)
                if finding:
                    findings.append(finding)

        permissions_finding = self._check_permissions(relative, document, content)
        if permissions_finding:
            findings.append(permissions_finding)

        if "pull_request_target" in triggers:
            finding = self._check_pull_request_target(relative, lines)
            if finding:
                findings.append(finding)

        if "workflow_run" in triggers:
            finding = self._check_workflow_run(relative, lines)
            if finding:
                findings.append(finding)

        for run_start, script_lines in _extract_run_blocks(lines):
            findings.extend(self._audit_run_block(relative, run_start, script_lines))

        return findings, warnings

    def _check_action_pin(
        self, relative: str, action: str, index: int, line: str
    ) -> Finding | None:
        name, separator, reference = action.partition("@")
        if not separator or not name or not reference:
            check = CONFIG_CHECKS["PIPE-CFG-009"]
            return finding_from_check(
                check,
                relative,
                f"Action {action} is not pinned to a commit SHA.",
                context=f"action-pin:{action}",
                line=index,
                snippet=line,
            )
        if _FULL_SHA.match(reference.lower()):
            return None
        first_party = name.startswith(("actions/", "github/"))
        severity = Severity.LOW if first_party else Severity.MEDIUM
        check = CONFIG_CHECKS["PIPE-CFG-009"]
        return finding_from_check(
            check,
            relative,
            f"Action {name} uses mutable reference {reference}; pin a full commit SHA.",
            context=f"action-pin:{action}",
            line=index,
            snippet=line,
            severity=severity,
            metadata={"action": action, "firstParty": first_party},
        )

    def _check_permissions(
        self, relative: str, document: dict[str, Any], content: str
    ) -> Finding | None:
        check = CONFIG_CHECKS["PIPE-CFG-010"]
        permissions = document.get("permissions") if document else None
        if isinstance(permissions, str) and permissions.strip().lower() == "write-all":
            line_number, line = _find_line(content, r"^\s*permissions:\s*write-all\s*$")
            return finding_from_check(
                check,
                relative,
                "The workflow requests permissions: write-all; scope the token to the minimum required.",
                context="permissions:write-all",
                line=line_number,
                snippet=line,
                severity=Severity.HIGH,
            )
        if document and "permissions" not in document:
            line_number, line = _find_line(content, r"^\s*jobs:\s*$")
            return finding_from_check(
                check,
                relative,
                "No top-level permissions block; GitHub falls back to the repository default token scope.",
                context="permissions:absent",
                line=line_number,
                snippet=line,
                severity=Severity.INFO,
            )
        if not document:
            if re.search(r"(?m)^\s*permissions:\s*write-all\s*$", content):
                line_number, line = _find_line(content, r"^\s*permissions:\s*write-all\s*$")
                return finding_from_check(
                    check,
                    relative,
                    "The workflow requests permissions: write-all; scope the token to the minimum required.",
                    context="permissions:write-all",
                    line=line_number,
                    snippet=line,
                    severity=Severity.HIGH,
                )
            if not re.search(r"(?m)^permissions\s*:", content):
                line_number, line = _find_line(content, r"^\s*jobs:\s*$")
                return finding_from_check(
                    check,
                    relative,
                    "No top-level permissions block; GitHub falls back to the repository default token scope.",
                    context="permissions:absent",
                    line=line_number,
                    snippet=line,
                    severity=Severity.INFO,
                )
        return None

    def _check_pull_request_target(self, relative: str, lines: list[str]) -> Finding | None:
        checkout_refs = _pr_head_references(lines)
        if not checkout_refs:
            return None
        check = CONFIG_CHECKS["PIPE-CFG-011"]
        line_number, ref, line = checkout_refs[0]
        return finding_from_check(
            check,
            relative,
            f"pull_request_target checks out PR controlled code via ref {ref}; this runs attacker code with secrets.",
            context=f"pr-target-checkout:{ref}",
            line=line_number,
            snippet=line,
        )

    def _check_workflow_run(self, relative: str, lines: list[str]) -> Finding | None:
        references = _pr_head_references(lines, workflow_run=True)
        if not references:
            return None
        check = CONFIG_CHECKS["PIPE-CFG-014"]
        line_number, ref, line = references[0]
        return finding_from_check(
            check,
            relative,
            f"workflow_run checks out untrusted PR code via ref {ref} with a privileged token.",
            context=f"workflow-run-checkout:{ref}",
            line=line_number,
            snippet=line,
        )

    def _audit_run_block(
        self, relative: str, run_start: int, script_lines: list[tuple[int, str]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in script_lines:
            if re.search(r"\$\{\{\s*github\.event\.", line):
                check = CONFIG_CHECKS["PIPE-CFG-012"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "github.event data is interpolated into a run script; pass it through env: instead.",
                        context=f"script-injection:{_hash_value(line.strip())}",
                        line=line_number,
                        snippet=line,
                    )
                )
            if re.search(r"\$\{\{\s*secrets\.", line) and re.search(
                r"\b(?:echo|printf|print|cat\s*<<<?|logger)\b", line
            ):
                check = CONFIG_CHECKS["PIPE-CFG-013"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "A secret expression is echoed into the workflow log.",
                        context=f"secret-echo:{_hash_value(line.strip())}",
                        line=line_number,
                        snippet=line,
                    )
                )
            if _CURL_PIPE.search(line):
                check = CONFIG_CHECKS["PIPE-CFG-007"]
                findings.append(
                    finding_from_check(
                        check,
                        relative,
                        "A remote script is piped directly into a shell; verify a checksum or signature first.",
                        context=f"curl-pipe:{_hash_value(line.strip())}",
                        line=line_number,
                        snippet=line,
                    )
                )
        return findings

    # -- repository hygiene ------------------------------------------------

    def _audit_hygiene(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        root = context.root
        git_repo = is_git_repo(root)
        gitignore = root / ".gitignore"
        gitignore_text = ""
        if gitignore.is_file():
            try:
                gitignore_text = gitignore.read_text(encoding="utf-8", errors="replace")
            except OSError:
                gitignore_text = ""

        env_files = [item for item in workspace_files(root) if _is_real_env_file(item)]
        for env_path in env_files:
            relative = safe_relpath(env_path, root)
            if _excluded(relative, context.exclude_paths):
                continue
            if git_repo and not is_tracked(root, relative):
                continue
            check = CONFIG_CHECKS["PIPE-CFG-015"]
            findings.append(
                finding_from_check(
                    check,
                    relative,
                    f"{relative} is part of the repository; environment files usually contain live credentials.",
                    context=f"committed-env:{relative}",
                )
            )

        gitignore_excluded = _excluded(".gitignore", context.exclude_paths)
        if not gitignore.is_file() and not gitignore_excluded:
            check = CONFIG_CHECKS["PIPE-CFG-016"]
            findings.append(
                finding_from_check(
                    check,
                    ".gitignore",
                    "No .gitignore file; environment files and build output can be committed accidentally.",
                    context="gitignore:missing",
                )
            )
        elif gitignore.is_file() and not gitignore_excluded:
            patterns = _gitignore_env_patterns(gitignore_text)
            if not patterns:
                check = CONFIG_CHECKS["PIPE-CFG-017"]
                findings.append(
                    finding_from_check(
                        check,
                        ".gitignore",
                        ".gitignore does not exclude .env files.",
                        context="gitignore:env-missing",
                    )
                )

        for manifest, lockfiles in _LOCKFILE_REQUIREMENTS.items():
            if _excluded(manifest, context.exclude_paths):
                continue
            if not (root / manifest).is_file():
                continue
            if not any((root / lockfile).is_file() for lockfile in lockfiles):
                check = CONFIG_CHECKS["PIPE-CFG-018"]
                findings.append(
                    finding_from_check(
                        check,
                        manifest,
                        f"{manifest} is present but no lockfile ({', '.join(lockfiles)}) was found.",
                        context=f"lockfile-missing:{manifest}",
                    )
                )

        findings.extend(self._audit_key_files(context))
        return findings

    def _audit_key_files(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in workspace_files(context.root):
            relative = safe_relpath(path, context.root)
            if _excluded(relative, context.exclude_paths):
                continue
            name = path.name.lower()
            candidate = (
                name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
                or name.endswith((".pem", ".key", ".p12", ".pfx"))
                or "/.ssh/" in f"/{relative}"
            )
            if not candidate or name.endswith(".pub"):
                continue
            try:
                if path.stat().st_size > context.max_file_bytes:
                    continue
                head = path.read_bytes()[:4096]
            except OSError:
                continue
            if b"PRIVATE KEY" not in head and name not in {
                "id_rsa",
                "id_dsa",
                "id_ecdsa",
                "id_ed25519",
            }:
                continue
            check = CONFIG_CHECKS["PIPE-CFG-019"]
            findings.append(
                finding_from_check(
                    check,
                    relative,
                    f"{relative} appears to contain private key material.",
                    context=f"private-key:{relative}",
                    metadata={"file": relative},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Workflow helpers
# ---------------------------------------------------------------------------


def _normalize_triggers(value: Any) -> set[str]:
    triggers: set[str] = set()
    if isinstance(value, str):
        triggers.add(value)
    elif isinstance(value, list):
        triggers.update(str(item) for item in value)
    elif isinstance(value, dict):
        triggers.update(str(key) for key in value)
    return triggers


def _extract_run_blocks(lines: list[str]) -> list[tuple[int, list[tuple[int, str]]]]:
    blocks: list[tuple[int, list[tuple[int, str]]]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(?P<indent>\s*)(?:-\s*)?run:\s*(?P<value>.*)$", line)
        if not match:
            index += 1
            continue
        indent = len(match.group("indent"))
        value = match.group("value").strip()
        collected: list[tuple[int, str]] = []
        if value in {"|", ">", "|-", ">-", "|+", ">+"} or not value:
            cursor = index + 1
            while cursor < len(lines):
                candidate = lines[cursor]
                if not candidate.strip():
                    cursor += 1
                    continue
                candidate_indent = len(candidate) - len(candidate.lstrip())
                if candidate_indent <= indent:
                    break
                collected.append((cursor + 1, candidate))
                cursor += 1
            index = cursor
        else:
            collected.append((index + 1, value))
            index += 1
        if collected:
            blocks.append((index, collected))
    return blocks


def _pr_head_references(lines: list[str], workflow_run: bool = False) -> list[tuple[int, str, str]]:
    references: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines, start=1):
        match = _REFERENCE.match(line)
        if not match:
            continue
        ref = match.group("ref").strip().strip("'\"")
        lowered = ref.lower()
        if workflow_run:
            if "github.event.workflow_run.head" in lowered:
                references.append((index, ref, line))
        elif (
            "github.event.pull_request.head" in lowered
            or "github.head_ref" in lowered
            or "refs/pull/" in lowered
        ):
            references.append((index, ref, line))
    # Also catch manual checkout commands inside run scripts.
    for index, line in enumerate(lines, start=1):
        lowered = line.lower()
        if "git checkout" not in lowered:
            continue
        if any(
            token in lowered
            for token in (
                "github.event.pull_request.head",
                "github.head_ref",
                "refs/pull/",
            )
        ):
            references.append((index, line.strip(), line))
        if workflow_run and "github.event.workflow_run.head" in lowered:
            references.append((index, line.strip(), line))
    return references


def _find_line(content: str, pattern: str) -> tuple[int | None, str]:
    regex = re.compile(pattern)
    for index, line in enumerate(content.splitlines(), start=1):
        if regex.search(line):
            return index, line.strip()
    return None, ""


# ---------------------------------------------------------------------------
# Hygiene helpers
# ---------------------------------------------------------------------------


def _is_real_env_file(path: Path) -> bool:
    name = path.name.lower()
    if name != ".env" and not name.startswith(".env."):
        return False
    return name not in {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.test",
        ".env.ci",
    }


def _gitignore_env_patterns(text: str) -> list[str]:
    patterns: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        cleaned = line.lstrip("/")
        if cleaned in {
            ".env",
            ".env*",
            "*.env",
            ".env.*",
            "**/.env",
            "/.env",
            "env",
        } or fnmatch.fnmatch(".env", cleaned):
            patterns.append(line)
    return patterns


_LOCKFILE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "requirements.txt"),
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"),
    "Cargo.toml": ("Cargo.lock",),
    "go.mod": ("go.sum",),
}
