"""Secret scanning over the working tree, the git index and git history.

Design notes
------------
* Rules are regex plus optional Shannon entropy thresholds. Regex is a
  heuristic, not a proof; see the limitations section in the README.
* A match is only reported when the captured value is long enough, random
  enough and not a documented placeholder or vendor example.
* Raw secrets never leave this module. Findings carry a redacted snippet and a
  fingerprint derived from a hash of the normalized value.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from ..gitutil import (
    FileBlob,
    HistoryLine,
    history_added_lines,
    is_git_repo,
    staged_files,
    workspace_files,
)
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

RULES_FILE = "secrets_rules.yml"
MAX_MATCHES_PER_LINE = 10
MAX_HISTORY_COMMITS = 500
MAX_MERGED_COMMITS = 10


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    description: str
    severity: Severity
    patterns: tuple[re.Pattern[str], ...]
    secret_group: int = 0
    min_length: int = 12
    min_entropy: float = 0.0
    keywords: tuple[str, ...] = ()
    remediation: str = ""
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def matches_keyword(self, line: str) -> bool:
        if not self.keywords:
            return True
        lowered = line.lower()
        return any(keyword.lower() in lowered for keyword in self.keywords)

    def candidate(self, match: re.Match[str]) -> str:
        try:
            value = match.group(self.secret_group)
        except (IndexError, error_group()):  # pragma: no cover - guarded by load_rules
            value = match.group(0)
        return value.strip().strip("'\"").strip()


def error_group() -> type[Exception]:  # pragma: no cover - tiny indirection for mypy
    return IndexError


@dataclass
class RulePack:
    rules: list[SecretRule] = field(default_factory=list)
    allowlist_paths: list[str] = field(default_factory=list)
    allowlist_values: list[str] = field(default_factory=list)

    def by_id(self, rule_id: str) -> SecretRule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


def _rules_path() -> Path:
    return Path(str(resources.files("pipelineguard") / RULES_FILE))


def load_rule_pack(path: Path | None = None) -> RulePack:
    """Load and validate the bundled (or supplied) rule pack."""
    import yaml

    source = path or _rules_path()
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read secret rules from {source}: {exc}") from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in {source}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ValueError(f"{source} must contain a top-level 'rules' list")

    pack = RulePack()
    allowlist = document.get("allowlist") or {}
    if isinstance(allowlist, dict):
        pack.allowlist_paths = [str(item) for item in allowlist.get("paths") or []]
        pack.allowlist_values = [str(item) for item in allowlist.get("values") or []]

    seen: set[str] = set()
    for index, raw in enumerate(document["rules"]):
        if not isinstance(raw, dict):
            raise ValueError(f"rule #{index} is not a mapping")
        rule_id = str(raw.get("id", "")).strip()
        if not rule_id:
            raise ValueError(f"rule #{index} is missing an id")
        if rule_id in seen:
            raise ValueError(f"duplicate rule id {rule_id}")
        seen.add(rule_id)
        patterns_raw = raw.get("patterns") or ([raw["pattern"]] if "pattern" in raw else [])
        if not patterns_raw:
            raise ValueError(f"rule {rule_id} has no patterns")
        compiled: list[re.Pattern[str]] = []
        for pattern in patterns_raw:
            try:
                compiled.append(re.compile(str(pattern)))
            except re.error as exc:
                raise ValueError(f"rule {rule_id} has an invalid regex: {exc}") from exc
        group = int(raw.get("secret_group", 0))
        for pattern_obj in compiled:
            if group > pattern_obj.groups:
                raise ValueError(
                    f"rule {rule_id} selects group {group} but a pattern has only "
                    f"{pattern_obj.groups} groups"
                )
        try:
            severity = Severity.parse(str(raw.get("severity", "high")))
        except ValueError as exc:
            raise ValueError(f"rule {rule_id}: {exc}") from exc
        pack.rules.append(
            SecretRule(
                id=rule_id,
                name=str(raw.get("name") or rule_id),
                description=str(raw.get("description") or ""),
                severity=severity,
                patterns=tuple(compiled),
                secret_group=group,
                min_length=int(raw.get("min_length", 12)),
                min_entropy=float(raw.get("min_entropy", 0.0)),
                keywords=tuple(str(item) for item in raw.get("keywords") or ()),
                remediation=str(raw.get("remediation") or ""),
                references=tuple(str(item) for item in raw.get("references") or ()),
                tags=tuple(str(item) for item in raw.get("tags") or ()),
            )
        )
    return pack


def _secret_context(value: str) -> str:
    """Fingerprint context that identifies a secret without storing it."""
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return "secret:" + digest[:32]


def _path_matches(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(normalized, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(normalized, pattern[3:]):
            return True
    return False


def _should_skip(path: str, patterns: list[str], extra: list[str]) -> bool:
    return _path_matches(path, patterns) or _path_matches(path, extra)


@register
class SecretsScanner:
    name = "secrets"
    description = "Secret scanning across the working tree, git index and history"

    def __init__(self, rule_pack: RulePack | None = None) -> None:
        self._pack = rule_pack

    @property
    def pack(self) -> RulePack:
        if self._pack is None:
            self._pack = load_rule_pack()
        return self._pack

    def scan(self, context: ScanContext) -> ScannerResult:
        result = ScannerResult(scanner=self.name, started_at=utc_now())
        rules = self.pack.rules
        allowlist_paths = list(self.pack.allowlist_paths)
        allowlist_values = set(self.pack.allowlist_values)
        options = context.options.get("secrets_allowlist") or {}
        if isinstance(options, dict):
            allowlist_paths.extend(str(item) for item in options.get("paths") or [])
            allowlist_values.update(str(item) for item in options.get("values") or [])
        allowlist_paths.extend(context.exclude_paths)

        seen: dict[str, Finding] = {}
        metadata: dict[str, Any] = {
            "rules": len(rules),
            "filesScanned": 0,
            "binarySkipped": 0,
            "largeSkipped": 0,
            "excludedSkipped": 0,
        }

        if context.staged:
            self._scan_staged(
                context, result, rules, allowlist_paths, allowlist_values, seen, metadata
            )
        else:
            self._scan_workspace(
                context, result, rules, allowlist_paths, allowlist_values, seen, metadata
            )

        if context.history:
            history_meta = self._scan_history(
                context, result, rules, allowlist_paths, allowlist_values, seen
            )
            metadata.update(history_meta)

        # Stable ordering keeps reports diff-friendly.
        result.findings = sorted(
            result.findings,
            key=lambda item: (item.path, item.line or 0, item.rule_id),
        )
        metadata["findings"] = len(result.findings)
        metadata["suppressedByRule"] = _suppressed_breakdown(result)
        result.metadata = metadata
        if context.staged and not is_git_repo(context.root) and metadata.get("stagedFallback"):
            result.metadata["note"] = (
                "not a git repository; staged scan fell back to the working tree"
            )
        return result

    # -- workspace ---------------------------------------------------------

    def _scan_workspace(
        self,
        context: ScanContext,
        result: ScannerResult,
        rules: list[SecretRule],
        allowlist_paths: list[str],
        allowlist_values: set[str],
        seen: dict[str, Finding],
        metadata: dict[str, Any],
    ) -> None:
        for path in workspace_files(context.root):
            relative = safe_relpath(path, context.root)
            if _should_skip(relative, allowlist_paths, []):
                metadata["excludedSkipped"] += 1
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > context.max_file_bytes:
                metadata["largeSkipped"] += 1
                continue
            if is_probably_binary(path):
                metadata["binarySkipped"] += 1
                continue
            content = read_text(path, max_bytes=context.max_file_bytes)
            if content is None:
                metadata["binarySkipped"] += 1
                continue
            metadata["filesScanned"] += 1
            self._scan_content(
                result,
                rules,
                relative,
                content.splitlines(),
                allowlist_values,
                seen,
                context.entropy_threshold,
                mode="workspace",
            )

    def _scan_staged(
        self,
        context: ScanContext,
        result: ScannerResult,
        rules: list[SecretRule],
        allowlist_paths: list[str],
        allowlist_values: set[str],
        seen: dict[str, Finding],
        metadata: dict[str, Any],
    ) -> None:
        blobs: list[FileBlob] = staged_files(context.root)
        if not blobs and not is_git_repo(context.root):
            metadata["stagedFallback"] = True
            self._scan_workspace(
                context, result, rules, allowlist_paths, allowlist_values, seen, metadata
            )
            return
        metadata["stagedFiles"] = len(blobs)
        for blob in blobs:
            if _should_skip(blob.path, allowlist_paths, []):
                metadata["excludedSkipped"] += 1
                continue
            metadata["filesScanned"] += 1
            self._scan_content(
                result,
                rules,
                blob.path,
                blob.content.splitlines(),
                allowlist_values,
                seen,
                context.entropy_threshold,
                mode="staged",
            )

    # -- history -----------------------------------------------------------

    def _scan_history(
        self,
        context: ScanContext,
        result: ScannerResult,
        rules: list[SecretRule],
        allowlist_paths: list[str],
        allowlist_values: set[str],
        seen: dict[str, Finding],
    ) -> dict[str, Any]:
        history = history_added_lines(context.root, max_commits=MAX_HISTORY_COMMITS)
        metadata: dict[str, Any] = {
            "historyCommits": history.commits,
            "historyLines": len(history.lines),
            "historyTruncated": history.truncated,
        }
        if history.error:
            metadata["historyError"] = history.error
            return metadata

        by_key: dict[tuple[str, str, str], HistoryLine] = {}
        for line in history.lines:
            if _should_skip(line.path, allowlist_paths, []):
                continue
            key = (line.path, line.commit, line.text)
            by_key.setdefault(key, line)

        for line in by_key.values():
            self._scan_content(
                result,
                rules,
                line.path,
                [line.text],
                allowlist_values,
                seen,
                context.entropy_threshold,
                mode="history",
                line_offset=line.line - 1,
                commit=line.commit,
                author=line.author,
                date=line.date,
            )
        return metadata

    # -- shared ------------------------------------------------------------

    def _scan_content(
        self,
        result: ScannerResult,
        rules: list[SecretRule],
        path: str,
        lines: list[str],
        allowlist_values: set[str],
        seen: dict[str, Finding],
        entropy_threshold: float,
        mode: str,
        line_offset: int = 0,
        commit: str | None = None,
        author: str = "",
        date: str = "",
    ) -> None:
        for index, line in enumerate(lines):
            if not line or len(line) > 20000:
                continue
            line_number = line_offset + index + 1
            emitted = 0
            line_candidates: set[str] = set()
            for rule in rules:
                if not rule.matches_keyword(line):
                    continue
                threshold = rule.min_entropy or entropy_threshold
                for pattern in rule.patterns:
                    for match in pattern.finditer(line):
                        candidate = rule.candidate(match)
                        if candidate in line_candidates:
                            continue
                        if not self._is_candidate(rule, candidate, allowlist_values, threshold):
                            continue
                        line_candidates.add(candidate)
                        finding = self._build_finding(
                            rule,
                            path,
                            line_number,
                            line,
                            candidate,
                            commit=commit,
                            author=author,
                            date=date,
                            mode=mode,
                        )
                        if finding.fingerprint in seen:
                            self._merge_history_metadata(seen[finding.fingerprint], commit)
                            continue
                        seen[finding.fingerprint] = finding
                        result.findings.append(finding)
                        emitted += 1
                        if emitted >= MAX_MATCHES_PER_LINE:
                            break
                    if emitted >= MAX_MATCHES_PER_LINE:
                        break

    def _is_candidate(
        self,
        rule: SecretRule,
        candidate: str,
        allowlist_values: set[str],
        threshold: float,
    ) -> bool:
        if len(candidate) < rule.min_length:
            return False
        if rule.secret_group == 0 and rule.id == "PIPE-SEC-010":
            # Private key headers are identifiers, not secret values; report them
            # even though they are short and highly repetitive.
            return True
        if candidate in allowlist_values:
            return False
        if is_placeholder(candidate):
            return False
        if rule.min_entropy and normalized_entropy(candidate) < rule.min_entropy:
            return False
        return not (not rule.min_entropy and normalized_entropy(candidate) < threshold)

    def _build_finding(
        self,
        rule: SecretRule,
        path: str,
        line_number: int,
        line: str,
        candidate: str,
        commit: str | None,
        author: str,
        date: str,
        mode: str,
    ) -> Finding:
        masked = redact(candidate)
        redacted_line = line.replace(candidate, masked)
        metadata: dict[str, Any] = {
            "mode": mode,
            "entropy": round(normalized_entropy(candidate), 2),
            "valueLength": len(candidate),
            "remediation": rule.remediation,
        }
        if author:
            metadata["commitAuthor"] = author
        if date:
            metadata["commitDate"] = date
        message = f"{rule.name} detected. Redacted value: {masked}."
        return Finding(
            scanner=self.name,
            rule_id=rule.id,
            title=rule.name,
            severity=rule.severity,
            message=message,
            path=path,
            line=line_number,
            snippet=make_snippet(redacted_line),
            context=_secret_context(candidate),
            commit=commit,
            references=list(rule.references),
            metadata=metadata,
        )

    def _merge_history_metadata(self, finding: Finding, commit: str | None) -> None:
        if not commit:
            return
        commits = finding.metadata.setdefault("commits", [])
        if commit not in commits and len(commits) < MAX_MERGED_COMMITS:
            commits.append(commit)
        finding.metadata["occurrences"] = int(finding.metadata.get("occurrences", 1)) + 1


def _suppressed_breakdown(result: ScannerResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in result.findings:
        if finding.suppressed:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    return counts
