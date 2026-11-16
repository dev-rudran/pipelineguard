"""Dependency inventory and OSV vulnerability auditing.

Supported inputs: requirements.txt (recursive), pyproject.toml (PEP 621 and
Poetry), poetry.lock, package-lock.json v1/v2/v3, yarn.lock, pnpm-lock.yaml,
go.sum and Cargo.lock.

Network access is limited to the OSV batch API, one host, POST only, with a
10 second timeout, a single retry and an on-disk cache. ``--offline`` disables
all network calls and can use a local OSV advisory file instead.
"""

from __future__ import annotations

import fnmatch
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Component, Finding, ScannerResult, Severity, utc_now
from .base import ScanContext, register

OSV_API = "https://api.osv.dev/v1/querybatch"
OSV_CHUNK_SIZE = 100
OSV_TIMEOUT = 10.0
OSV_RETRIES = 1
CACHE_TTL = 24 * 60 * 60
MAX_LOCKFILE_BYTES = 32 * 1024 * 1024

ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
}
OSV_TO_ECOSYSTEM = {value.lower(): key for key, value in ECOSYSTEM_MAP.items()}
OSV_TO_ECOSYSTEM["crates.io"] = "cargo"

LOCKFILES = (
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "Cargo.lock",
)


class OSVError(RuntimeError):
    """Raised when the OSV API cannot be used or returns malformed data."""


@dataclass
class ParsedProject:
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_component(self, component: Component) -> None:
        self.components.append(component)

    def extend(self, other: ParsedProject) -> None:
        self.components.extend(other.components)
        self.findings.extend(other.findings)
        self.files.extend(other.files)
        self.warnings.extend(other.warnings)


# ---------------------------------------------------------------------------
# Requirement parsing
# ---------------------------------------------------------------------------

_REQUIREMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[(?P<extras>[^\]]*)\])?\s*"
    r"(?P<spec>(?:===|==|~=|>=|<=|>|<|!=)\s*[^,;\s]+)?\s*"
    r"(?:;\s*(?P<marker>.+))?$"
)
_DIRECT_URL_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s*(?P<url>\S+)\s*(?:;\s*(?P<marker>.+))?$"
)
_SPEC_RE = re.compile(r"^(===|==|~=|>=|<=|>|<|!=)\s*(.+)$")
_EXACT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")


def parse_requirement(
    text: str,
    source: str,
    direct: bool = True,
) -> tuple[Component | None, Finding | None]:
    """Parse a single PEP 508 requirement into a component and optional warning."""
    raw = text.split(" #", 1)[0].strip()
    if not raw or raw.startswith("#"):
        return None, None
    if raw.startswith("-"):
        return None, None
    if " @ " in raw or re.search(r"\]\s*@\s*", raw):
        match = _DIRECT_URL_RE.match(raw)
        if not match:
            return None, None
        name = match.group("name")
        component = Component(
            ecosystem="pypi",
            name=name,
            version="",
            direct=direct,
            source=source,
        )
        warning = Finding(
            scanner="deps",
            rule_id="PIPE-DEP-002",
            title="Unversioned direct URL dependency",
            severity=Severity.LOW,
            message=(
                f"{name} is installed from a direct URL without an exact version; "
                "SBOM and vulnerability data cannot be resolved."
            ),
            path=source,
            snippet=raw,
            context=f"url:{name}:{match.group('url')}",
            metadata={"package": name, "constraint": "direct-url"},
        )
        return component, warning

    match = _REQUIREMENT_RE.match(raw)
    if not match:
        return None, None
    name = match.group("name")
    spec = (match.group("spec") or "").replace(" ", "")
    version, pinned, constraint = _version_from_spec(spec)
    if version is None:
        component = Component(ecosystem="pypi", name=name, version="", direct=direct, source=source)
        warning = Finding(
            scanner="deps",
            rule_id="PIPE-DEP-002",
            title="Unpinned dependency",
            severity=Severity.LOW,
            message=f"{name} has no version constraint; audits and SBOMs need an exact pin.",
            path=source,
            snippet=raw,
            context=f"unpinned:{name}",
            metadata={"package": name, "constraint": spec or "none"},
        )
        return component, warning

    component = Component(
        ecosystem="pypi",
        name=name,
        version=version,
        direct=direct,
        source=source,
        license=None,
    )
    if not pinned:
        warning = Finding(
            scanner="deps",
            rule_id="PIPE-DEP-002",
            title="Unpinned dependency constraint",
            severity=Severity.LOW,
            message=(
                f"{name} is declared as {constraint}; builds can resolve different versions. "
                f"Pin an exact version (currently lower-bounded by {version})."
            ),
            path=source,
            snippet=raw,
            context=f"constraint:{name}:{constraint}",
            metadata={
                "package": name,
                "constraint": constraint,
                "minimumVersion": version,
                "extras": _split_extras(match.group("extras")),
                "marker": (match.group("marker") or "").strip(),
            },
        )
        return component, warning
    return component, None


def _split_extras(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _version_from_spec(spec: str) -> tuple[str | None, bool, str]:
    if not spec:
        return None, False, ""
    match = _SPEC_RE.match(spec)
    if not match:
        return None, False, spec
    operator, version = match.group(1), match.group(2).strip()
    if operator == "===":
        return version, True, spec
    if operator == "==":
        if version.endswith(".*") or "*" in version:
            return version.rstrip(".*"), False, spec
        if _EXACT_VERSION.match(version):
            return version, True, spec
        return None, False, spec
    if operator == "~=":
        base = version.split(",")[0]
        return base, False, spec
    return version, False, spec


def _normalize_poetry_constraint(value: str) -> str:
    """Turn a Poetry constraint into a minimum version plus a display spec."""
    cleaned = value.strip().strip('"')
    if not cleaned or cleaned == "*":
        return ""
    if cleaned[0] in "^~" and len(cleaned) > 1:
        return ">=" + cleaned[1:]
    if cleaned[0].isdigit():
        return "==" + cleaned
    return cleaned


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_requirements_file(
    root: Path, relative: str, seen: set[str] | None = None
) -> ParsedProject:
    project = ParsedProject()
    seen = seen if seen is not None else set()
    normalized = str(relative).replace("\\", "/")
    if normalized in seen:
        return project
    seen.add(normalized)
    path = root / normalized
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    project.files.append(normalized)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("-r ", "--requirement ")):
            nested = stripped.split(maxsplit=1)[1].strip()
            nested_path = (path.parent / nested).resolve()
            try:
                nested_rel = nested_path.relative_to(root.resolve()).as_posix()
            except ValueError:
                project.warnings.append(f"requirements include outside the repository: {nested}")
                continue
            project.extend(parse_requirements_file(root, nested_rel, seen))
            continue
        if stripped.startswith(("-c ", "--constraint ")):
            project.warnings.append(f"constraint file not audited: {stripped}")
            continue
        if stripped.startswith("--"):
            continue
        component, warning = parse_requirement(stripped, normalized)
        if component:
            project.add_component(component)
        if warning:
            project.findings.append(warning)
    return project


def parse_pyproject(root: Path, relative: str = "pyproject.toml") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    project.files.append(relative)
    document = _load_toml(text)
    if document is None:
        for requirement in _fallback_requirements(text):
            component, warning = parse_requirement(requirement, relative)
            if component:
                component.source = relative
                project.add_component(component)
            if warning:
                project.findings.append(warning)
        return project

    project_table = document.get("project") or {}
    if isinstance(project_table, dict):
        for requirement in project_table.get("dependencies") or []:
            component, warning = parse_requirement(str(requirement), relative)
            if component:
                project.add_component(component)
            if warning:
                project.findings.append(warning)
        optional = project_table.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for _group, requirements in optional.items():
                for requirement in requirements or []:
                    component, warning = parse_requirement(str(requirement), relative)
                    if component:
                        component.direct = True
                        project.add_component(component)
                    if warning:
                        project.findings.append(warning)

    tool = document.get("tool") or {}
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        for section_name in ("dependencies", "dev-dependencies"):
            section = poetry.get(section_name)
            if isinstance(section, dict):
                _add_poetry_dependencies(project, section, relative, section_name)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for group_name, group in groups.items():
                if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                    _add_poetry_dependencies(
                        project,
                        group["dependencies"],
                        relative,
                        f"group:{group_name}",
                    )
    return project


def _add_poetry_dependencies(
    project: ParsedProject,
    section: dict[str, Any],
    relative: str,
    section_name: str,
) -> None:
    for name, specification in section.items():
        if str(name).lower() == "python":
            continue
        if isinstance(specification, dict):
            value = str(specification.get("version") or "")
            optional = bool(specification.get("optional"))
            if not value and specification.get("git"):
                component = Component(ecosystem="pypi", name=name, version="", source=relative)
                project.add_component(component)
                continue
        else:
            value = str(specification)
            optional = False
        constraint = _normalize_poetry_constraint(value)
        component, warning = parse_requirement(
            f"{name}{constraint}" if constraint else name,
            relative,
            direct=not optional,
        )
        if component:
            project.add_component(component)
        if warning:
            warning.metadata["section"] = section_name
            project.findings.append(warning)


def parse_poetry_lock(root: Path, relative: str = "poetry.lock") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    project.files.append(relative)
    document = _load_toml(text)
    packages: list[dict[str, Any]] = []
    if document is not None:
        raw_packages = document.get("package") or []
        packages = [item for item in raw_packages if isinstance(item, dict)]
    else:
        packages = _fallback_toml_packages(text)
    for package in packages:
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip()
        if not name or not version:
            continue
        project.add_component(
            Component(
                ecosystem="pypi",
                name=name,
                version=version,
                direct=False,
                source=relative,
            )
        )
    return project


def parse_package_lock(root: Path, relative: str = "package-lock.json") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return project
    if not isinstance(document, dict):
        return project
    project.files.append(relative)
    direct_names = _package_json_direct_names(root)
    if isinstance(document.get("packages"), dict):
        root_package = document["packages"].get("") or {}
        if isinstance(root_package, dict):
            for section in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                values = root_package.get(section) or {}
                if isinstance(values, dict):
                    direct_names.update(str(name) for name in values)
        for key, entry in document["packages"].items():
            if not key or not isinstance(entry, dict):
                continue
            if entry.get("link"):
                continue
            name = _name_from_node_modules(str(key))
            if not name:
                continue
            version = str(entry.get("version") or "").strip()
            if not version:
                continue
            project.add_component(
                Component(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    direct=name in direct_names and str(key).count("node_modules/") == 1,
                    license=_license_name(entry.get("license")),
                    source=relative,
                )
            )
    elif isinstance(document.get("dependencies"), dict):
        _walk_npm_v1(project, document["dependencies"], relative, direct_names, depth=1)
    return project


def _walk_npm_v1(
    project: ParsedProject,
    dependencies: dict[str, Any],
    relative: str,
    direct_names: set[str],
    depth: int,
) -> None:
    for name, entry in dependencies.items():
        if not isinstance(entry, dict):
            continue
        version = str(entry.get("version") or "").strip()
        if version:
            project.add_component(
                Component(
                    ecosystem="npm",
                    name=name,
                    version=version,
                    direct=name in direct_names and depth == 1,
                    license=_license_name(entry.get("license")),
                    source=relative,
                )
            )
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_npm_v1(project, nested, relative, direct_names, depth + 1)


def _name_from_node_modules(key: str) -> str:
    normalized = key.replace("\\", "/")
    marker = "node_modules/"
    if normalized.endswith("node_modules"):
        return ""
    if marker not in normalized:
        return ""
    tail = normalized.rsplit(marker, 1)[-1]
    parts = tail.split("/")
    if tail.startswith("@") and len(parts) >= 2:
        return "/".join(parts[:2])
    return parts[0]


def parse_yarn_lock(root: Path, relative: str = "yarn.lock") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    project.files.append(relative)
    direct_names = _package_json_direct_names(root)
    block: list[str] = []
    blocks: list[list[str]] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t", "#")):
            if block:
                blocks.append(block)
            block = [line]
        elif block:
            block.append(line)
    if block:
        blocks.append(block)

    for lines in blocks:
        header = lines[0].strip().rstrip(":")
        if header.startswith("__") or header == "__metadata":
            continue
        first_spec = header.split(",")[0].strip().strip('"')
        version = ""
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.startswith("version"):
                candidate = (
                    stripped.split(":", 1)[-1] if ":" in stripped else stripped.split(" ", 1)[-1]
                )
                version = candidate.strip().strip('"')
                break
        name = _npm_name_from_spec(first_spec)
        if not name or not version:
            continue
        project.add_component(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                direct=name in direct_names,
                source=relative,
            )
        )
    return project


def _npm_name_from_spec(spec: str) -> str:
    cleaned = spec.strip().strip('"')
    if cleaned.startswith("@"):
        first = cleaned.find("@", 1)
        return cleaned[:first] if first > 0 else cleaned
    return cleaned.split("@", 1)[0]


def parse_pnpm_lock(root: Path, relative: str = "pnpm-lock.yaml") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    import yaml

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        project.warnings.append(f"could not parse {relative}")
        return project
    if not isinstance(document, dict):
        return project
    project.files.append(relative)
    direct_names: set[str] = set()
    importers = document.get("importers")
    if isinstance(importers, dict):
        root_importer = importers.get(".") or {}
        if isinstance(root_importer, dict):
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                values = root_importer.get(section)
                if isinstance(values, dict):
                    direct_names.update(str(name) for name in values)
    else:
        direct_names = _package_json_direct_names(root)

    packages = document.get("packages")
    if not isinstance(packages, dict):
        return project
    for key, entry in packages.items():
        parsed = _parse_pnpm_key(str(key))
        if parsed is None:
            continue
        name, version = parsed
        if not version:
            continue
        license_value = entry.get("license") if isinstance(entry, dict) else None
        project.add_component(
            Component(
                ecosystem="npm",
                name=name,
                version=version,
                direct=name in direct_names,
                license=_license_name(license_value),
                source=relative,
            )
        )
    return project


def _parse_pnpm_key(key: str) -> tuple[str, str] | None:
    cleaned = key.strip().lstrip("/")
    if not cleaned:
        return None
    cleaned = cleaned.split("(", 1)[0]
    if cleaned.startswith("@"):
        scope, _, remainder = cleaned.partition("/")
        if not remainder:
            return None
        if "@" in remainder:
            name_part, version = remainder.rsplit("@", 1)
            return f"{scope}/{name_part}", version
        pieces = remainder.rsplit("/", 1)
        return (f"{scope}/{pieces[0]}", pieces[1]) if len(pieces) == 2 else None
    if "@" in cleaned:
        name, version = cleaned.rsplit("@", 1)
        return (name, version) if name else None
    pieces = cleaned.rsplit("/", 1)
    if len(pieces) == 2:
        return pieces[0], pieces[1]
    return None


def parse_go_sum(root: Path, relative: str = "go.sum") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    project.files.append(relative)
    direct_names = _go_mod_direct_names(root)
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        if not name or not version or (name, version) in seen:
            continue
        seen.add((name, version))
        project.add_component(
            Component(
                ecosystem="golang",
                name=name,
                version=version,
                direct=name in direct_names,
                source=relative,
            )
        )
    return project


def parse_cargo_lock(root: Path, relative: str = "Cargo.lock") -> ParsedProject:
    project = ParsedProject()
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return project
    project.files.append(relative)
    document = _load_toml(text)
    direct_names = _cargo_direct_names(root)
    packages: list[dict[str, Any]] = []
    if document is not None:
        raw_packages = document.get("package") or []
        packages = [item for item in raw_packages if isinstance(item, dict)]
    else:
        packages = _fallback_toml_packages(text)
    for package in packages:
        name = str(package.get("name") or "").strip()
        version = str(package.get("version") or "").strip()
        if not name or not version:
            continue
        local = not package.get("source")
        project.add_component(
            Component(
                ecosystem="cargo",
                name=name,
                version=version,
                direct=name in direct_names or local,
                source=relative,
            )
        )
    return project


# ---------------------------------------------------------------------------
# Manifest direct-dependency helpers
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _package_json_direct_names(root: Path) -> set[str]:
    document = _read_json(root / "package.json")
    names: set[str] = set()
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = document.get(section)
        if isinstance(values, dict):
            names.update(str(name) for name in values)
    return names


def _go_mod_direct_names(root: Path) -> set[str]:
    try:
        text = (root / "go.mod").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    names: set[str] = set()
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block and stripped:
            names.add(stripped.split()[0])
        elif stripped.startswith("require "):
            names.add(stripped.split()[1])
    return names


def _cargo_direct_names(root: Path) -> set[str]:
    try:
        text = (root / "Cargo.toml").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    document = _load_toml(text)
    names: set[str] = set()
    if document is not None:
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            values = document.get(section)
            if isinstance(values, dict):
                names.update(str(name) for name in values)
        workspace = document.get("workspace") or {}
        if isinstance(workspace, dict) and isinstance(workspace.get("dependencies"), dict):
            names.update(str(name) for name in workspace["dependencies"])
        return names
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=", line)
        if match and "dependencies" in text[: text.find(line)][-200:]:
            names.add(match.group(1))
    return names


# ---------------------------------------------------------------------------
# TOML compatibility (Python 3.10 has no tomllib)
# ---------------------------------------------------------------------------


def _load_toml(text: str) -> dict[str, Any] | None:
    try:
        import tomllib
    except ImportError:  # Python 3.10
        try:
            import tomli as tomllib
        except ImportError:
            return None
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def _fallback_requirements(text: str) -> list[str]:
    """Extract PEP 621 and Poetry dependency strings without tomllib (3.10)."""
    requirements: list[str] = []
    for match in re.finditer(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text):
        body = match.group(1)
        for item in re.findall(r'"([^"\n]+)"|\'([^\'\n]+)\'', body):
            value = item[0] or item[1]
            if value:
                requirements.append(value)
    for match in re.finditer(r"(?m)^\s*([A-Za-z0-9_.-]+)\s*=\s*\"([^\"\n]+)\"\s*$", text):
        key, value = match.group(1), match.group(2)
        if key in {"name", "version", "description", "license", "python"}:
            continue
        if any(operator in value for operator in ("^", "~", ">", "<", "=", "*")):
            requirements.append(f"{key}{_normalize_poetry_constraint(value)}")
    return requirements


def _fallback_toml_packages(text: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        section = block.split("\n[", 1)[0]
        name_match = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', section)
        version_match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', section)
        source_match = re.search(r'(?m)^\s*source\s*=\s*"([^"]*)"', section)
        if name_match and version_match:
            packages.append(
                {
                    "name": name_match.group(1),
                    "version": version_match.group(1),
                    "source": source_match.group(1) if source_match else None,
                }
            )
    return packages


def _license_name(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("type", "name", "id"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return None


# ---------------------------------------------------------------------------
# Component collection
# ---------------------------------------------------------------------------


def discover_manifests(root: Path, exclude_paths: list[str] | None = None) -> list[str]:
    found: list[str] = []
    for name in LOCKFILES:
        if (root / name).is_file():
            found.append(name)
    for candidate in sorted(root.glob("requirements*.txt")):
        relative = candidate.name
        if relative not in found:
            found.append(relative)
    requirements_dir = root / "requirements"
    if requirements_dir.is_dir():
        for candidate in sorted(requirements_dir.glob("*.txt")):
            found.append(candidate.relative_to(root).as_posix())
    if exclude_paths:
        found = [item for item in found if not _path_excluded(item, exclude_paths)]
    return found


def _path_excluded(relative: str, patterns: list[str]) -> bool:
    normalized = relative.replace("\\", "/")
    for pattern in patterns:
        candidate = pattern.replace("\\", "/")
        if fnmatch.fnmatch(normalized, candidate):
            return True
        if candidate.startswith("**/") and fnmatch.fnmatch(normalized, candidate[3:]):
            return True
        if normalized == candidate:
            return True
    return False


def collect_components(root: Path, exclude_paths: list[str] | None = None) -> ParsedProject:
    """Parse every supported manifest, deduplicate and merge metadata."""
    project = ParsedProject()
    for relative in discover_manifests(root, exclude_paths=exclude_paths):
        lower = relative.lower()
        if lower.endswith("requirements.txt") or (
            lower.startswith("requirements") and lower.endswith(".txt")
        ):
            project.extend(parse_requirements_file(root, relative))
        elif relative == "pyproject.toml":
            project.extend(parse_pyproject(root, relative))
        elif relative == "poetry.lock":
            project.extend(parse_poetry_lock(root, relative))
        elif relative == "package-lock.json":
            project.extend(parse_package_lock(root, relative))
        elif relative == "yarn.lock":
            project.extend(parse_yarn_lock(root, relative))
        elif relative == "pnpm-lock.yaml":
            project.extend(parse_pnpm_lock(root, relative))
        elif relative == "go.sum":
            project.extend(parse_go_sum(root, relative))
        elif relative == "Cargo.lock":
            project.extend(parse_cargo_lock(root, relative))
    project.components = dedupe_components(project.components)
    project.findings = _dedupe_findings(project.findings)
    project.files = sorted(dict.fromkeys(project.files))
    return project


def dedupe_components(components: Iterable[Component]) -> list[Component]:
    merged: dict[str, Component] = {}
    for component in components:
        if not component.name:
            continue
        key = component.key
        existing = merged.get(key)
        if existing is None:
            merged[key] = component
            continue
        existing.direct = existing.direct or component.direct
        if not existing.license and component.license:
            existing.license = component.license
        if component.source and component.source not in existing.source:
            existing.source = (
                f"{existing.source},{component.source}" if existing.source else component.source
            )
    return sorted(
        merged.values(),
        key=lambda item: (item.ecosystem, item.name.lower(), _version_key(item.version)),
    )


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_VERSION_PART = re.compile(r"(\d+)|([A-Za-z]+)")


def _version_key(version: str) -> tuple[Any, ...]:
    parts: list[Any] = []
    for match in _VERSION_PART.finditer(version.lstrip("vV")):
        token = match.group(0).lower()
        if token.isdigit():
            parts.append((1, int(token)))
        else:
            parts.append((0, token))
    return tuple(parts)


def compare_versions(left: str, right: str) -> int:
    left_key, right_key = _version_key(left), _version_key(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def version_in_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None = None,
) -> bool:
    if introduced and introduced != "0" and compare_versions(version, introduced) < 0:
        return False
    if fixed and compare_versions(version, fixed) >= 0:
        return False
    return not (last_affected and compare_versions(version, last_affected) > 0)


# ---------------------------------------------------------------------------
# OSV client
# ---------------------------------------------------------------------------


class OSVCache:
    """TTL cache keyed by ``ecosystem:name:version``."""

    def __init__(self, path: Path, ttl: int = CACHE_TTL) -> None:
        self.path = path
        self.ttl = ttl
        self._entries: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        entries = document.get("entries") if isinstance(document, dict) else None
        if isinstance(entries, dict):
            self._entries = {
                str(key): value for key, value in entries.items() if isinstance(value, dict)
            }

    def get(self, key: str) -> list[dict[str, Any]] | None:
        entry = self._entries.get(key)
        if not entry:
            return None
        fetched = entry.get("fetched")
        if not isinstance(fetched, (int, float)) or time.time() - fetched > self.ttl:
            return None
        vulns = entry.get("vulns")
        return vulns if isinstance(vulns, list) else None

    def put(self, key: str, vulns: list[dict[str, Any]]) -> None:
        self._entries[key] = {"fetched": time.time(), "vulns": vulns}
        self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps({"version": 1, "entries": self._entries}, indent=2),
                encoding="utf-8",
            )
            temporary.replace(self.path)
            self._dirty = False
        except OSError:
            return


def cache_key(component: Component) -> str:
    return f"{component.ecosystem}:{component.name}:{component.version}".lower()


def _osv_ecosystem(ecosystem: str) -> str:
    return ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)


def _post_json(url: str, payload: dict[str, Any], timeout: float = OSV_TIMEOUT) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "pipelineguard/0.1.0",
        },
    )
    # The URL is a module constant pinned to the OSV API; no user input reaches it.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        if response.status and response.status >= 400:
            raise OSVError(f"OSV returned HTTP {response.status}")
        data = response.read(8 * 1024 * 1024)
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OSVError("OSV returned malformed JSON") from exc
    if not isinstance(document, dict):
        raise OSVError("OSV returned an unexpected payload")
    return document


def query_osv(
    components: list[Component],
    chunks: int = OSV_CHUNK_SIZE,
    timeout: float = OSV_TIMEOUT,
) -> dict[str, list[dict[str, Any]]]:
    """Query OSV for components and return results keyed by cache key."""
    results: dict[str, list[dict[str, Any]]] = {}
    for start in range(0, len(components), chunks):
        batch = components[start : start + chunks]
        payload = {
            "queries": [
                {
                    "package": {"ecosystem": _osv_ecosystem(item.ecosystem), "name": item.name},
                    "version": item.version,
                }
                for item in batch
            ]
        }
        response: dict[str, Any] | None = None
        last_error: Exception | None = None
        for attempt in range(OSV_RETRIES + 1):
            try:
                response = _post_json(OSV_API, payload, timeout=timeout)
                break
            except (urllib.error.URLError, TimeoutError, OSError, OSVError) as exc:
                last_error = exc
                if attempt < OSV_RETRIES:
                    continue
        if response is None:
            raise OSVError(f"OSV request failed: {last_error}") from last_error
        raw_results = response.get("results")
        if not isinstance(raw_results, list) or len(raw_results) != len(batch):
            raise OSVError("OSV response did not match the query batch size")
        for component, item in zip(batch, raw_results, strict=False):
            if not isinstance(item, dict):
                raise OSVError("OSV result entry is not an object")
            vulns = item.get("vulns") or []
            if not isinstance(vulns, list):
                raise OSVError("OSV vulns entry is not a list")
            results[cache_key(component)] = [vuln for vuln in vulns if isinstance(vuln, dict)]
    return results


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def parse_cvss_v3(vector: str) -> float | None:
    """Compute a CVSS v3 base score from a vector string."""
    values: dict[str, str] = {}
    for part in vector.strip().split("/")[1:]:
        key, _, value = part.partition(":")
        values[key.upper()] = value.upper()
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[values["AV"]]
        ac = {"L": 0.77, "H": 0.44}[values["AC"]]
        ui = {"N": 0.85, "R": 0.62}[values["UI"]]
        scope_changed = values["S"] == "C"
        if scope_changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[values["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[values["PR"]]
        confidentiality = {"H": 0.56, "L": 0.22, "N": 0.0}[values["C"]]
        integrity = {"H": 0.56, "L": 0.22, "N": 0.0}[values["I"]]
        availability = {"H": 0.56, "L": 0.22, "N": 0.0}[values["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    score = min(impact + exploitability, 10.0)
    return _roundup(score)


def _roundup(value: float) -> float:
    import math

    integer = int(value * 100000)
    return integer / 100000.0 if integer % 10000 == 0 else (math.floor(integer / 10000) + 1) / 10.0


def score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def osv_severity(vulnerability: dict[str, Any]) -> Severity:
    database_specific = vulnerability.get("database_specific") or {}
    if isinstance(database_specific, dict):
        label = str(database_specific.get("severity") or "").strip().lower()
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "moderate": Severity.MEDIUM,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        if label in mapping:
            return mapping[label]
    severities = vulnerability.get("severity") or []
    if isinstance(severities, list):
        best: Severity | None = None
        for entry in severities:
            if not isinstance(entry, dict):
                continue
            raw = str(entry.get("score") or "").strip()
            score: float | None = None
            if raw.upper().startswith("CVSS:3"):
                score = parse_cvss_v3(raw)
            elif raw.upper().startswith("CVSS:4"):
                score = None
            else:
                try:
                    score = float(raw)
                except ValueError:
                    score = None
            if score is None:
                continue
            severity = score_to_severity(score)
            if best is None or severity.rank > best.rank:
                best = severity
        if best is not None:
            return best
    return Severity.MEDIUM


def fixed_versions(vulnerability: dict[str, Any], component: Component) -> list[str]:
    ecosystem = _osv_ecosystem(component.ecosystem).lower()
    fixed: list[str] = []
    affected = vulnerability.get("affected") or []
    if not isinstance(affected, list):
        return fixed
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict):
            continue
        if str(package.get("ecosystem") or "").lower() != ecosystem:
            continue
        if str(package.get("name") or "").lower() != component.name.lower():
            continue
        ranges = entry.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for range_entry in ranges:
            if not isinstance(range_entry, dict):
                continue
            for event in range_entry.get("events") or []:
                if not isinstance(event, dict) or "fixed" not in event:
                    continue
                candidate = str(event["fixed"])
                if compare_versions(candidate, component.version) > 0:
                    fixed.append(candidate)
    return sorted(set(fixed), key=_version_key)


def vulnerability_matches(vulnerability: dict[str, Any], component: Component) -> bool:
    """Match a local advisory entry against an installed version."""
    ecosystem = _osv_ecosystem(component.ecosystem).lower()
    affected = vulnerability.get("affected") or []
    if not isinstance(affected, list):
        return False
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict):
            continue
        if str(package.get("ecosystem") or "").lower() != ecosystem:
            continue
        if str(package.get("name") or "").lower() != component.name.lower():
            continue
        versions = entry.get("versions")
        if (
            isinstance(versions, list)
            and versions
            and any(str(value) == component.version for value in versions)
        ):
            return True
        for range_entry in entry.get("ranges") or []:
            if not isinstance(range_entry, dict):
                continue
            introduced = None
            fixed = None
            last_affected = None
            for event in range_entry.get("events") or []:
                if not isinstance(event, dict):
                    continue
                if "introduced" in event:
                    introduced = str(event["introduced"])
                if "fixed" in event:
                    fixed = str(event["fixed"])
                if "last_affected" in event:
                    last_affected = str(event["last_affected"])
            if version_in_range(component.version, introduced, fixed, last_affected):
                return True
    return False


# ---------------------------------------------------------------------------
# Offline advisory database
# ---------------------------------------------------------------------------


def load_advisory_db(path: Path) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise OSVError(f"cannot read advisory database {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise OSVError(f"advisory database {path} is not valid JSON: {exc}") from exc
    if isinstance(document, dict):
        vulns = document.get("vulns")
    elif isinstance(document, list):
        vulns = document
    else:
        vulns = None
    if not isinstance(vulns, list):
        raise OSVError(f"advisory database {path} must contain a 'vulns' list")
    return [item for item in vulns if isinstance(item, dict)]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def vulnerability_finding(
    vulnerability: dict[str, Any],
    component: Component,
) -> Finding:
    vuln_id = str(vulnerability.get("id") or "OSV-UNKNOWN")
    aliases = [str(alias) for alias in vulnerability.get("aliases") or [] if isinstance(alias, str)]
    summary = str(vulnerability.get("summary") or vulnerability.get("details") or "").strip()
    summary = summary.splitlines()[0][:300] if summary else "Known vulnerability"
    fixed = fixed_versions(vulnerability, component)
    fixed_version = fixed[0] if fixed else None
    references = [
        str(item.get("url"))
        for item in vulnerability.get("references") or []
        if isinstance(item, dict) and item.get("url")
    ][:10]
    label = aliases[0] if aliases else vuln_id
    message = f"{component.name} {component.version} is affected by {label}: {summary}"
    if fixed_version:
        message += f" Upgrade to {fixed_version} or later."
    else:
        message += " No fixed version is published; consider removing or isolating the dependency."
    return Finding(
        scanner="deps",
        rule_id="PIPE-DEP-001",
        title=f"Vulnerable dependency {component.name} ({label})",
        severity=osv_severity(vulnerability),
        message=message,
        path=component.source or "requirements",
        package=component.name,
        version=component.version,
        fixed_version=fixed_version,
        aliases=aliases,
        references=references,
        context=f"vuln:{component.key}:{vuln_id}",
        metadata={
            "vulnId": vuln_id,
            "summary": summary,
            "ecosystem": component.ecosystem,
            "direct": component.direct,
            "fixedVersions": fixed,
            "source": "osv",
        },
    )


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


@register
class DependencyScanner:
    name = "deps"
    description = "Dependency CVE audit against the OSV database"

    def scan(self, context: ScanContext) -> ScannerResult:
        result = ScannerResult(scanner=self.name, started_at=utc_now())
        project = collect_components(context.root, exclude_paths=context.exclude_paths)
        result.components = project.components
        result.findings.extend(project.findings)
        metadata: dict[str, Any] = {
            "manifests": project.files,
            "components": len(project.components),
            "direct": sum(1 for item in project.components if item.direct),
            "offline": context.offline,
        }
        if project.warnings:
            metadata["warnings"] = project.warnings[:20]

        components = [
            item for item in project.components if item.version and item.ecosystem in ECOSYSTEM_MAP
        ]
        if not project.files:
            result.skipped = True
            result.skip_reason = "no supported dependency manifests found"
            result.metadata = metadata
            return result

        advisory_db: list[dict[str, Any]] | None = None
        if context.advisory_db is not None:
            advisory_db = load_advisory_db(context.advisory_db)
            metadata["advisoryDb"] = str(context.advisory_db)

        cache = OSVCache(
            context.resolved_cache_dir / "osv.json",
            ttl=int(context.options.get("cache_ttl", CACHE_TTL)),
        )
        results: dict[str, list[dict[str, Any]]] = {}
        cache_hits = 0
        pending: list[Component] = []

        for component in components:
            key = cache_key(component)
            cached = cache.get(key)
            if cached is not None:
                results[key] = cached
                cache_hits += 1
            else:
                pending.append(component)

        if advisory_db is not None:
            metadata["auditSource"] = "advisory-db"
            for component in components:
                key = cache_key(component)
                results[key] = [
                    vuln for vuln in advisory_db if vulnerability_matches(vuln, component)
                ]
        elif context.offline:
            metadata["auditSource"] = "cache" if cache_hits else "none"
            if not cache_hits:
                metadata["note"] = (
                    "offline mode without an advisory database: packages inventoried, "
                    "no vulnerability lookup performed"
                )
            for component in pending:
                results[cache_key(component)] = []
        else:
            metadata["auditSource"] = "osv"
            try:
                fetched = query_osv(
                    pending, timeout=float(context.options.get("osv_timeout", OSV_TIMEOUT))
                )
                for component in pending:
                    key = cache_key(component)
                    vulns = fetched.get(key, [])
                    results[key] = vulns
                    cache.put(key, vulns)
                cache.save()
            except OSVError as exc:
                metadata["osvError"] = str(exc)
                metadata["auditSource"] = "cache-partial"
                for component in pending:
                    results.setdefault(cache_key(component), [])

        seen: set[str] = set()
        for component in components:
            for vulnerability in results.get(cache_key(component), []):
                finding = vulnerability_finding(vulnerability, component)
                if finding.fingerprint in seen:
                    continue
                seen.add(finding.fingerprint)
                result.findings.append(finding)

        metadata["cacheHits"] = cache_hits
        metadata["vulnerabilities"] = sum(
            1 for finding in result.findings if finding.rule_id == "PIPE-DEP-001"
        )
        result.findings.sort(
            key=lambda item: (
                -item.severity.rank,
                item.package or "",
                item.rule_id,
            )
        )
        result.metadata = metadata
        return result
