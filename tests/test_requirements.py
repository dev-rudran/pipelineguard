"""Tests for requirement and pyproject parsing."""

from __future__ import annotations

from pathlib import Path

from pipelineguard.models import Component
from pipelineguard.scanners.deps import (
    _fallback_requirements,
    collect_components,
    dedupe_components,
    discover_manifests,
    parse_pyproject,
    parse_requirement,
    parse_requirements_file,
)
from tests.support import scan_named, write_tree


def test_exact_pin():
    component, warning = parse_requirement("requests==2.31.0", "requirements.txt")
    assert component is not None
    assert component.name == "requests"
    assert component.version == "2.31.0"
    assert component.ecosystem == "pypi"
    assert component.direct is True
    assert warning is None


def test_extras_and_marker():
    component, warning = parse_requirement(
        'requests[security,socks]==2.31.0; python_version >= "3.8"',
        "requirements.txt",
    )
    assert component is not None
    assert component.name == "requests"
    assert component.version == "2.31.0"
    assert warning is None


def test_range_constraint_produces_pin_warning():
    component, warning = parse_requirement("flask>=3.0.0", "requirements.txt")
    assert component is not None
    assert component.version == "3.0.0"
    assert warning is not None
    assert warning.rule_id == "PIPE-DEP-002"
    assert warning.severity.value == "low"
    assert "flask" in warning.message


def test_compatible_release_constraint_is_unpinned():
    component, warning = parse_requirement("django~=4.2.0", "requirements.txt")
    assert component is not None
    assert component.version == "4.2.0"
    assert warning is not None


def test_unversioned_requirement():
    component, warning = parse_requirement("flask", "requirements.txt")
    assert component is not None
    assert component.version == ""
    assert warning is not None
    assert "no version constraint" in warning.message


def test_direct_url_requirement():
    component, warning = parse_requirement(
        "demo @ https://example.com/demo-1.0.0.tar.gz", "requirements.txt"
    )
    assert component is not None
    assert component.version == ""
    assert warning is not None
    assert warning.metadata["constraint"] == "direct-url"


def test_comment_and_empty_lines_are_ignored():
    assert parse_requirement("# comment", "requirements.txt") == (None, None)
    assert parse_requirement("", "requirements.txt") == (None, None)
    assert parse_requirement("--index-url https://pypi.org/simple", "r.txt") == (None, None)


def test_recursive_requirements(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "-r requirements/base.txt\nflask==3.0.0\n",
            "requirements/base.txt": "jinja2==3.1.4\n",
        },
    )
    project = parse_requirements_file(tmp_path, "requirements.txt")
    names = {component.name for component in project.components}
    assert names == {"flask", "jinja2"}
    assert "requirements/base.txt" in project.files


def test_recursive_cycle_is_bounded(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "-r requirements.txt\nflask==3.0.0\n",
        },
    )
    project = parse_requirements_file(tmp_path, "requirements.txt")
    assert [component.name for component in project.components] == ["flask"]


def test_missing_requirements_file(tmp_path: Path):
    project = parse_requirements_file(tmp_path, "requirements.txt")
    assert project.components == []
    assert project.files == []


def test_discover_manifests(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "",
            "requirements-dev.txt": "",
            "requirements/extra.txt": "",
            "pyproject.toml": "",
            "package-lock.json": "{}",
            "Cargo.lock": "",
            "notes.txt": "",
        },
    )
    found = discover_manifests(tmp_path)
    assert "requirements.txt" in found
    assert "requirements-dev.txt" in found
    assert "requirements/extra.txt" in found
    assert "pyproject.toml" in found
    assert "package-lock.json" in found
    assert "Cargo.lock" in found
    assert "notes.txt" not in found


def test_parse_pyproject_pep621(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": """
[project]
name = "demo"
version = "1.0.0"
dependencies = ["requests==2.31.0", "flask>=3.0.0"]

[project.optional-dependencies]
dev = ["pytest==8.3.0"]
""",
        },
    )
    project = parse_pyproject(tmp_path)
    by_name = {component.name: component for component in project.components}
    assert by_name["requests"].version == "2.31.0"
    assert by_name["flask"].version == "3.0.0"
    assert by_name["pytest"].direct is True
    assert any(finding.rule_id == "PIPE-DEP-002" for finding in project.findings)


def test_parse_pyproject_poetry(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": """
[tool.poetry]
name = "demo"
version = "1.0.0"

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"
jinja2 = "3.1.4"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
""",
        },
    )
    project = parse_pyproject(tmp_path)
    by_name = {component.name: component for component in project.components}
    assert "python" not in by_name
    assert by_name["jinja2"].version == "3.1.4"
    assert by_name["requests"].version == "2.31.0"
    assert by_name["pytest"].name == "pytest"
    warnings = [finding for finding in project.findings if finding.rule_id == "PIPE-DEP-002"]
    assert len(warnings) == 2


def test_dedupe_merges_direct_and_license():
    components = [
        Component(
            ecosystem="pypi", name="Jinja2", version="3.1.4", direct=False, source="poetry.lock"
        ),
        Component(
            ecosystem="pypi",
            name="jinja2",
            version="3.1.4",
            direct=True,
            license="BSD-3-Clause",
            source="pyproject.toml",
        ),
    ]
    merged = dedupe_components(components)
    assert len(merged) == 1
    assert merged[0].direct is True
    assert merged[0].license == "BSD-3-Clause"
    assert "poetry.lock" in merged[0].source


def test_collect_components_merges_manifests(tmp_path: Path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "jinja2==3.1.4\n",
            "pyproject.toml": """
[project]
name = "demo"
version = "1.0.0"
dependencies = ["jinja2==3.1.4"]
""",
        },
    )
    project = collect_components(tmp_path)
    assert len(project.components) == 1
    assert project.files == ["pyproject.toml", "requirements.txt"]


def test_toml_fallback_extracts_dependencies():
    text = """
[project]
dependencies = [
  "requests==2.31.0",
  "flask>=3.0.0",
]
"""
    assert _fallback_requirements(text) == ["requests==2.31.0", "flask>=3.0.0"]


def test_purl_for_pypi_is_normalized():
    component = Component(ecosystem="pypi", name="My_Package", version="1.0.0")
    assert component.purl == "pkg:pypi/my-package@1.0.0"


def test_component_key_is_case_insensitive():
    left = Component(ecosystem="PyPI", name="Jinja2", version="3.1.4")
    right = Component(ecosystem="pypi", name="jinja2", version="3.1.4")
    assert left.key == right.key


def test_discover_manifests_honors_exclude_paths(tmp_path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "requests==2.31.0\n",
            "package.json": "{}\n",
            "package-lock.json": '{"lockfileVersion": 3, "packages": {}}\n',
        },
    )
    assert "requirements.txt" in discover_manifests(tmp_path)
    assert discover_manifests(tmp_path, exclude_paths=["requirements.txt"]) == ["package-lock.json"]


def test_collect_components_honors_exclude_paths(tmp_path):
    write_tree(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    assert collect_components(tmp_path).components
    project = collect_components(tmp_path, exclude_paths=["requirements*.txt"])
    assert project.components == []
    assert project.files == []


def test_dependency_scanner_reports_skipped_when_manifest_is_excluded(tmp_path):
    write_tree(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    result = scan_named("deps", tmp_path, exclude_paths=["requirements.txt"], offline=True)
    assert result.skipped is True
    assert result.skip_reason == "no supported dependency manifests found"


def test_sbom_scanner_honors_exclude_paths(tmp_path):
    write_tree(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    result = scan_named("sbom", tmp_path, exclude_paths=["requirements.txt"])
    assert result.skipped is True
    assert result.components == []
