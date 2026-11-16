"""Configuration scanner tests for Dockerfiles, workflows and repository hygiene."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipelineguard.scanners.base import ScanContext
from pipelineguard.scanners.config import ConfigScanner
from tests.support import commit_all, git, make_git_repo, scan_named, write_tree

GITIGNORE = "node_modules/\n.env\n"
PINNED_ACTION = "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3"


def scan(root: Path):
    return scan_named("config", root)


def ids(result) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def test_full_dockerfile_triggers_expected_checks(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM ubuntu:latest
ARG API_KEY=Tr0ub4dor&3xK9mQ2
ENV DB_PASSWORD=Tr0ub4dor&3xK9mQ2
ADD https://example.com/tools.tar.gz /tmp/tools.tar.gz
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.com/install.sh | sh
RUN chmod 777 /app
CMD ["app"]
""",
        },
    )
    result = scan(tmp_path)
    found = set(ids(result))
    assert result.error is None
    assert {
        "PIPE-CFG-001",
        "PIPE-CFG-002",
        "PIPE-CFG-004",
        "PIPE-CFG-005",
        "PIPE-CFG-006",
        "PIPE-CFG-007",
        "PIPE-CFG-008",
    } <= found
    assert result.metadata["dockerfiles"] == 1
    by_id = {finding.rule_id: finding for finding in result.findings}
    assert by_id["PIPE-CFG-005"].severity.value == "critical"
    assert "Tr0ub4dor" not in by_id["PIPE-CFG-005"].snippet
    assert by_id["PIPE-CFG-001"].line == 2


def test_clean_dockerfile_has_no_findings(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM debian:12.5-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
RUN useradd --create-home app
USER app
COPY app /app
CMD ["/app"]
""",
        },
    )
    result = scan(tmp_path)
    assert result.findings == []
    assert result.metadata["dockerfiles"] == 1


def test_floating_and_untagged_base_images_are_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM ubuntu
USER app
""",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-002" in ids(result)
    assert "PIPE-CFG-003" not in ids(result)


def test_tag_pinned_base_image_reports_missing_digest(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM registry.example.com:5000/ubuntu:22.04
USER app
""",
        },
    )
    result = scan(tmp_path)
    assert ids(result) == ["PIPE-CFG-003"]


@pytest.mark.parametrize("image", ["scratch", "$BASE_IMAGE"])
def test_base_image_special_cases(tmp_path, image):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": f"FROM {image}\nUSER app\n",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-002" not in ids(result)
    assert "PIPE-CFG-003" not in ids(result)


@pytest.mark.parametrize("image", ["ubuntu:edge", "ubuntu:main", "ubuntu:latest"])
def test_floating_tags_are_reported(tmp_path, image):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": f"FROM {image}\nUSER app\n",
        },
    )
    result = scan(tmp_path)
    assert ids(result) == ["PIPE-CFG-002"]


def test_root_user_is_reported_for_final_stage_only(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM ubuntu:22.04 AS builder
USER root
FROM ubuntu:22.04
USER app
USER root
""",
        },
    )
    result = scan(tmp_path)
    root_findings = [item for item in result.findings if item.rule_id == "PIPE-CFG-001"]
    assert len(root_findings) == 1
    assert root_findings[0].line == 4


def test_and_wget_pipe_are_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM ubuntu:22.04
USER app
RUN wget -qO- https://example.com/install.sh | sudo bash
""",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-007" in ids(result)


def test_non_secret_env_is_ignored(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": """
FROM ubuntu:22.04
USER app
ENV PORT=8080
ENV API_URL=${API_URL}
""",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-005" not in ids(result)


def test_workflow_checks_cover_pins_permissions_and_injection(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            ".github/workflows/ci.yml": """
name: ci
on:
  pull_request_target:
  workflow_run:
    workflows: [build]
    types: [completed]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: example/third-party@v1
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.event.workflow_run.head_branch }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: echo "${{ secrets.DEPLOY_TOKEN }}"
      - run: curl -fsSL https://example.com/install.sh | bash
""",
        },
    )
    result = scan(tmp_path)
    found = set(ids(result))
    assert {
        "PIPE-CFG-007",
        "PIPE-CFG-009",
        "PIPE-CFG-010",
        "PIPE-CFG-011",
        "PIPE-CFG-012",
        "PIPE-CFG-013",
        "PIPE-CFG-014",
    } <= found
    assert result.metadata["workflows"] == 1
    permissions = [item for item in result.findings if item.rule_id == "PIPE-CFG-010"]
    assert len(permissions) == 1
    assert permissions[0].severity.value == "high"
    pins = [item for item in result.findings if item.rule_id == "PIPE-CFG-009"]
    assert any(item.metadata["firstParty"] for item in pins)
    assert any(item.severity.value == "medium" for item in pins)


def test_clean_workflow_has_no_findings(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            ".github/workflows/ci.yml": f"""
name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {PINNED_ACTION}
      - run: python -m pytest
""",
        },
    )
    result = scan(tmp_path)
    assert result.findings == []


def test_missing_permissions_block_is_informational(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            ".github/workflows/ci.yml": f"""
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {PINNED_ACTION}
      - run: echo ok
""",
        },
    )
    result = scan(tmp_path)
    permissions = [item for item in result.findings if item.rule_id == "PIPE-CFG-010"]
    assert len(permissions) == 1
    assert permissions[0].severity.value == "info"


def test_invalid_workflow_yaml_is_a_warning_and_falls_back_to_text(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            ".github/workflows/broken.yml": """
on: [push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""",
        },
    )
    result = scan(tmp_path)
    assert result.error is None
    assert result.metadata["workflowWarnings"]
    assert "PIPE-CFG-010" in ids(result)


def test_missing_gitignore_is_reported(tmp_path):
    write_tree(tmp_path, {"README.md": "# demo\n"})
    result = scan(tmp_path)
    assert ids(result) == ["PIPE-CFG-016"]


def test_gitignore_without_env_pattern_is_reported(tmp_path):
    write_tree(tmp_path, {".gitignore": "node_modules/\ndist/\n"})
    result = scan(tmp_path)
    assert ids(result) == ["PIPE-CFG-017"]


@pytest.mark.parametrize("pattern", [".env", ".env*", "*.env", "**/.env", "/.env"])
def test_gitignore_env_patterns_are_accepted(tmp_path, pattern):
    write_tree(tmp_path, {".gitignore": pattern + "\n"})
    result = scan(tmp_path)
    assert "PIPE-CFG-017" not in ids(result)


def test_committed_env_file_is_reported_outside_git(tmp_path):
    write_tree(tmp_path, {".gitignore": GITIGNORE, ".env": "TOKEN=abc\n"})
    result = scan(tmp_path)
    assert "PIPE-CFG-015" in ids(result)


def test_env_example_is_not_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            ".env.example": "TOKEN=replace-me\n",
            ".env.sample": "TOKEN=replace-me\n",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-015" not in ids(result)


def test_env_file_is_ignored_when_untracked_in_git(tmp_path):
    write_tree(tmp_path, {".gitignore": GITIGNORE, "README.md": "# demo\n"})
    make_git_repo(tmp_path)
    commit_all(tmp_path)
    write_tree(tmp_path, {".env": "TOKEN=abc\n"})
    result = scan(tmp_path)
    assert "PIPE-CFG-015" not in ids(result)


def test_env_file_is_reported_when_tracked(tmp_path):
    write_tree(tmp_path, {".env": "TOKEN=abc\n"})
    make_git_repo(tmp_path)
    git(tmp_path, "add", "-f", ".env")
    git(tmp_path, "commit", "-q", "-m", "commit env")
    result = scan(tmp_path)
    assert "PIPE-CFG-015" in ids(result)


def test_missing_lockfile_is_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "pyproject.toml": '[project]\nname = "demo"\n',
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-018" in ids(result)


def test_lockfile_present_is_accepted(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "pyproject.toml": '[project]\nname = "demo"\n',
            "requirements.txt": "requests==2.31.0\n",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-018" not in ids(result)


@pytest.mark.parametrize("name", ["id_rsa", "server.pem", "deploy.key"])
def test_private_key_material_is_reported(tmp_path, name):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            name: "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-019" in ids(result)


def test_public_key_is_not_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "id_rsa.pub": "ssh-rsa AAAA test@example\n",
        },
    )
    result = scan(tmp_path)
    assert "PIPE-CFG-019" not in ids(result)


def test_excluded_paths_are_skipped(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": "FROM ubuntu:latest\n",
        },
    )
    result = scan_named("config", tmp_path, exclude_paths=["Dockerfile"])
    assert result.findings == []


def test_exclude_paths_skip_hygiene_findings(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "examples/demo/.env": "TOKEN=abc\n",
            "pyproject.toml": '[project]\nname = "demo"\n',
        },
    )
    result = scan_named(
        "config",
        tmp_path,
        exclude_paths=["examples/**", "pyproject.toml"],
    )
    assert result.findings == []


def test_excluding_gitignore_silences_gitignore_checks(tmp_path):
    write_tree(tmp_path, {"README.md": "# demo\n"})
    result = scan_named("config", tmp_path, exclude_paths=[".gitignore"])
    assert result.findings == []


def test_scanner_reports_file_statistics(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": GITIGNORE,
            "Dockerfile": "FROM ubuntu:22.04\nUSER app\n",
            ".github/workflows/ci.yml": "on: [push]\npermissions:\n  contents: read\njobs: {}\n",
        },
    )
    result = ConfigScanner().scan(ScanContext(root=tmp_path))
    assert result.metadata["filesScanned"] == 2
    assert result.metadata["dockerfiles"] == 1
    assert result.metadata["workflows"] == 1
    assert result.metadata["findings"] == len(result.findings)
