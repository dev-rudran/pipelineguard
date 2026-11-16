"""Pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.support import CLEAN, VULNERABLE, make_git_repo


@pytest.fixture
def vulnerable_root() -> Path:
    return VULNERABLE


@pytest.fixture
def clean_root() -> Path:
    return CLEAN


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    return make_git_repo(tmp_path / "repo")
