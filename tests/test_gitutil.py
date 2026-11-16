"""Git plumbing tests, all executed against throwaway repositories."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipelineguard.gitutil import (
    GitError,
    head_commit,
    history_added_lines,
    is_git_repo,
    is_tracked,
    log_for_path,
    read_index_blob,
    run_git,
    staged_files,
    staged_relative_paths,
    workspace_files,
)
from tests.support import FAKE_AWS_KEY, commit_all, git, make_git_repo, write_tree


def relative_files(root: Path) -> list[str]:
    return [path.relative_to(root).as_posix() for path in workspace_files(root)]


def test_plain_directory_is_not_a_repository(tmp_path):
    assert is_git_repo(tmp_path) is False
    assert head_commit(tmp_path) is None


def test_repository_detection_and_head(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"README.md": "# demo\n"})
    commit = commit_all(repo, "initial")
    assert is_git_repo(repo) is True
    assert head_commit(repo) == commit
    assert len(commit) == 40


def test_run_git_check_raises_on_failure(tmp_path):
    with pytest.raises(GitError):
        run_git(["rev-parse", "HEAD"], tmp_path, check=True)


def test_run_git_without_check_returns_failure(tmp_path):
    completed = run_git(["rev-parse", "HEAD"], tmp_path)
    assert completed.returncode != 0


def test_workspace_files_includes_github_and_skips_git(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(
        repo,
        {
            ".github/workflows/ci.yml": "on: [push]\n",
            "src/app.py": "print('ok')\n",
            ".gitignore": "dist/\n",
        },
    )
    commit_all(repo)
    files = relative_files(repo)
    assert files == [".github/workflows/ci.yml", ".gitignore", "src/app.py"]
    assert not any(path.startswith(".git/") for path in files)


def test_workspace_files_respects_gitignore(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {".gitignore": "ignored.txt\n"})
    commit_all(repo)
    write_tree(repo, {"ignored.txt": "secret\n", "kept.txt": "ok\n"})
    files = relative_files(repo)
    assert "ignored.txt" not in files
    assert "kept.txt" in files


def test_workspace_files_walk_fallback(tmp_path):
    write_tree(
        tmp_path,
        {
            "README.md": "# demo\n",
            ".github/workflows/ci.yml": "on: [push]\n",
            "node_modules/pkg/index.js": "module.exports = 1;\n",
            ".git/config": "[core]\n",
            "src/app.py": "print('ok')\n",
        },
    )
    files = relative_files(tmp_path)
    assert ".github/workflows/ci.yml" in files
    assert "src/app.py" in files
    assert not any(path.startswith("node_modules/") for path in files)
    assert not any(path.startswith(".git/") for path in files)


def test_staged_files_read_from_index(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"app.txt": "old content\n"})
    commit_all(repo)
    write_tree(repo, {"app.txt": "new content\n", "untracked.txt": "later\n"})
    git(repo, "add", "app.txt")
    blobs = staged_files(repo)
    assert [blob.path for blob in blobs] == ["app.txt"]
    assert blobs[0].content == "new content\n"
    assert blobs[0].mode == "staged"
    assert staged_relative_paths(repo) == ["app.txt"]


def test_staged_files_outside_git_are_empty(tmp_path):
    write_tree(tmp_path, {"app.txt": "hello\n"})
    assert staged_files(tmp_path) == []
    assert staged_relative_paths(tmp_path) == []


def test_read_index_blob_missing_returns_none(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"app.txt": "hello\n"})
    commit_all(repo)
    assert read_index_blob(repo, "app.txt") is not None
    assert read_index_blob(repo, "missing.txt") is None


def test_history_added_lines_finds_removed_secret(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"settings.py": 'AWS_ACCESS_KEY_ID = "AKIAQ7Z2M4N6P8R1T3V5"\n'})
    first = commit_all(repo, "add settings")
    write_tree(repo, {"settings.py": "AWS_ACCESS_KEY_ID = os.environ['AWS_KEY']\n"})
    second = commit_all(repo, "remove secret")

    scan = history_added_lines(repo)
    assert scan.error is None
    assert scan.commits >= 2
    matches = [line for line in scan.lines if FAKE_AWS_KEY in line.text]
    assert len(matches) == 1
    assert matches[0].commit == first
    assert matches[0].commit != second
    assert matches[0].path == "settings.py"
    assert matches[0].author == "Pipelineguard Tests"


def test_history_outside_git_reports_error(tmp_path):
    scan = history_added_lines(tmp_path)
    assert scan.commits == 0
    assert scan.lines == []
    assert scan.error == "not a git repository"


def test_history_truncation_is_reported(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"big.txt": "line\n" * 5000})
    commit_all(repo)
    scan = history_added_lines(repo, max_bytes=100)
    assert scan.truncated is True


def test_is_tracked(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"tracked.txt": "yes\n"})
    commit_all(repo)
    write_tree(repo, {"untracked.txt": "no\n"})
    assert is_tracked(repo, "tracked.txt") is True
    assert is_tracked(repo, "untracked.txt") is False


def test_log_for_path(tmp_path):
    repo = make_git_repo(tmp_path / "repo")
    write_tree(repo, {"app.txt": "one\n"})
    commit_all(repo, "first change")
    write_tree(repo, {"app.txt": "two\n"})
    commit_all(repo, "second change")
    entries = log_for_path(repo, "app.txt")
    assert len(entries) == 2
    assert entries[0].endswith("second change")
    assert entries[1].endswith("first change")
    assert log_for_path(repo, "missing.txt") == []
