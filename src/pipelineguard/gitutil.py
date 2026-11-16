"""Git plumbing.

All git interaction goes through :mod:`subprocess` with an argument list and
``shell=False``. Repositories are treated as untrusted input: output is bounded,
binary patches are skipped and every failure degrades gracefully so that
pipelineguard also runs in a plain directory or a source tarball.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess  # nosec B404 - git is invoked with a fixed argument vector and shell=False
from dataclasses import dataclass
from pathlib import Path

from .util.text import is_binary_bytes, is_skipped_dir

GIT_TIMEOUT = 60
HISTORY_MAX_BYTES = 64 * 1024 * 1024
HISTORY_MAX_LINES = 2_000_000

_COMMIT_RE = re.compile(r"^commit ([0-9a-f]{40}|[0-9a-f]{64})$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class GitError(RuntimeError):
    """Raised when a git invocation fails unexpectedly."""


def run_git(
    args: list[str],
    cwd: Path,
    timeout: int = GIT_TIMEOUT,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run git with a fixed argument vector and no shell."""
    command = ["git", "-c", "core.quotepath=false", "-c", "color.ui=false", *args]
    try:
        completed = subprocess.run(  # nosec B603 - argument list, shell=False, fixed binary
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=_git_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitError(str(exc)) from exc
    if check and completed.returncode != 0:
        raise GitError((completed.stderr or completed.stdout or "git failed").strip())
    return completed


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_PAGER"] = "cat"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    env.pop("GIT_DIR", None)
    return env


def is_git_repo(path: Path) -> bool:
    if not path.exists():
        return False
    completed = run_git(["rev-parse", "--is-inside-work-tree"], path)
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def git_root(path: Path) -> Path | None:
    completed = run_git(["rev-parse", "--show-toplevel"], path)
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return Path(value) if value else None


def head_commit(path: Path) -> str | None:
    completed = run_git(["rev-parse", "HEAD"], path)
    if completed.returncode != 0:
        return None
    sha = completed.stdout.strip()
    return sha if _SHA_RE.match(sha) else None


def _split_z(output: str) -> list[str]:
    return [item for item in output.split("\x00") if item]


def workspace_files(root: Path) -> list[Path]:
    """Enumerate scannable files, honoring .gitignore when in a repository.

    Falls back to a manual walk with a hard-coded exclude list outside git.
    """
    if is_git_repo(root):
        completed = run_git(
            ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            root,
        )
        if completed.returncode == 0:
            files: list[Path] = []
            for relative in _split_z(completed.stdout):
                candidate = (root / relative).resolve()
                try:
                    candidate.relative_to(root.resolve())
                except ValueError:
                    continue
                if candidate.is_file() and not candidate.is_symlink():
                    files.append(candidate)
            return sorted(files)
    return _walk_files(root)


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not is_skipped_dir(name))
        for filename in sorted(filenames):
            candidate = Path(dirpath) / filename
            if candidate.is_file() and not candidate.is_symlink():
                files.append(candidate)
    return files


@dataclass
class FileBlob:
    path: str
    content: str
    mode: str = "workspace"

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()


def staged_files(root: Path) -> list[FileBlob]:
    """Return added or modified files from the git index.

    Content is read from the index (``git show :path``) rather than the working
    tree so that ``--staged`` checks exactly what is about to be committed.
    """
    if not is_git_repo(root):
        return []
    completed = run_git(
        ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"],
        root,
    )
    if completed.returncode != 0:
        return []
    blobs: list[FileBlob] = []
    for relative in _split_z(completed.stdout):
        blob = read_index_blob(root, relative)
        if blob is not None:
            blobs.append(blob)
    return sorted(blobs, key=lambda item: item.path)


def read_index_blob(root: Path, relative: str) -> FileBlob | None:
    completed = run_git(["show", f":{relative}"], root)
    if completed.returncode != 0:
        return None
    data = completed.stdout.encode("utf-8", errors="replace")
    if is_binary_bytes(data) or len(data) > 2 * 1024 * 1024:
        return None
    return FileBlob(path=relative.replace(os.sep, "/"), content=completed.stdout, mode="staged")


def staged_relative_paths(root: Path) -> list[str]:
    if not is_git_repo(root):
        return []
    completed = run_git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], root)
    if completed.returncode != 0:
        return []
    return sorted(_split_z(completed.stdout))


@dataclass
class HistoryLine:
    """A single added line attributed to a commit and file."""

    commit: str
    path: str
    line: int
    text: str
    author: str = ""
    date: str = ""


@dataclass
class HistoryScan:
    lines: list[HistoryLine]
    commits: int
    truncated: bool = False
    error: str | None = None


def history_added_lines(
    root: Path,
    max_commits: int = 500,
    max_bytes: int = HISTORY_MAX_BYTES,
) -> HistoryScan:
    """Stream ``git log -p`` and return added lines only.

    Output is bounded by commit count and total bytes. Rename detection is
    disabled to keep patch parsing predictable; deleted files still appear in
    the diff of the commit that removed them, which is what secret history
    scanning needs.
    """
    if not is_git_repo(root):
        return HistoryScan(lines=[], commits=0, error="not a git repository")

    command = [
        "git",
        "-c",
        "core.quotepath=false",
        "-c",
        "color.ui=false",
        "log",
        "-p",
        "--all",
        "--no-color",
        "--no-ext-diff",
        "--unified=0",
        "--diff-filter=AM",
        f"--max-count={max_commits}",
        "--format=commit %H%nAuthor: %an%nDate: %ad",
    ]
    added: list[HistoryLine] = []
    commit = ""
    author = ""
    date = ""
    path = ""
    line_number = 0
    commits_seen = 0
    consumed = 0
    truncated = False

    try:
        process = subprocess.Popen(  # nosec B603 - argument list, shell=False, fixed binary
            command,
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            env=_git_env(),
        )
    except OSError as exc:  # pragma: no cover - environment dependent
        return HistoryScan(lines=[], commits=0, error=str(exc))

    if process.stdout is None:  # pragma: no cover - defensive
        process.kill()
        return HistoryScan(lines=[], commits=0, error="git log produced no output stream")
    returncode = 0
    try:
        for raw in process.stdout:
            consumed += len(raw)
            if consumed > max_bytes:
                truncated = True
                process.kill()
                break
            line = raw.rstrip("\n")
            match = _COMMIT_RE.match(line)
            if match:
                commit = match.group(1)
                commits_seen += 1
                path = ""
                continue
            if line.startswith("Author: "):
                author = line[len("Author: ") :]
                continue
            if line.startswith("Date: "):
                date = line[len("Date: ") :]
                continue
            if line.startswith("diff --git "):
                path = ""
                continue
            if line.startswith("+++ "):
                candidate = line[4:].strip()
                if candidate == "/dev/null":
                    path = ""
                else:
                    path = candidate[2:] if candidate.startswith("b/") else candidate
                continue
            hunk = _HUNK_RE.match(line)
            if hunk:
                line_number = int(hunk.group(1))
                continue
            if line.startswith("+") and not line.startswith("+++"):
                if path and commit:
                    added.append(
                        HistoryLine(
                            commit=commit,
                            path=path,
                            line=line_number,
                            text=line[1:],
                            author=author,
                            date=date,
                        )
                    )
                line_number += 1
                continue
            if line.startswith(" "):
                line_number += 1
    finally:
        with contextlib.suppress(OSError):
            process.stdout.close()
        returncode = process.wait()
    if returncode not in (0, -9) and not truncated:  # pragma: no cover - defensive
        return HistoryScan(lines=[], commits=0, error="git log failed")
    return HistoryScan(lines=added, commits=commits_seen, truncated=truncated)


def is_tracked(root: Path, relative: str) -> bool:
    completed = run_git(["ls-files", "--error-unmatch", "--", relative], root)
    return completed.returncode == 0


def log_for_path(root: Path, relative: str, limit: int = 5) -> list[str]:
    completed = run_git(
        ["log", "--format=%h %ad %s", "--date=short", f"--max-count={limit}", "--", relative],
        root,
    )
    if completed.returncode != 0:
        return []
    return [line for line in completed.stdout.splitlines() if line.strip()]
