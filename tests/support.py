"""Shared helpers for the pipelineguard test suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = PROJECT_ROOT / "examples"
VULNERABLE = EXAMPLES / "vulnerable-repo"
CLEAN = EXAMPLES / "clean-repo"
ADVISORY_DB = PROJECT_ROOT / "src" / "pipelineguard" / "advisories" / "osv-fixture.json"

# All credentials below are fake values generated for this test suite.
FAKE_AWS_KEY = "AKIAQ7Z2M4N6P8R1T3V5"
FAKE_AWS_SECRET = "kQ3rT8vW2xZ5aB7cD9eF1gH4jK6mN0pQ2sT4uV" + "6w"
FAKE_GH_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_GH_PAT = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2"
FAKE_GITLAB = "glpat-Ab3Df6Gh9Jk2Lm5Np8" + "Qr"
FAKE_SLACK = "xoxb-123456789012-123456789012-" + "AbCdEfGhIjKlMnOpQrStUvWx"
FAKE_SLACK_WEBHOOK = "https://hooks.slack.com/services/T01234567/" + "B01234567/abcdefghijklmnopqrstuvwx"
FAKE_STRIPE = "sk_live_Ab3Df6Gh9Jk2Lm5Np8" + "Qr4TuV"
FAKE_GOOGLE = "AIza" + "Ab3Df6Gh9Jk2Lm5Np8Qr4TuVwXyZ0123456"
FAKE_NPM = "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_PYPI = "pypi-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5Z"
FAKE_SENDGRID = "SG." + "A1b2C3d4E5f6G7h8I9j0K1" + "." + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
FAKE_TWILIO = "0123456789abcdef0123456789abcdef"
FAKE_HEROKU = "123e4567-e89b-12d3-a456-426614174000"
FAKE_AZURE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/ab=="
FAKE_GENERIC = "Tr0ub4dor&3xK9mQ2"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def scan_scanner(
    scanner: Any,
    root: Path,
    **context_kwargs: Any,
):
    """Run one scanner instance against a directory and return its result."""
    from pipelineguard.scanners.base import ScanContext

    context = ScanContext(root=root, **context_kwargs)
    return scanner.scan(context)


def scan_named(name: str, root: Path, **context_kwargs: Any):
    from pipelineguard.scanners.base import get_scanner

    return scan_scanner(get_scanner(name), root, **context_kwargs)


def finding_dicts(result: Any) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in result.findings]


def rule_ids(result: Any) -> list[str]:
    return [finding.rule_id for finding in result.findings]


def run_cli(argv: list[str]) -> int:
    from pipelineguard.cli import main

    return main(argv)


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": "Pipelineguard Tests",
            "GIT_AUTHOR_EMAIL": "tests@example.com",
            "GIT_COMMITTER_NAME": "Pipelineguard Tests",
            "GIT_COMMITTER_EMAIL": "tests@example.com",
        }
    )
    completed = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {completed.stderr}")
    return completed


def make_git_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q", "-b", "main")
    return root


def commit_all(repo: Path, message: str = "commit") -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def contains_raw_secret(payload: str, values: list[str] | None = None) -> list[str]:
    candidates = values or [
        FAKE_AWS_KEY,
        FAKE_AWS_SECRET,
        FAKE_GH_TOKEN,
        FAKE_GH_PAT,
        FAKE_GITLAB,
        FAKE_SLACK,
        FAKE_SLACK_WEBHOOK,
        FAKE_STRIPE,
        FAKE_GOOGLE,
        FAKE_NPM,
        FAKE_PYPI,
        FAKE_SENDGRID,
        FAKE_TWILIO,
        FAKE_HEROKU,
        FAKE_AZURE,
        FAKE_GENERIC,
        FAKE_JWT,
        # Example fixture credentials; all are fake.
        "AKIAF4C5IEYYNJGXVDKB",
        "AKIAGYYPLMFE23J6HH" + "C",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY0" + "0",
        "ghp_AmhyjC0dQS4PGYvZrXFh1nYkYx2Ol2DPJ4" + "R0",
        "rJCZ1UbCHb8RyYiBG7Qb08Y3sKl4FCB8",
        "sk_live_vdX38ko0VQbnfTH6BVrJ" + "MjM0",
        "xoxb-123456789012-" + "abcdefghij",
        "XSx1laLMShaSaLqM6hmdpzV8kouDWOfcL7wk",
    ]
    return [value for value in candidates if value and value in payload]


def python_module_available() -> bool:
    completed = subprocess.run(
        [sys.executable, "-c", "import pipelineguard"],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode == 0
