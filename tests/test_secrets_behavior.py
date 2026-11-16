"""Behavioural tests for secret scanning modes, redaction and fingerprints."""

from __future__ import annotations

import json
from pathlib import Path

from pipelineguard.scanners.secrets import SecretsScanner
from pipelineguard.util.text import redact
from tests.support import (
    FAKE_AWS_KEY,
    FAKE_GENERIC,
    FAKE_GH_TOKEN,
    commit_all,
    rule_ids,
    scan_named,
    write_tree,
)


def test_redaction_keeps_prefix_and_suffix():
    assert redact(FAKE_AWS_KEY) == "AKIA...T3V5"
    assert redact(FAKE_GENERIC) == "Tr0u...9mQ2"


def test_short_values_are_fully_masked():
    assert redact("short") == "*****"
    assert redact("abcdefghijk") == "***********"


def test_empty_value_is_empty():
    assert redact("") == ""


def test_snippet_and_message_are_redacted(tmp_path):
    write_tree(tmp_path, {"settings.py": f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\n'})
    result = scan_named("secrets", tmp_path)
    finding = result.findings[0]
    assert FAKE_AWS_KEY not in finding.snippet
    assert FAKE_AWS_KEY not in finding.message
    assert "AKIA...T3V5" in finding.snippet


def test_fingerprint_stable_when_lines_move(tmp_path):
    root = tmp_path / "repo"
    write_tree(root, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    first = scan_named("secrets", root).findings[0]
    write_tree(
        root,
        {"app.py": f'# header\n\nimport os\n\ntoken = "{FAKE_GH_TOKEN}"\n'},
    )
    second = scan_named("secrets", root).findings[0]
    assert first.fingerprint == second.fingerprint
    assert first.line == 1
    assert second.line == 5


def test_fingerprint_differs_across_files(tmp_path):
    root = tmp_path / "repo"
    write_tree(
        root, {"a.py": f'token = "{FAKE_GH_TOKEN}"\n', "b.py": f'token = "{FAKE_GH_TOKEN}"\n'}
    )
    findings = scan_named("secrets", root).findings
    assert len({finding.fingerprint for finding in findings}) == 2


def test_fingerprint_is_short_hex(tmp_path):
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    finding = scan_named("secrets", tmp_path).findings[0]
    assert len(finding.fingerprint) == 16
    int(finding.fingerprint, 16)


def test_allowlist_by_value(tmp_path):
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    result = scan_named(
        "secrets",
        tmp_path,
        options={"secrets_allowlist": {"values": [FAKE_GH_TOKEN]}},
    )
    assert result.findings == []


def test_allowlist_by_path(tmp_path):
    write_tree(
        tmp_path,
        {
            "vendor/config.py": f'token = "{FAKE_GH_TOKEN}"\n',
            "src/config.py": f'token = "{FAKE_GH_TOKEN}"\n',
        },
    )
    result = scan_named(
        "secrets",
        tmp_path,
        options={"secrets_allowlist": {"paths": ["vendor/**"]}},
    )
    assert [finding.path for finding in result.findings] == ["src/config.py"]


def test_policy_exclude_paths_are_honoured(tmp_path):
    write_tree(
        tmp_path,
        {
            "generated/config.py": f'token = "{FAKE_GH_TOKEN}"\n',
            "src/config.py": f'token = "{FAKE_GH_TOKEN}"\n',
        },
    )
    result = scan_named("secrets", tmp_path, exclude_paths=["generated/**"])
    assert [finding.path for finding in result.findings] == ["src/config.py"]


def test_binary_file_is_skipped(tmp_path):
    (tmp_path / "blob.bin").write_bytes(
        b'token = "' + FAKE_GH_TOKEN.encode() + b'"\x00\x01\x02\x03'
    )
    result = scan_named("secrets", tmp_path)
    assert result.findings == []
    assert result.metadata["binarySkipped"] >= 1


def test_large_file_is_skipped(tmp_path):
    write_tree(tmp_path, {"big.py": f'token = "{FAKE_GH_TOKEN}"\n' + "# pad\n" * 100})
    result = scan_named("secrets", tmp_path, max_file_bytes=32)
    assert result.findings == []
    assert result.metadata["largeSkipped"] >= 1


def test_dot_git_directory_is_not_scanned(tmp_path):
    write_tree(tmp_path, {".git/objects/secret.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    result = scan_named("secrets", tmp_path)
    assert result.findings == []


def test_history_mode_without_git_is_graceful(tmp_path):
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    result = scan_named("secrets", tmp_path, history=True)
    assert result.error is None
    assert "historyError" in result.metadata
    assert "not a git repository" in result.metadata["historyError"]


def test_history_finds_removed_secret(git_repo: Path):
    write_tree(git_repo, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    secret_commit = commit_all(git_repo, "add token")
    write_tree(git_repo, {"app.py": "print('clean')\n"})
    commit_all(git_repo, "remove token")

    result = scan_named("secrets", git_repo, history=True)
    assert "PIPE-SEC-003" in rule_ids(result)
    finding = next(item for item in result.findings if item.rule_id == "PIPE-SEC-003")
    assert finding.commit == secret_commit
    assert finding.metadata.get("commitAuthor")


def test_history_deduplicates_secret_still_present(git_repo: Path):
    write_tree(git_repo, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    commit = commit_all(git_repo, "add token")
    result = scan_named("secrets", git_repo, history=True)
    findings = [item for item in result.findings if item.rule_id == "PIPE-SEC-003"]
    assert len(findings) == 1
    assert commit in findings[0].metadata.get("commits", [])


def test_staged_mode_reads_the_index(git_repo: Path):
    write_tree(git_repo, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    from tests.support import git

    git(git_repo, "add", "app.py")
    write_tree(git_repo, {"app.py": "print('clean working tree')\n"})

    staged = scan_named("secrets", git_repo, staged=True)
    workspace = scan_named("secrets", git_repo)
    assert "PIPE-SEC-003" in rule_ids(staged)
    assert "PIPE-SEC-003" not in rule_ids(workspace)


def test_staged_mode_without_git_falls_back(tmp_path):
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    result = scan_named("secrets", tmp_path, staged=True)
    assert "PIPE-SEC-003" in rule_ids(result)
    assert result.metadata.get("stagedFallback") is True


def test_scanner_result_json_is_safe(tmp_path):
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    result = scan_named("secrets", tmp_path)
    payload = json.dumps(result.to_dict())
    assert FAKE_GH_TOKEN not in payload


def test_internal_context_does_not_contain_secret(tmp_path):
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    finding = scan_named("secrets", tmp_path).findings[0]
    assert FAKE_GH_TOKEN not in finding.context
    assert "secret:" in finding.context


def test_scanner_instance_reuses_rule_pack(tmp_path):
    scanner = SecretsScanner()
    write_tree(tmp_path, {"app.py": f'token = "{FAKE_GH_TOKEN}"\n'})
    result = scanner.scan(
        __import__("pipelineguard.scanners.base", fromlist=["ScanContext"]).ScanContext(
            root=tmp_path
        )
    )
    assert scanner.pack.rules
    assert result.findings
