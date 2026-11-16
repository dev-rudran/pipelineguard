"""Rule-by-rule secret detection tests."""

from __future__ import annotations

import json

import pytest

from pipelineguard.scanners.secrets import SecretsScanner, load_rule_pack
from tests.support import (
    FAKE_AWS_KEY,
    FAKE_AWS_SECRET,
    FAKE_AZURE,
    FAKE_GENERIC,
    FAKE_GH_PAT,
    FAKE_GH_TOKEN,
    FAKE_GITLAB,
    FAKE_GOOGLE,
    FAKE_HEROKU,
    FAKE_JWT,
    FAKE_NPM,
    FAKE_PYPI,
    FAKE_SENDGRID,
    FAKE_SLACK,
    FAKE_SLACK_WEBHOOK,
    FAKE_STRIPE,
    FAKE_TWILIO,
    rule_ids,
    scan_named,
    write_tree,
)


def detect(tmp_path, line: str):
    write_tree(tmp_path, {"sample.txt": line + "\n"})
    return scan_named("secrets", tmp_path)


@pytest.mark.parametrize(
    "line,expected",
    [
        (f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"', "PIPE-SEC-001"),
        (f'aws_secret_access_key = "{FAKE_AWS_SECRET}"', "PIPE-SEC-002"),
        (f'token = "{FAKE_GH_TOKEN}"', "PIPE-SEC-003"),
        (f'token = "{FAKE_GH_PAT}"', "PIPE-SEC-004"),
        (f'token = "{FAKE_GITLAB}"', "PIPE-SEC-005"),
        (f'token = "{FAKE_SLACK}"', "PIPE-SEC-006"),
        (f"webhook = {FAKE_SLACK_WEBHOOK}", "PIPE-SEC-007"),
        (f'stripe = "{FAKE_STRIPE}"', "PIPE-SEC-008"),
        (f'google = "{FAKE_GOOGLE}"', "PIPE-SEC-009"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "PIPE-SEC-010"),
        (f'token = "{FAKE_JWT}"', "PIPE-SEC-011"),
        (f'token = "{FAKE_NPM}"', "PIPE-SEC-012"),
        (f'token = "{FAKE_PYPI}"', "PIPE-SEC-013"),
        (f'key = "{FAKE_SENDGRID}"', "PIPE-SEC-014"),
        (f'twilio_auth_token = "{FAKE_TWILIO}"', "PIPE-SEC-015"),
        (f'heroku_api_key = "{FAKE_HEROKU}"', "PIPE-SEC-016"),
        (f"AccountKey={FAKE_AZURE}", "PIPE-SEC-017"),
        (f'password = "{FAKE_GENERIC}"', "PIPE-SEC-018"),
    ],
)
def test_each_rule_true_positive(tmp_path, line, expected):
    result = detect(tmp_path, line)
    assert expected in rule_ids(result)
    assert result.error is None


def test_no_findings_on_clean_text(tmp_path):
    result = detect(tmp_path, "print('hello world')")
    assert result.findings == []


PLACEHOLDER_FILE = """
password = "changeme"
api_key = "${API_KEY}"
access_token = "<your-token>"
secret = "example"
aws_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
other = "xxxxxxxxxxxxxxxxxxxxxxxx"
password = os.environ["DB_PASSWORD"]
api_key = process.env.API_KEY
SECRET_KEY = "your-super-secret-key-here"
client_secret = "{{ secrets.CLIENT_SECRET }}"
api_key = "TODO"
token = "notasecret"
"""


def test_placeholders_produce_no_findings(tmp_path):
    write_tree(tmp_path, {"config.py": PLACEHOLDER_FILE})
    result = scan_named("secrets", tmp_path)
    assert result.findings == [], [finding.message for finding in result.findings]


def test_low_entropy_assignment_is_not_reported(tmp_path):
    result = detect(tmp_path, 'password = "aaaaaaaaaaaa"')
    assert "PIPE-SEC-018" not in rule_ids(result)


def test_documented_example_keys_are_allowlisted(tmp_path):
    content = (
        "AKIAIOSFODNN7EXAMPLE\n"
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
    )
    write_tree(tmp_path, {"docs/aws.txt": content})
    result = scan_named("secrets", tmp_path)
    assert result.findings == []


def test_multiple_rules_in_one_file(tmp_path):
    content = f'aws = "{FAKE_AWS_KEY}"\nstripe = "{FAKE_STRIPE}"\n'
    write_tree(tmp_path, {"settings.py": content})
    result = scan_named("secrets", tmp_path)
    ids = rule_ids(result)
    assert "PIPE-SEC-001" in ids
    assert "PIPE-SEC-008" in ids


def test_same_value_is_not_reported_twice_on_one_line(tmp_path):
    result = detect(tmp_path, f'GITHUB_TOKEN="{FAKE_GH_TOKEN}"')
    ids = rule_ids(result)
    assert ids.count("PIPE-SEC-003") == 1
    assert "PIPE-SEC-018" not in ids


def test_rule_pack_loads_and_validates():
    pack = load_rule_pack()
    assert len(pack.rules) == 18
    ids = [rule.id for rule in pack.rules]
    assert ids == sorted(ids)
    assert all(rule.patterns for rule in pack.rules)


def test_rule_pack_has_no_duplicate_ids():
    pack = load_rule_pack()
    ids = [rule.id for rule in pack.rules]
    assert len(ids) == len(set(ids))


def test_scanner_metadata_reports_rules(tmp_path):
    result = detect(tmp_path, "clean")
    assert result.metadata["rules"] == 18
    assert result.metadata["filesScanned"] >= 1


def test_findings_do_not_contain_raw_secret(tmp_path):
    result = detect(tmp_path, f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"')
    payload = json.dumps([finding.to_dict() for finding in result.findings])
    assert FAKE_AWS_KEY not in payload
    assert "AKIA...3V5" in payload or "AKIA...T3V5" in payload or "AKIA...3V5" in payload


def test_scanner_is_registered():
    from pipelineguard.scanners.base import get_scanner

    assert isinstance(get_scanner("secrets"), SecretsScanner)
