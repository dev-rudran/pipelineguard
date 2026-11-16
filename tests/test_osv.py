"""OSV client, severity mapping, cache and offline advisory tests."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest

from pipelineguard.models import Component, Severity
from pipelineguard.scanners import deps as deps_module
from pipelineguard.scanners.base import ScanContext
from pipelineguard.scanners.deps import (
    DependencyScanner,
    OSVCache,
    OSVError,
    fixed_versions,
    load_advisory_db,
    osv_severity,
    parse_cvss_v3,
    query_osv,
    score_to_severity,
    vulnerability_finding,
    vulnerability_matches,
)
from tests.support import ADVISORY_DB, CLEAN, VULNERABLE, write_tree


def _component(name: str = "jinja2", version: str = "2.11.2") -> Component:
    return Component(ecosystem="pypi", name=name, version=version, source="requirements.txt")


def test_cvss_v3_high_score():
    assert parse_cvss_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5


def test_cvss_v3_critical_score():
    assert parse_cvss_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_cvss_v3_invalid_returns_none():
    assert parse_cvss_v3("not-a-vector") is None
    assert parse_cvss_v3("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.9, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_score_to_severity(score, expected):
    assert score_to_severity(score) is expected


def test_osv_severity_database_specific():
    assert osv_severity({"database_specific": {"severity": "CRITICAL"}}) is Severity.CRITICAL
    assert osv_severity({"database_specific": {"severity": "MODERATE"}}) is Severity.MEDIUM
    assert osv_severity({"database_specific": {"severity": "low"}}) is Severity.LOW


def test_osv_severity_cvss_vector():
    vulnerability = {
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    }
    assert osv_severity(vulnerability) is Severity.CRITICAL


def test_osv_severity_numeric():
    assert osv_severity({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}) is Severity.HIGH


def test_osv_severity_defaults_to_medium():
    assert osv_severity({}) is Severity.MEDIUM


def test_load_advisory_db():
    vulns = load_advisory_db(ADVISORY_DB)
    assert len(vulns) == 3
    assert {vuln["id"] for vuln in vulns}


def test_load_advisory_db_invalid(tmp_path: Path):
    write_tree(tmp_path, {"advisories.json": "{broken"})
    with pytest.raises(OSVError, match="not valid JSON"):
        load_advisory_db(tmp_path / "advisories.json")


def test_load_advisory_db_wrong_shape(tmp_path: Path):
    write_tree(tmp_path, {"advisories.json": json.dumps({"items": []})})
    with pytest.raises(OSVError, match="vulns"):
        load_advisory_db(tmp_path / "advisories.json")


def test_fixed_versions():
    vuln = load_advisory_db(ADVISORY_DB)[0]
    assert fixed_versions(vuln, _component()) == ["2.11.3"]


def test_vulnerability_matches_range():
    vuln = load_advisory_db(ADVISORY_DB)[0]
    assert vulnerability_matches(vuln, _component("jinja2", "2.11.2"))
    assert not vulnerability_matches(vuln, _component("jinja2", "2.11.3"))
    assert not vulnerability_matches(vuln, _component("requests", "2.11.2"))


def test_vulnerability_matches_explicit_versions():
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "versions": ["1.0.0", "1.1.0"],
            }
        ]
    }
    component = Component(ecosystem="pypi", name="demo", version="1.1.0")
    assert vulnerability_matches(vuln, component)
    component.version = "1.2.0"
    assert not vulnerability_matches(vuln, component)


def test_vulnerability_finding_shape():
    vuln = load_advisory_db(ADVISORY_DB)[0]
    finding = vulnerability_finding(vuln, _component())
    assert finding.rule_id == "PIPE-DEP-001"
    assert finding.severity is Severity.HIGH
    assert finding.package == "jinja2"
    assert finding.version == "2.11.2"
    assert finding.fixed_version == "2.11.3"
    assert "CVE-2020-28493" in finding.aliases
    assert "2.11.3" in finding.message
    assert finding.path == "requirements.txt"


def test_query_osv_chunks(monkeypatch):
    calls: list[int] = []

    def fake_post(url, payload, timeout=10.0):
        calls.append(len(payload["queries"]))
        return {"results": [{"vulns": []} for _ in payload["queries"]]}

    monkeypatch.setattr(deps_module, "_post_json", fake_post)
    components = [
        Component(ecosystem="pypi", name=f"pkg-{index}", version="1.0.0") for index in range(150)
    ]
    results = query_osv(components)
    assert calls == [100, 50]
    assert len(results) == 150


def test_query_osv_retries_once(monkeypatch):
    attempts = {"count": 0}

    def flaky_post(url, payload, timeout=10.0):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise urllib.error.URLError("temporary failure")
        return {"results": [{"vulns": []} for _ in payload["queries"]]}

    monkeypatch.setattr(deps_module, "_post_json", flaky_post)
    results = query_osv([_component()])
    assert attempts["count"] == 2
    assert list(results.values()) == [[]]


def test_query_osv_malformed_response(monkeypatch):
    monkeypatch.setattr(
        deps_module,
        "_post_json",
        lambda url, payload, timeout=10.0: {"results": []},
    )
    with pytest.raises(OSVError, match="batch size"):
        query_osv([_component()])


def test_query_osv_network_failure(monkeypatch):
    def failing_post(url, payload, timeout=10.0):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(deps_module, "_post_json", failing_post)
    with pytest.raises(OSVError, match="request failed"):
        query_osv([_component()])


def test_cache_roundtrip(tmp_path: Path):
    cache = OSVCache(tmp_path / "cache" / "osv.json", ttl=3600)
    key = "pypi:jinja2:2.11.2"
    cache.put(key, [{"id": "TEST-1"}])
    cache.save()
    reloaded = OSVCache(tmp_path / "cache" / "osv.json", ttl=3600)
    assert reloaded.get(key) == [{"id": "TEST-1"}]


def test_cache_expiry(tmp_path: Path):
    cache = OSVCache(tmp_path / "osv.json", ttl=0)
    cache.put("k", [])
    assert cache.get("k") is None


def test_cache_missing_entry(tmp_path: Path):
    cache = OSVCache(tmp_path / "osv.json")
    assert cache.get("missing") is None


def test_cache_corrupt_file(tmp_path: Path):
    write_tree(tmp_path, {"osv.json": "{broken"})
    cache = OSVCache(tmp_path / "osv.json")
    assert cache.get("anything") is None


def test_dependency_scanner_offline_advisory():
    scanner = DependencyScanner()
    result = scanner.scan(ScanContext(root=VULNERABLE, offline=True, advisory_db=ADVISORY_DB))
    assert result.error is None
    findings = [finding for finding in result.findings if finding.rule_id == "PIPE-DEP-001"]
    assert len(findings) == 1
    assert findings[0].package == "jinja2"
    assert result.metadata["auditSource"] == "advisory-db"


def test_dependency_scanner_offline_without_db(tmp_path: Path):
    write_tree(tmp_path, {"requirements.txt": "jinja2==3.1.4\n"})
    result = DependencyScanner().scan(ScanContext(root=tmp_path, offline=True))
    assert result.error is None
    assert result.findings == []
    assert "no vulnerability lookup" in result.metadata["note"]


def test_dependency_scanner_network_error_degrades(tmp_path: Path, monkeypatch):
    write_tree(tmp_path, {"requirements.txt": "jinja2==2.11.2\n"})

    def failing_post(url, payload, timeout=10.0):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(deps_module, "_post_json", failing_post)
    result = DependencyScanner().scan(
        ScanContext(root=tmp_path, offline=False, cache_dir=tmp_path / "cache")
    )
    assert result.error is None
    assert "osvError" in result.metadata
    assert result.findings == []


def test_dependency_scanner_uses_cache(tmp_path: Path, monkeypatch):
    write_tree(tmp_path, {"requirements.txt": "jinja2==2.11.2\n"})
    cache_dir = tmp_path / ".cache"
    cache = OSVCache(cache_dir / "osv.json")
    cache.put("pypi:jinja2:2.11.2", [])
    cache.save()

    def must_not_call(url, payload, timeout=10.0):
        raise AssertionError("network should not be used when the cache is fresh")

    monkeypatch.setattr(deps_module, "_post_json", must_not_call)
    result = DependencyScanner().scan(
        ScanContext(root=tmp_path, offline=False, cache_dir=cache_dir)
    )
    assert result.error is None
    assert result.metadata["cacheHits"] == 1


def test_dependency_scanner_no_manifests(tmp_path: Path):
    result = DependencyScanner().scan(ScanContext(root=tmp_path, offline=True))
    assert result.skipped is True
    assert "no supported dependency manifests" in result.skip_reason


def test_clean_repo_offline_has_no_high_findings():
    result = DependencyScanner().scan(ScanContext(root=CLEAN, offline=True))
    high = [finding for finding in result.findings if finding.severity.rank >= Severity.HIGH.rank]
    assert high == []


def test_parse_requirement_handles_wildcard_version():
    from pipelineguard.scanners.deps import parse_requirement

    component, warning = parse_requirement("django==4.2.*", "requirements.txt")
    assert component is not None
    assert component.version == "4.2"
    assert warning is not None
