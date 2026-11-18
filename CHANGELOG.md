# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `licenses` scanner for dependency license compliance. It reuses the dependency
  parsers, enforces a configurable case-insensitive SPDX denylist
  (`PIPE-LIC-001`, high) and optionally reports dependencies with unknown license
  metadata (`PIPE-LIC-002`, low). Policy keys `licenses.deny` and
  `licenses.allow_unknown` default to `GPL-3.0`, `AGPL-3.0` and `SSPL-1.0`, with
  unknown licenses allowed.

## [0.1.0] - 2026-11-15

### Added

- Secret scanning with 18 bundled rules, Shannon entropy checks, placeholder and
  documentation-value allowlists, and redaction that never serializes a raw
  credential.
- Scanner modes for the working tree, the git index (`--staged`) and added lines
  from git history (`--history`), with commit and author attribution.
- Dependency inventory and OSV auditing for requirements files, `pyproject.toml`
  (PEP 621 and Poetry), `poetry.lock`, `package-lock.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `go.sum` and `Cargo.lock`.
- Offline auditing with a local OSV advisory JSON file and a 24 hour on-disk
  cache for online lookups.
- CycloneDX 1.5 SBOM generation with deterministic serial numbers and component
  ordering.
- Dockerfile, GitHub Actions and repository hygiene checks under the
  `PIPE-CFG-*` rule family.
- Policy file support for severity thresholds, required scanners, per-severity
  budgets, path exclusions, time-bounded allowances and offline mode.
- Baseline reports so a gate can fail only on new findings.
- Console, JSON, SARIF 2.1.0, Markdown and CycloneDX output. `--format all`
  writes `results.json`, `results.sarif`, `comment.md` and `sbom.cdx.json`.
- Exit codes: `0` gate passed, `1` gate failed, `2` tool or configuration error.
- Composite GitHub Action, reusable workflow and pre-commit hooks.
- Example vulnerable and clean repositories used by the test suite and the
  documentation.

### Security

- Findings carry redacted snippets and SHA-256 fingerprints only.
- Git is invoked with an argument vector and `shell=False`; repository content
  is treated as untrusted input.
- The only network endpoint is the fixed OSV batch API URL with a 10 second
  timeout and one retry.

[0.1.0]: https://github.com/dev-rudran/pipelineguard/releases/tag/v0.1.0
