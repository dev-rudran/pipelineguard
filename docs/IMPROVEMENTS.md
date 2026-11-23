# Improvement backlog

Captured 2026-11-23. Priorities: **P1** correctness/security, **P2** capability,
**P3** polish. Keep the existing suite green and add tests for every change.

## P1

- **Strict typing.** Add `src/pipelineguard/py.typed`, `[tool.mypy]` with
  `strict = true`, and a CI step. Definition of done: `mypy src` is clean.
- **Coverage gate.** This is the only repo without coverage configuration. Add
  `[tool.coverage.*]` plus `--cov-fail-under` to `pyproject.toml` and CI.
- **GitHub annotations.** Emit `::error file=...,line=...::` workflow commands and
  write a Markdown summary to `$GITHUB_STEP_SUMMARY` when that variable is set,
  so findings appear on the PR diff and the job page.
- **Per-scanner gates.** Allow `fail_on` to be overridden per scanner (for
  example fail on `secrets: low` but `config: high`). Validate the policy schema
  and reject unknown scanner names.

## P2

- **SPDX SBOM.** `--format spdx` producing SPDX 2.3 JSON alongside CycloneDX,
  with the same component set and a determinism test.
- **Changed-files mode.** `--changed-only --base REF` to scan only files touched
  by a PR, using the existing git plumbing and falling back to a full scan when
  git metadata is unavailable.
- **Custom secret rules.** Allow a `secrets.rules` path in `pipelineguard.yaml`
  with the same schema as the bundled pack, including allowlists and tests.
- **OSV cache in CI.** Document and test an `actions/cache` keyed on
  `.pipelineguard-cache/osv.json` plus lockfile hashes; add `--cache-dir`.
- **PyPI release.** OIDC trusted publishing and `pip install pipelineguard`
  install lines, keeping the composite action working.

## P3

- **JUnit output** for CI reporters.
- **Container image** with git and the CLI, for CI systems without Python setup.
- Pre-commit hook option to scan git history on demand (document runtime cost).
- Add `CODE_OF_CONDUCT.md`.
