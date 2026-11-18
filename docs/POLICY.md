# Policy reference

`pipelineguard scan` evaluates every finding through a policy. Without a policy
file the defaults are:

- fail when any actionable finding is at severity `high` or above,
- require no particular scanner,
- apply no allowances or path exclusions,
- deny the `GPL-3.0`, `AGPL-3.0` and `SSPL-1.0` dependency licenses while
  allowing packages without license metadata,
- use online OSV lookup unless `--offline` is passed.

The CLI looks for `pipelineguard.yaml` in the scanned directory. Pass
`--policy path/to/pipelineguard.yaml` to use a different file; the file must
exist. Unknown keys are rejected so typos do not silently weaken a gate.

```yaml
version: 1

# Lowest severity that fails the gate: critical, high, medium, low, info or none.
fail_on: high

# Every listed scanner must run. Valid names: secrets, deps, licenses, sbom, config.
required_scanners:
  - secrets
  - deps
  - licenses
  - sbom
  - config

# Dependency license compliance for the licenses scanner.
licenses:
  deny: [GPL-3.0, AGPL-3.0, SSPL-1.0]
  allow_unknown: true

# Optional per-severity budgets. Exceeding a budget fails the gate even when the
# finding is below fail_on.
max_findings:
  critical: 0
  high: 5

# Findings whose path matches any glob are excluded from the gate. The globs are
# also passed to the scanners so excluded files are not read.
exclude_paths:
  - "vendor/**"
  - "*.min.js"

# Force offline OSV behaviour for every scan that uses this policy.
offline: false
```

## License policy

The `licenses` scanner evaluates the license metadata resolved by the dependency
parsers. Its configuration lives under the `licenses` key:

| Key | Default | Meaning |
| --- | --- | --- |
| `deny` | `[GPL-3.0, AGPL-3.0, SSPL-1.0]` | SPDX identifiers that produce a high severity `PIPE-LIC-001` finding. Matching is case-insensitive and folds `-only`, `-or-later` and legacy `+` suffixes onto the base identifier. |
| `allow_unknown` | `true` | When `false`, a dependency with no usable license metadata produces a low severity `PIPE-LIC-002` finding. |

Supplying `deny` replaces the default list; use `deny: []` to disable license
denials. A clean repository with permissive licenses and the default policy is
not affected by the new scanner. Any `PIPE-LIC-*` finding participates in
`fail_on`, `max_findings`, allowances, baselines, fingerprints and every report
format like any other finding.

```yaml
licenses:
  deny: [GPL-3.0, AGPL-3.0, SSPL-1.0, CC-BY-NC-4.0]
  allow_unknown: false
```

## Precedence

- `--fail-on` overrides the policy's `fail_on`.
- `--offline` forces offline mode. A policy with `offline: true` also forces it
  when the flag is absent.
- `--advisory-db` supplies a local advisory database. It is used in place of a
  network lookup and works with `--offline`.
- `exclude_paths` from the policy are combined with scanner exclusions and the
  secrets rule pack allowlist.

## Allowances

An allowance suppresses matching findings. Every selector present in one entry
must match: they are combined with AND. At least one selector is required and a
non-empty `reason` is mandatory.

```yaml
allow:
  - id: PIPE-CFG-018
    file: pyproject.toml
    reason: library distributed from source, no application lockfile
    expires: 2026-12-31

  - fingerprint: 4f8c2a1d9e0b7c63
    reason: documented test credential, tracked in issue SEC-142
    expires: 2026-06-30

  - scanner: deps
    id: PIPE-DEP-001
    reason: accepted until the upstream fix ships
    expires: 2026-03-01
```

Supported keys:

| Key | Meaning |
| --- | --- |
| `scanner` | Match only findings from `secrets`, `deps`, `licenses`, `sbom` or `config`. |
| `id` / `rule` | Match a rule identifier such as `PIPE-SEC-001`. `rule` is an alias. |
| `fingerprint` | Match the stable finding fingerprint. |
| `file` / `path` | Match a path glob. `path` is an alias. |
| `reason` | Required human explanation stored in the gate result. |
| `expires` | Optional ISO date (`YYYY-MM-DD`). |

An allowance is active through the end of its `expires` date. After that date it
is reported as stale and suppresses nothing. An active allowance that matches no
current finding is also reported as stale. Stale allowances appear in console,
JSON, SARIF and Markdown output but do not by themselves fail the gate; remove
them or correct their selectors during review.

A scanner-only allowance is powerful. Prefer a `fingerprint` or an `id` plus a
`file` glob so the exception cannot hide unrelated future findings.

## Fingerprints

A fingerprint is stable across line-number changes:

```text
sha256(scanner + rule_id + path + normalized_context)[:16]
```

The context is scanner specific. Secret rules store a SHA-256 digest of the
matched value, never the value itself. Dependency findings use the package
ecosystem, name, version and vulnerability identifier. Configuration findings
use a structured context such as `permissions:write-all` or
`action-pin:actions/checkout@v4`.

Fingerprints survive edits elsewhere in the file, but renaming or moving a file
changes the path and therefore the fingerprint. Regenerate the baseline or
update the allowance after a rename.

## Baselines

A baseline records the findings that already exist, so a gate can block only new
findings while a team pays down its backlog.

```console
pipelineguard scan . --write-baseline .pipelineguard-baseline.json
pipelineguard scan . --baseline .pipelineguard-baseline.json
```

`--write-baseline` writes every actionable finding after policy evaluation and
still returns the normal gate exit code. `--baseline` accepts either a baseline
file or a `results.json` report. The gate counts only findings whose fingerprint
is absent from the baseline. JSON and Markdown reports include new, fixed and
existing counts.

Baselines do not suppress findings: suppressed findings are removed from all
counts, while baseline findings remain visible as existing. Prefer an allowance
mechanism only for deliberate, documented exceptions, and a baseline for bulk
backlog management.

## Defaults and exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Gate passed. |
| `1` | Gate failed because of findings, budgets, required scanners or scanner errors. |
| `2` | Tool, policy, path or configuration error. |

Policy parse errors, unknown keys, unknown severities, missing policy files and
missing advisory databases are tool errors and return `2`.
