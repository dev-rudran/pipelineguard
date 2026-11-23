# Five-minute quickstart

## 1. Install

```console
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python -m pip install -e .
```

## 2. Scan a deliberately vulnerable repository

```console
$ pipelineguard scan examples/vulnerable-repo \
    --offline \
    --advisory-db src/pipelineguard/advisories/osv-fixture.json
Gate: FAIL
  - 23 finding(s) at or above severity high
```

`--offline` uses the bundled advisory fixture instead of the OSV API, so the
demo is deterministic and works without network access.

## 3. Scan a clean repository

```console
$ pipelineguard scan examples/clean-repo --offline
pipelineguard: PASS
```

## 4. Produce every artifact

```console
$ pipelineguard scan examples/vulnerable-repo --offline \
    --advisory-db src/pipelineguard/advisories/osv-fixture.json \
    --format all --output-dir out
```

This writes `results.json`, `results.sarif`, `comment.md` and `sbom.cdx.json`.

## 5. Use it in CI

Copy `examples/consumer-workflow.yml` or call the reusable workflow from
`.github/workflows/security-gate.yml`. Locally, install the hook with:

```console
$ pre-commit install
```

Policy thresholds, allowlists and expiring exceptions live in
`pipelineguard.yaml`; see `docs/POLICY.md`.
