# Contributing

Thanks for improving pipelineguard. The project favours small, reviewable
changes that keep the tool deterministic, offline-friendly and safe to run on
untrusted repositories.

## Development setup

Requirements: Python 3.10 or newer and git.

```console
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the full local check before opening a pull request:

```console
make check
```

`make check` runs `ruff check`, `ruff format --check`, `bandit -r src` and the
pytest suite. You can also run the tools directly:

```console
ruff check src tests
ruff format --check src tests
bandit -r src
pytest
```

## Adding a secret rule

1. Add an entry to `src/pipelineguard/secrets_rules.yml` with the next free
   `PIPE-SEC-*` identifier, a severity, one or more regular expressions, the
   capture group that holds the credential, minimum length, optional entropy
   floor, keywords, remediation and references.
2. Use a realistic but fake value in tests. Never commit a live credential.
3. Add the rule to `docs/CHECKS.md`.
4. Add a positive test to `tests/test_secrets_rules.py` and, when the rule
   needs context or entropy behaviour, a test to `tests/test_secrets_behavior.py`.

## Adding a configuration check

1. Add a `CheckDefinition` to `CONFIG_CHECKS` in
   `src/pipelineguard/scanners/config.py` with the next free `PIPE-CFG-*`
   identifier.
2. Emit it with `finding_from_check`, including a stable `context` so the
   fingerprint survives unrelated edits.
3. Add tests to `tests/test_config_scanner.py` and update `docs/CHECKS.md`.

## Adding a dependency parser

Parsers return a `ParsedProject` with components, warnings and the files that
were read. Components need an ecosystem, name, version, direct flag, source and
purl. Unpinned declarations should produce a `PIPE-DEP-002` warning. Add fixture
tests to `tests/test_requirements.py` or `tests/test_lockfiles.py`.

## Test data

- Put intentionally vulnerable fixtures under `examples/vulnerable-repo/`.
- Every credential in the repository and test suite must be fake and clearly
  labelled as such.
- Do not add real tokens, private keys, customer data or internal hostnames.
- Prefer small fixtures that exercise one behaviour. The test suite must not
  require network access.

## Style

- Python 3.10 compatible syntax, type hints on public functions.
- Line length 100, formatted with `ruff format`.
- No emojis in code, documentation or output.
- User-facing messages should state the problem and the remediation.
- New runtime dependencies need a strong justification; the runtime dependency
  list is intentionally limited to PyYAML.

## Commits and pull requests

- Keep one logical change per commit with an imperative subject.
- Describe the problem, the approach and the verification commands in the pull
  request.
- Include tests for new behaviour and update documentation when a command,
  output format, rule or policy key changes.
- Do not include generated artifacts, virtual environments or cache directories.

By contributing you agree that your contribution is licensed under the MIT
License. Be respectful and technical in reviews; disagreement about a detection
rule is welcome when it includes evidence.
