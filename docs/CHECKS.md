# Checks reference

Every finding has a stable identifier, a severity and a scanner. The same
identifier appears in console output, JSON, SARIF rule metadata and Markdown
reports. Use `pipelineguard rules list` to print the live list.

## Scan targets

| Scanner | Inputs |
| --- | --- |
| `secrets` | Working tree, the git index with `--staged`, and added lines from git history with `--history`. Text files up to the configured size limit; binary files are skipped. |
| `deps` | `requirements*.txt` (recursive includes), `pyproject.toml` (PEP 621 and Poetry), `poetry.lock`, `package-lock.json` v1-v3, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`, `Cargo.lock`. |
| `licenses` | The same parsed components as `deps`, using license metadata from lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock` when present). |
| `sbom` | The same manifests as `deps`, collected for CycloneDX 1.5 output. |
| `config` | `Dockerfile` and `*.dockerfile`, `.github/workflows/*.yml` and `*.yaml`, plus repository hygiene checks. |

The dependency scanner audits PyPI, npm, Go and crates.io components through
OSV. Package URLs follow the [purl specification](https://github.com/package-url/purl-spec).
Online lookups use only `https://api.osv.dev/v1/querybatch`; `--offline` uses a
local advisory file or the 24 hour cache.

## Secret rules

Secret rules run line by line. A candidate must meet the rule's minimum length,
must not be a documented placeholder or vendor example, and must pass the
entropy floor. Values are matched by regular expression and, where needed,
contextual keywords reduce noise.

| Rule | Severity | Credential | Remediation |
| --- | --- | --- | --- |
| `PIPE-SEC-001` | Critical | AWS access key ID | Revoke the key in IAM, rotate credentials and load them from a secret manager. |
| `PIPE-SEC-002` | Critical | AWS secret access key | Revoke the key pair in IAM and rotate every credential that used it. |
| `PIPE-SEC-003` | Critical | GitHub token | Revoke the token in GitHub settings and replace it with a short-lived installation token. |
| `PIPE-SEC-004` | Critical | GitHub fine-grained personal access token | Revoke the token in GitHub settings and issue a least-privilege replacement. |
| `PIPE-SEC-005` | Critical | GitLab personal access token | Revoke the token under User Settings, Access Tokens. |
| `PIPE-SEC-006` | High | Slack token | Revoke the token in the Slack app configuration and reinstall the app. |
| `PIPE-SEC-007` | High | Slack incoming webhook | Revoke the webhook in Slack and store the replacement as a secret. |
| `PIPE-SEC-008` | Critical | Stripe live secret key | Roll the key in the Stripe dashboard and audit recent API activity. |
| `PIPE-SEC-009` | High | Google API key | Delete the key in Google Cloud Console and restrict replacements by API and referrer. |
| `PIPE-SEC-010` | Critical | Private key block | Remove the key from the repository, rotate it and store it in a secret manager. |
| `PIPE-SEC-011` | High | JSON Web Token | Revoke the signing key, rotate the token and shorten its lifetime. |
| `PIPE-SEC-012` | High | npm access token | Revoke the token on npmjs.com and publish with provenance instead. |
| `PIPE-SEC-013` | High | PyPI upload token | Revoke the token in PyPI account settings and use trusted publishing. |
| `PIPE-SEC-014` | High | SendGrid API key | Delete the key in SendGrid and create a restricted replacement. |
| `PIPE-SEC-015` | High | Twilio auth token | Rotate the auth token in the Twilio console. |
| `PIPE-SEC-016` | High | Heroku API key | Revoke the key in Heroku account settings and rotate the credential. |
| `PIPE-SEC-017` | Critical | Azure storage account key | Rotate both storage keys and move consumers to managed identities. |
| `PIPE-SEC-018` | High | Generic credential assignment | Remove the literal, rotate the credential and load it from the environment or a secret manager. |

### Redaction and placeholders

Findings never contain a raw credential. Values of 12 or more characters are
rendered as the first four and last four characters separated by `...`; shorter
values are replaced entirely with asterisks. The stored context is a SHA-256
digest of the matched value.

Documented vendor examples and obvious placeholders (`changeme`, `<your-token>`,
`${API_KEY}`, `example`, and similar forms) are ignored. Paths such as
`**/*.min.js`, `**/*.map`, `**/vendor/**` and `**/third_party/**` are
allowlisted by the bundled rule pack. The policy `exclude_paths` option adds
path globs for every scanner.

## Dependency rules

| Rule | Severity | Meaning |
| --- | --- | --- |
| `PIPE-DEP-001` | Severity from the advisory, medium when unknown | A resolved package version is listed in OSV. The finding includes the advisory identifier, aliases, fixed versions and references. |
| `PIPE-DEP-002` | Low | A declaration is a range, an unversioned direct URL or otherwise cannot resolve to one concrete version. Pin exact versions and commit the ecosystem lockfile. |

OSV severity is taken from a database-specific severity label first, then from a
CVSS v3 vector or numeric score. Advisories with no usable severity data default
to medium. Malformed advisory entries are rejected when an advisory file is
loaded; an OSV transport failure degrades the scan to cached or inventory-only
metadata instead of crashing it.

## License rules

The `licenses` scanner reads the components resolved by the dependency parsers.
License identifiers are compared case-insensitively against the policy denylist.
Deprecated `-only` and `-or-later` suffixes and the legacy `+` form fold onto the
base identifier, so `GPL-3.0`, `GPL-3.0-only` and `GPL-3.0-or-later` all match a
`GPL-3.0` deny entry. SPDX expressions such as `MIT OR Apache-2.0` are split into
individual identifiers.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `PIPE-LIC-001` | High | A resolved dependency license matches an entry in `licenses.deny`. The finding includes the component name, version, license and remediation. |
| `PIPE-LIC-002` | Low | A resolved dependency has no usable license metadata. Reported only when `licenses.allow_unknown` is `false`. |

The default denylist is `GPL-3.0`, `AGPL-3.0` and `SSPL-1.0`. The default for
`allow_unknown` is `true`, so repositories without license metadata keep their
current verdict. Configure the scanner in [POLICY.md](POLICY.md#license-policy).

## Dockerfile checks

| Rule | Severity | Check |
| --- | --- | --- |
| `PIPE-CFG-001` | High | The final stage runs as root or has no `USER` instruction. |
| `PIPE-CFG-002` | Medium | The base image is untagged or uses `latest`, `edge`, `main` or `master`. |
| `PIPE-CFG-003` | Low | The base image has a tag but no `@sha256:` digest. |
| `PIPE-CFG-004` | Medium | `ADD` downloads a remote URL without checksum verification. |
| `PIPE-CFG-005` | Critical | `ARG` or `ENV` bakes a credential into an image layer. |
| `PIPE-CFG-006` | Low | `apt-get install` omits `--no-install-recommends` or leaves `/var/lib/apt/lists` in the layer. |
| `PIPE-CFG-007` | High | `curl` or `wget` output is piped into a shell. |
| `PIPE-CFG-008` | Medium | `chmod 777` makes a path world-writable. |

## GitHub Actions checks

| Rule | Severity | Check |
| --- | --- | --- |
| `PIPE-CFG-009` | Medium for third-party actions, low for first-party actions | An action reference is a tag or branch rather than a full 40 character commit SHA. Local `./` and `docker://` references are ignored. |
| `PIPE-CFG-010` | High for `write-all`, informational when absent | The workflow requests `permissions: write-all` or declares no top-level permissions block. |
| `PIPE-CFG-011` | Critical | A `pull_request_target` workflow checks out PR-controlled code through `github.event.pull_request.head`, `github.head_ref` or `refs/pull/`. |
| `PIPE-CFG-012` | High | A `run` script interpolates `github.event` data directly. Pass values through `env:` instead. |
| `PIPE-CFG-013` | High | A workflow echoes a `secrets.*` expression. |
| `PIPE-CFG-014` | High | A `workflow_run` workflow checks out `github.event.workflow_run.head` code with a privileged token. |

Workflow YAML is parsed when valid. Invalid YAML produces a warning in scanner
metadata and falls back to conservative text matching so a broken workflow does
not hide an obvious risk.

## Repository hygiene checks

| Rule | Severity | Check |
| --- | --- | --- |
| `PIPE-CFG-015` | High | A real `.env` file is committed. `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.test` and `.env.ci` are exempt. In a git repository, untracked and ignored files are not reported. |
| `PIPE-CFG-016` | Medium | The repository has no `.gitignore`. |
| `PIPE-CFG-017` | Medium | `.gitignore` does not exclude `.env` files. |
| `PIPE-CFG-018` | Medium | A manifest has no matching lockfile. |
| `PIPE-CFG-019` | Critical | A private key file (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `*.pem`, `*.key`, `*.p12`, `*.pfx` or files under `.ssh/`) contains private key material. Public keys are ignored. |

## What is intentionally not checked

pipelineguard is a static gate. It does not build images, execute workflows,
scan container layers, inspect compiled binaries, verify exploitability, or
replace runtime protection. Secret detection is pattern and entropy based, so it
will miss novel formats and can produce false positives. The dependency audit
reflects the OSV database at scan time, not the full advisory universe.
