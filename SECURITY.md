# Security policy

## Supported versions

Security fixes are provided for the latest 0.1.x release line. The project is
pre-1.0, so interfaces may change between minor releases.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Report it privately to
**rudraking2404@gmail.com** with:

- the affected version or commit,
- a description of the issue and its impact,
- a minimal reproduction or proof of concept that does not contain live
  credentials,
- any suggested remediation.

You should receive an acknowledgement within five business days. Please allow
time for a fix and coordinated disclosure before publishing details. Reports
about the accuracy of a detection rule are welcome as normal issues when they do
not expose a security weakness in pipelineguard itself.

## Handling of sensitive data

pipelineguard is built to be safe to run in CI and to archive its output.

- Raw secret values are never stored in findings. Messages and snippets contain
  redacted values such as `AKIA...T3V5`; values shorter than 12 characters are
  replaced entirely with asterisks.
- Fingerprints are `sha256(scanner + rule + path + normalized context)[:16]`. The
  context for a secret finding stores a SHA-256 digest of the value, not the
  value itself.
- The `.pipelineguard-cache` directory contains OSV advisory responses only. It
  never contains source code or credentials and is excluded by the bundled
  `.gitignore`.
- `--offline` disables all network access. Without `--advisory-db` the dependency
  scanner inventories packages but performs no vulnerability lookup.
- The only online endpoint is `https://api.osv.dev/v1/querybatch`. Requests use
  a fixed URL, a 10 second timeout, one retry and no credentials.
- Git commands are executed with an argument vector and `shell=False`. Output
  size and history depth are bounded.

## Limitations

pipelineguard is a static gate, not a guarantee. It does not execute builds or
containers, does not scan binary artifacts, does not verify exploitability, and
does not detect every secret format. Detection rules can produce false positives
and false negatives. Use it together with least-privilege credentials, secret
managers, dependency review and runtime protection.

If you discover that a finding or artifact contains an unredacted credential,
treat that as a security issue and report it privately using the process above.
