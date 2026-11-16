# Vulnerable demo repository

This repository exists to demonstrate what pipelineguard finds. Every credential
in this tree is fake and was generated for this fixture.

The AWS documentation example key `AKIAIOSFODNN7EXAMPLE` is intentionally
present here and is allowlisted by the scanner; it is a published vendor
example, not a credential.

Expected results on a default gate:

- secrets: several critical and high findings in `.env`, `app/settings.py` and `deploy/id_rsa`
- deps: a vulnerable Jinja2 pin matched against the offline advisory fixture
- config: root container, floating base image, secrets in ARG/ENV, curl piped to a shell,
  write-all workflow permissions, `pull_request_target` checkout of PR head, script
  injection, echoed secret, committed `.env`, missing `.env` ignore rule and a missing lockfile

Run it:

```console
pipelineguard scan examples/vulnerable-repo --offline \
  --advisory-db src/pipelineguard/advisories/osv-fixture.json
```
