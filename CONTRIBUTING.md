# Contributing to KAORI TLS Certificate Manager

Thank you for improving KAORI. We welcome reproducible bug reports, documentation, accessibility improvements, synthetic fixtures, test coverage and security-minded changes to the CLI.

## Start here

1. Read [README.md](README.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and the [architecture](docs/ARCHITECTURE.md).
2. Search the [issue tracker](https://github.com/OXY7O/kaori-tls-secret-manager/issues) for related reports. Open an issue for design-level changes, especially changes to mutation behavior.
3. Fork or branch from the active development source; create a focused PR with a clear problem statement and explanation of user-facing behavior.
4. Keep tests offline and use fake cluster data. **Never connect public CI to live Kubernetes.**
5. If your change touches Create/Update/Delete, document authorization, scope, failure modes, rollback/reconciliation and safe negative test cases.

## Development setup

Supported test workstation: Linux or WSL, Python 3.10+, Bash, Git, OpenSSL and age. kubectl is needed only for approved local cluster integration.

~~~bash
git clone https://github.com/OXY7O/kaori-tls-secret-manager.git
cd kaori-tls-secret-manager

python3 -m unittest discover -s tests -v
bash -n scripts/tls-secret-manager.sh scripts/kaori-tls-secret-manager.sh \
  scripts/kubernetes/tls-secret-manager/tls-secret-manager.sh
python3 -m py_compile scripts/tls_crud.py \
  scripts/kubernetes/tls-secret-manager/tls_secret_manager.py \
  scripts/kubernetes/tls-secret-manager/tls_secret_wizard.py \
  scripts/kubernetes/tls-secret-manager/tls_inventory.py \
  scripts/kubernetes/tls-secret-manager/tls_ops.py
bash scripts/tls-secret-manager.sh doctor
bash scripts/tls-secret-manager.sh crud --help
~~~

**Note:** use the default `main` branch for contributions. The `0.1.0-rc.1` prerelease is intended for evaluation only; do not create or use production credentials for local tests.

## Pull request requirements

- Keep the scope narrow. Explain **why** the change is needed and which CLI functions, menus, evidence artifacts or safeguards are affected.
- Include automated tests for behavioral changes, especially **HOLD, RBAC errors, controller ownership, API timeout, UID/resourceVersion drift, encryption failure and uncertain result** cases.
- Preserve the wizard's single-operator workflow without imposing manual enterprise approval artifacts; keep advanced signed approval flows as explicitly separate options.
- Preserve guided operation semantics, legacy commands, readable errors and `--plain`/`NO_COLOR` compatibility unless an intentionally versioned change is agreed.
- Do not weaken dependency checks, backup requirements, immutable plan checks or server-side mutation preconditions to make a test pass.
- Document user-facing additions in README, [command reference](docs/COMMAND-REFERENCE.md) and [CHANGELOG.md](CHANGELOG.md) where relevant.
- Include a short manual test plan and distinguish **offline PASS** from Kubernetes DEV/UAT acceptance.

## Sensitive information and safe examples

Never commit or attach real certificate private keys, kubeconfigs, cluster credentials, signed approvals, encrypted recovery identities, production domains, internal IPs, unsanitized logs or confidential evidence. Use reserved example domains and synthetic fixtures. Scrub screenshots and terminal transcripts before publication.

A vulnerable behavior is **not** a normal bug report: see [SECURITY.md](SECURITY.md) for private disclosure. Do not publicly post proof-of-concept payloads involving real credentials.

## Review and releases

Maintainers review for correctness, regression, operator ergonomics and security. A green offline CI run is **necessary but not sufficient** to approve a production-impacting change. Tags and release artifacts are published only after the [release checklist](docs/RELEASE-CHECKLIST.md) is satisfied. Contributions are accepted under the repository's [Apache-2.0 License](LICENSE).

For common usage questions, see [SUPPORT.md](SUPPORT.md) and [FAQ](docs/FAQ.md).
