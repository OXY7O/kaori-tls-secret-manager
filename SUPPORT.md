# Support

## Find your answer

- [README](README.md): overview, quick start, available commands and release status.
- [FAQ](docs/FAQ.md): stored versus served certificate, DELETE HOLD, backup keys and diagnostics.
- [Command reference](docs/COMMAND-REFERENCE.md): all available CLI commands and examples.
- [Local test guide](docs/LOCAL-TEST.md): offline checks and approved DEV/UAT read-only examples.
- [Operator guide](docs/OPERATOR-GUIDE.md) and [Delete SOP](docs/DELETE-TLS-SECRET-SOP.md): governed change workflows.
- [Security policy](SECURITY.md): secret handling and private vulnerability reports.

## Ask questions or report a bug

Use [GitHub Issues](https://github.com/OXY7O/kaori-tls-secret-manager/issues) for repeatable **non-sensitive** bugs, documentation defects or feature requests. Include the command and arguments with secrets redacted, operating system/Python versions, expected versus observed behavior, and the result of an offline reproduction if possible.

Do **not** share real kubectl output, production hostnames, certificate private keys, kubeconfig, backup identity, approval records, plan files or journal contents. Prefer fake data and minimal reproductions.

## Security disclosures

Do **not** open a public issue for an exploitable vulnerability. See [SECURITY.md](SECURITY.md) for the private disclosure route.

## Operational responsibility

KAORI is distributed as-is under Apache-2.0. The current development preview has no SLA, production support commitment or completed DEV/UAT acceptance. Maintainers cannot provide emergency hands-on access to clusters or authorize changes in your environment. For any live incident, follow your organization's incident response, certificate owner and recovery procedure.
