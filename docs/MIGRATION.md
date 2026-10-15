# Private-to-public migration plan

**Status: original source and regression tests migrated into the public development branch; local/offline checks PASS. The branch is Draft and still lacks real Kubernetes DEV/UAT acceptance and a stable release.** The private historical Issue #67 / PR #68 remain closed-unmerged and preserved. The private runbook main catalog points here.

1. Review each source file and fixture; sanitize environment-specific hostnames, namespaces, internal deployment assumptions, network addresses, credentials, company identifiers, and paths. Preserve **no private Git history**.
2. Transfer only reviewed standalone code and synthetic tests: the former Python launcher, renewal engine, inventory, operations diagnostics, wizard and tests; normalize imports and paths to the public layout.
3. Integrate the locally tested CRUD prototype (Create, metadata-only Read, same-SAN Update, governed Delete) after threat modeling and code review. Add operator-friendly menus without creating any unsafe default action.
4. Add all missing negative scenarios; run offline tests on GitHub Actions with no Kubernetes credentials; review software supply chain and publish versioned checksums.
5. Run real DEV/UAT signed approval and rollback/restore drills with a human operator, collecting private evidence outside public Git.
6. Publish a signed/tagged, versioned release only after passing acceptance.
7. The existing private repository has already merged a **handoff pointer** into its Kubernetes catalog. **Only after public release acceptance** may that pointer become pinned version/checksum installation instructions; keep the historical, unmerged implementation available through its archived PR.

Tracking in the public project: migration #1, Create #2, Delete #3, architecture Draft PR #4, and Read/Update #5. The legacy private issue/PR are closed as transferred; the private documentation handoff has been merged.

## Actual completed source transfer

- Original modules: `scripts/kubernetes/tls-secret-manager/{tls_secret_manager.py,tls_secret_wizard.py,tls_inventory.py,tls_ops.py,tls-secret-manager.sh}`.
- Original example files and all 11 historical regression test files, with environment-specific fixture identifiers replaced by synthetic `example.test` values.
- Original menu/ASCII branding retained. Wizard now offers 10 Create and 11 Delete; both call the guarded CRUD engine, not a second UI.
- Root entrypoint: `scripts/tls-secret-manager.sh`. The former private-checkout bridge is removed. Only one clone is needed.
- Offline CI covers original regression suite and standalone CRUD tests. **Real Kubernetes acceptance, security review, recovery exercises and versioned release still pending.**
