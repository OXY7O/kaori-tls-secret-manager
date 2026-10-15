# Private-to-public migration plan

**Status: NOT CUT OVER.** The public repository is still architecture-only; the former private implementation PR has been closed **unmerged as transferred**, while its commit/issue history remains archived. The private runbook catalog now points to the standalone project. This local package is not yet uploaded to the public development branch and does not authorize production rollout.

1. Review each source file and fixture; sanitize environment-specific hostnames, namespaces, internal deployment assumptions, network addresses, credentials, company identifiers, and paths. Preserve **no private Git history**.
2. Transfer only reviewed standalone code and synthetic tests: the former Python launcher, renewal engine, inventory, operations diagnostics, wizard and tests; normalize imports and paths to the public layout.
3. Integrate the locally tested CRUD prototype (Create, metadata-only Read, same-SAN Update, governed Delete) after threat modeling and code review. Add operator-friendly menus without creating any unsafe default action.
4. Add all missing negative scenarios; run offline tests on GitHub Actions with no Kubernetes credentials; review software supply chain and publish versioned checksums.
5. Run real DEV/UAT signed approval and rollback/restore drills with a human operator, collecting private evidence outside public Git.
6. Publish a signed/tagged, versioned release only after passing acceptance.
7. The existing private repository has already merged a **handoff pointer** into its Kubernetes catalog. **Only after public release acceptance** may that pointer become pinned version/checksum installation instructions; keep the historical, unmerged implementation available through its archived PR.

Tracking in the public project: migration #1, Create #2, Delete #3, architecture Draft PR #4, and Read/Update #5. The legacy private issue/PR are closed as transferred; the private documentation handoff has been merged.
