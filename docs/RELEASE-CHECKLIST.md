# Release acceptance checklist

Status: **not approved**. This checklist is not evidence of a release.

- [ ] Source and tests are sanitized and present in the public repository, with Apache-2.0 LICENSE.
- [ ] Public CI executes Python compilation, synthetic offline regression, static/security scanning.
- [ ] Create, Read, Update, Delete API behaviour validated on a scoped DEV/UAT cluster.
- [ ] Negative tests: RBAC denied, context mismatch, existing/missing Secret, wrong PEM/key/SAN,
      expired/untrusted source, owner/controller management, stale UID/RV, changed Ingress refs.
- [ ] Update backup decrypt/restore exercise, deletion precondition conflict, uncertain journal
      recovery, endpoint verification and application owner acceptance documented.
- [ ] Public help and docs accurately describe command semantics, trust anchors and limitations.
- [ ] No private evidence, credential material or internal hostnames in public Git/history/artifacts.
- [ ] A signed/attested versioned release, checksums, install and upgrade instructions exist.
- [ ] Internal runbook references pinned release+checksum; release is not auto-adopted.

Do not infer PASS from an offline unit suite or a docs-only GitHub PR.
