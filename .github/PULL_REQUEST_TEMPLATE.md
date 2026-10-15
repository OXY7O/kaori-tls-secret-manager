## Summary

Describe what changed and why operators or contributors need it.

## Scope

- Affected CLI subcommands / wizard menus:
- Documentation or evidence changes:
- Compatibility / user-visible output impact:

## Validation

- [ ] Offline Python regression tests run (`python3 -m unittest discover -s tests -v`)
- [ ] Python syntax checks run for modified code
- [ ] Bash syntax checks run for modified launchers
- [ ] Help and `--plain` checked if CLI output changed
- [ ] Negative cases and fail-closed behavior covered if any mutation path changed
- [ ] Kubernetes-specific validation, if applicable, is documented separately from automated CI results

## Safety and privacy

- [ ] No credentials, kubeconfigs, private keys, internal endpoint data or real evidence added
- [ ] No weakened approval, HOLD, backup, journal or Kubernetes precondition checks
- [ ] Changes affecting operators reflected in README/command reference/changelog

## Linked issue / notes

Closes #

## Release impact

Explain whether versioning, release notes, or operator/security documentation must change. A merged PR does not authorize changes to third-party infrastructure.
