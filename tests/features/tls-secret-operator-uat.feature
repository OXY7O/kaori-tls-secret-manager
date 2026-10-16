# Human-readable operator UAT specification; not run automatically by unittest.
# Real-cluster UAT requires an explicit isolated environment and authorization.
@manual @kubernetes-uat @no-production
Feature: Guarded TLS Secret lifecycle for one operator

  Scenario: A scaled-to-zero Deployment still blocks Delete
    Given a synthetic TLS Secret referenced by a Deployment with zero replicas
    When the operator requests a Delete preflight
    Then the result is HOLD with the named Deployment
    And no executable Delete plan or write is produced

  Scenario: Restricted RBAC cannot be interpreted as no consumers
    Given permission to read Secrets but not workload templates
    When the operator requests a Delete preflight
    Then the scan fails closed or returns HOLD
    And no Delete write is sent

  Scenario: Verified Delete creates a recoverable encrypted backup
    Given a synthetic unused TLS Secret and a protected age identity
    When the operator approves the exact target and confirms UNUSED
    Then the encrypted backup is verified by local decryption before Delete
    And successful completion means the original Secret UID is absent

  Scenario: An ambiguous Delete can only be reconciled
    Given the original Delete journal has MUTATION_UNCERTAIN
    When the operator opens Delete recovery
    Then the current Secret observation is displayed without a write
    And guided Restore is on HOLD

  Scenario: Verified Delete can be restored with no overwrite
    Given the original Delete journal is COMPLETE_ABSENCE_VERIFIED
    And the original cluster and namespace identities have not changed
    And the target Secret does not exist
    And the encrypted original backup can be decrypted
    When the operator types the exact RESTORE target
    Then KAORI creates only the absent Secret
    And the restored certificate and private key are verified
    And the restored Kubernetes UID is different from the deleted UID

  Scenario: DNS and explicit load balancer targets are diagnosed separately
    Given a hostname currently resolves to the old load balancer
    And a new approved load balancer IP is available
    When TLS Doctor checks the hostname with the new IP as connect target
    Then TLS SNI and hostname trust still use the original hostname
    And the served fingerprint is compared to the stored Secret
    And a mismatch never automatically triggers a new mutation
