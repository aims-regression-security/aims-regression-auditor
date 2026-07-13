# AIMS Regression Auditor

This private repository is the protected trust boundary for AIMS regression
receipts. Candidate repository write access does not grant access to the signing
key or permission to modify the default-branch verifier.

The default branch contains:

- the authoritative Ed25519 public-key trust policy;
- the protected receipt issuer and verifier implementation;
- independently reviewed, candidate-bound decisions under `decisions/`.

The signing key and the read-only AIMS deploy key are GitHub environment
secrets. AIMS code is never copied into this repository.

Every `decisions/*.json` change must be introduced by a pull request and
approved by a GitHub reviewer whose numeric user ID differs from the
implementation workflow actor. The issuer verifies that merged review through
the GitHub API before using the signing key. A decision therefore cannot become
authoritative merely by claiming an independent identity in JSON.

The personal private-repository plan does not provide environment required
reviewers. Independence is fail-closed through default-branch pull-request
protection and a distinct security reviewer account instead.
Protected Regression Auditor issuer and verifier trust root for AIMS
