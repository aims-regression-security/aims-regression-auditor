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
Protected Regression Auditor issuer and verifier trust root for AIMS
