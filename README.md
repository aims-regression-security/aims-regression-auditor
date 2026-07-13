# AIMS Regression Auditor

This private repository is the protected trust boundary for AIMS regression
receipts. Candidate repository write access does not grant access to the signing
key or permission to modify the default-branch verifier.

The default branch contains:

- the authoritative Ed25519 public-key trust policy;
- the protected receipt issuer and verifier implementation;
- independently reviewed, candidate-bound decisions under `decisions/`.

The signing key, read-only AIMS deploy key, and security GitHub App private key
are GitHub environment secrets. The `regression-auditor` environment permits
only the `main` branch, so a collaborator cannot modify a workflow on another
ref and dispatch it with those secrets. AIMS code is read as untrusted input and
is never executed by the verifier.

Every `decisions/*.json` change must be introduced by a pull request and
approved by a GitHub reviewer whose numeric user ID differs from the
implementation workflow actor. The issuer verifies that merged review through
the GitHub API before using the signing key. A decision therefore cannot become
authoritative merely by claiming an independent identity in JSON.

The personal private-repository plan does not provide environment required
reviewers. Independence is fail-closed through default-branch pull-request
protection and a distinct security reviewer account instead.

The AIMS-side workflow has no status/check write permission. It only dispatches
immutable PR coordinates to this repository. This repository verifies the
signed receipt and publishes `Regression Auditor / trusted-verifier` through a
separately owned GitHub App with Checks write permission. AIMS branch rules pin
the required check source to that App.

The trust policy stays `provisioned: false` until independent ownership, App
installation, dispatch credentials, signed receipt issuance, and the pinned AIMS
required check have all passed their repository-write probes. Activation is a
separate reviewed PR.
