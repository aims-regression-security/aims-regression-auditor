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
approved by a GitHub reviewer whose numeric user ID differs from the decision's
bound implementation identity. The issuer verifies that merged review through
the GitHub API before using the signing key. The receipt copies implementation
identity from the protected decision, not from the security account that starts
the issuer workflow, and the external verifier later compares it with the actual
AIMS PR author returned by GitHub.

The personal private-repository plan does not provide environment required
reviewers. Independence is fail-closed through default-branch pull-request
protection and a distinct security reviewer account instead.

The AIMS-side workflow has no status/check write permission. It dispatches only
the expected repository and pull-request number. The separately owned GitHub
App reads that pull request from GitHub, derives the actual base SHA, head SHA,
repository, base branch, and author identity, then verifies the complete PR
delta. Caller-supplied SHA or identity fields are not accepted. The App has
Checks write and Pull requests read permission, and AIMS branch rules pin the
required check source to that App.

The bootstrap order is fixed. First, merge the infrastructure with
`provisioned: false`; install the App; prove that the App can publish a failure
Check while trust is locked; and pin that App source in the AIMS ruleset. Next,
an independently reviewed activation PR changes the trust policy to true and
records the App integration ID and activation evidence. Only then may the
issuer create a signed receipt and the App publish a success Check. The
implementation account must have read-only or no issuer access after transfer.
