import base64
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from scripts import bounded_deploy_attestation_issue as issuer


CERTIFIED_SHA = "b4d91f646ebbfb7afaf7e0f0680487ceaab6cc85"
ARTIFACT_DIGEST = "92dcfdbd5655e136a7da5e04952f4c76ca82901c527fe0a376a70bcac3a54a76"
INSTALLER_DIGEST = "dbdc8bc7380287b8dc89528c937fbbe7347c7ea2437a84b698af61550113b39e"
LATEST_MANIFEST_DIGEST = "53656f7d144da879cd691fe9cc98e760366a62491c2631963bde8b131691b075"
PUBLISHER_SCRIPT_DIGEST = "58d3a02f849b4e5588712a9d46aff2471e55f045336292e6b0000b0233117f08"
SOURCE_TAG = "refs/tags/ac-source-v0.3.40-b4d91f646"
TAG_OBJECT_SHA = "56f2888cb971dca98ba732ce6760e361bed332f3"
PUBLISHER_COMMIT_SHA = "9b1537a7c3e99afcd3ddf1b3536d1b28d8cd944e"
SOURCE_TREE_SHA = "2863086fe85ab425f4d9707daff09cc8028d05ff"
PUBLISHER_DEPENDENCY_DIGESTS = {
    issuer.PUBLISHER_DEPENDENCY_PATHS[0]: "1" * 64,
    issuer.PUBLISHER_DEPENDENCY_PATHS[1]: "2" * 64,
    issuer.PUBLISHER_DEPENDENCY_PATHS[2]: "3" * 64,
}
REVIEWER = "github-app-id:4291228"
NOW = 1_784_500_000


def valid_decision() -> dict:
    return {
        "schema": issuer.DECISION_SCHEMA,
        "verdict": "PASS",
        "repository": "aim2nasa/aims",
        "operation": "deploy",
        "artifactKind": issuer.ARTIFACT_KIND,
        "issuer": issuer.ISSUER,
        "keyId": issuer.KEY_ID,
        "signatureAlgorithm": issuer.SIGNATURE_ALGORITHM,
        "certifiedSha": CERTIFIED_SHA,
        "artifactDigest": ARTIFACT_DIGEST,
        "installerDigest": INSTALLER_DIGEST,
        "latestManifestDigest": LATEST_MANIFEST_DIGEST,
        "publisherScriptDigest": PUBLISHER_SCRIPT_DIGEST,
        "commandContract": issuer.COMMAND_CONTRACT,
        "sourceTag": SOURCE_TAG,
        "tagObjectSha": TAG_OBJECT_SHA,
        "publisherCommitSha": PUBLISHER_COMMIT_SHA,
        "sourceTreeSha": SOURCE_TREE_SHA,
        "publisherFiles": {
            issuer.PUBLISHER_SCRIPT_PATH: PUBLISHER_SCRIPT_DIGEST,
            **PUBLISHER_DEPENDENCY_DIGESTS,
        },
        "sourceTagProtection": {
            "rulesetId": 19181898,
            "target": "tag",
            "enforcement": "active",
            "include": ["refs/tags/ac-source-*"],
            "rules": ["deletion", "non_fast_forward"],
            "bypassActors": [],
        },
        "auditorIdentity": "regression-auditor-agent:issue358-bounded-deploy",
        "auditorSessionId": "regression-auditor-session:issue358-bounded-deploy-01",
        "implementationIdentity": "github-actor-id:26228531",
        "decisionReviewerIdentity": REVIEWER,
        "issuedAt": NOW - 10,
        "expiresAt": NOW + 300,
        "evidence": ["Exact AC distribution manifest digest reviewed independently."],
    }


class BoundedDeployAttestationIssuerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "decisions").mkdir()
        self.decision_path = "decisions/issue358.json"
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.private_key_b64 = base64.b64encode(bytes(range(32))).decode("ascii")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_decision(self, value: dict) -> None:
        (self.root / self.decision_path).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def issue(self, decision: dict | None = None, **overrides):
        self.write_decision(decision or valid_decision())
        values = {
            "trust_root": self.root,
            "decision_path": self.decision_path,
            "repository": "aim2nasa/aims",
            "expected_reviewer_identity": REVIEWER,
            "expected_certified_sha": CERTIFIED_SHA,
            "expected_artifact_digest": ARTIFACT_DIGEST,
            "expected_installer_digest": INSTALLER_DIGEST,
            "expected_latest_manifest_digest": LATEST_MANIFEST_DIGEST,
            "expected_publisher_script_digest": PUBLISHER_SCRIPT_DIGEST,
            "expected_source_tag": SOURCE_TAG,
            "expected_tag_object_sha": TAG_OBJECT_SHA,
            "expected_publisher_commit_sha": PUBLISHER_COMMIT_SHA,
            "expected_source_tree_sha": SOURCE_TREE_SHA,
            "expected_publisher_dependency_digests": PUBLISHER_DEPENDENCY_DIGESTS,
            "private_key_b64": self.private_key_b64,
            "now": NOW,
        }
        values.update(overrides)
        return issuer.issue_attestation(**values)

    def test_valid_decision_signs_only_canonical_domain_separated_payload(self) -> None:
        attestation = self.issue()
        self.assertEqual(attestation["schema"], issuer.ATTESTATION_SCHEMA)
        self.assertEqual(attestation["issuer"], issuer.ISSUER)
        self.assertEqual(attestation["keyId"], issuer.KEY_ID)
        self.assertEqual(attestation["signatureAlgorithm"], "ed25519")
        self.assertEqual(
            set(attestation),
            {
                "schema",
                "repository",
                "operation",
                "artifactKind",
                "issuer",
                "keyId",
                "signatureAlgorithm",
                "certifiedSha",
                "artifactDigest",
                "installerDigest",
                "latestManifestDigest",
                "publisherScriptDigest",
                "commandContract",
                "sourceTag",
                "tagObjectSha",
                "publisherCommitSha",
                "sourceTreeSha",
                "publisherFiles",
                "decisionDigest",
                "issuedAt",
                "expiresAt",
                "signature",
            },
        )
        signed_payload = {key: value for key, value in attestation.items() if key != "signature"}
        self.private_key.public_key().verify(
            base64.b64decode(attestation["signature"], validate=True),
            issuer.signature_message(signed_payload),
        )

    def test_signature_binds_every_authorization_field(self) -> None:
        attestation = self.issue()
        signature = base64.b64decode(attestation["signature"], validate=True)
        for field in (
            "schema",
            "repository",
            "operation",
            "artifactKind",
            "issuer",
            "keyId",
            "signatureAlgorithm",
            "certifiedSha",
            "artifactDigest",
            "installerDigest",
            "latestManifestDigest",
            "publisherScriptDigest",
            "commandContract",
            "sourceTag",
            "tagObjectSha",
            "publisherCommitSha",
            "sourceTreeSha",
            "publisherFiles",
            "decisionDigest",
            "issuedAt",
            "expiresAt",
        ):
            with self.subTest(field=field):
                payload = {key: value for key, value in attestation.items() if key != "signature"}
                if isinstance(payload[field], str):
                    payload[field] += "x"
                elif isinstance(payload[field], dict):
                    payload[field] = {**payload[field], "unexpected.py": "4" * 64}
                else:
                    payload[field] += 1
                with self.assertRaises(Exception):
                    self.private_key.public_key().verify(
                        signature,
                        issuer.signature_message(payload),
                    )

    def test_decision_controls_both_sha_and_artifact_digest(self) -> None:
        for field, override_name, replacement in (
            ("certifiedSha", "expected_certified_sha", "a" * 40),
            ("artifactDigest", "expected_artifact_digest", "b" * 64),
        ):
            with self.subTest(field=field):
                decision = valid_decision()
                with self.assertRaisesRegex(ValueError, field):
                    self.issue(decision, **{override_name: replacement})

    def test_arbitrary_or_unreviewed_decisions_are_rejected(self) -> None:
        mutations = {
            "schema": "arbitrary.v1",
            "verdict": "FAIL",
            "repository": "attacker/repository",
            "operation": "release",
            "artifactKind": "arbitrary-file",
            "issuer": "local",
            "keyId": "attacker-key",
            "signatureAlgorithm": "rsa",
            "installerDigest": "a" * 64,
            "latestManifestDigest": "b" * 64,
            "publisherScriptDigest": "c" * 64,
            "commandContract": "arbitrary.command.v1",
            "decisionReviewerIdentity": "github-app-id:1",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                decision = valid_decision()
                decision[field] = replacement
                with self.assertRaisesRegex(ValueError, field):
                    self.issue(decision)

    def test_identity_evidence_and_validity_are_fail_closed(self) -> None:
        cases = (
            ("auditorIdentity", "github-actor-id:26228531"),
            ("auditorSessionId", ""),
            ("implementationIdentity", "github-actor-id:0"),
            ("evidence", []),
            ("issuedAt", NOW + 1),
            ("expiresAt", NOW),
        )
        for field, replacement in cases:
            with self.subTest(field=field):
                decision = valid_decision()
                decision[field] = replacement
                with self.assertRaises(ValueError):
                    self.issue(decision)

    def test_expired_or_overlong_decision_cannot_sign(self) -> None:
        expired = valid_decision()
        expired["issuedAt"] = NOW - 100
        expired["expiresAt"] = NOW
        with self.assertRaisesRegex(ValueError, "유효기간"):
            self.issue(expired)

        overlong = valid_decision()
        overlong["issuedAt"] = NOW - 10
        overlong["expiresAt"] = NOW + issuer.MAX_ATTESTATION_VALIDITY_SECONDS
        with self.assertRaisesRegex(ValueError, "유효기간"):
            self.issue(overlong)

    def test_source_tag_is_required_and_bound_into_signature(self) -> None:
        for value in (
            "ac-source-v0.3.40-b4d91f646",
            "refs/heads/main",
            "refs/tags/not-an-ac-source",
            "refs/tags/ac-source-../main",
        ):
            with self.subTest(value=value):
                decision = valid_decision()
                decision["sourceTag"] = value
                with self.assertRaisesRegex(ValueError, "sourceTag"):
                    self.issue(decision, expected_source_tag=value)

    def test_tag_object_sha_is_required_and_decision_bound(self) -> None:
        decision = valid_decision()
        decision["tagObjectSha"] = "INVALID"
        with self.assertRaises(ValueError):
            self.issue(decision, expected_tag_object_sha="INVALID")

    def test_publisher_commit_sha_is_required_and_decision_bound(self) -> None:
        decision = valid_decision()
        decision["publisherCommitSha"] = "INVALID"
        with self.assertRaises(ValueError):
            self.issue(decision, expected_publisher_commit_sha="INVALID")

    def test_source_tag_protection_evidence_is_exact_and_fail_closed(self) -> None:
        for mutation in (
            None,
            {},
            {
                "rulesetId": 19181898,
                "target": "tag",
                "enforcement": "active",
                "include": ["refs/tags/ac-source-*"],
                "rules": ["deletion", "non_fast_forward"],
                "bypassActors": None,
            },
        ):
            with self.subTest(mutation=mutation):
                decision = valid_decision()
                decision["sourceTagProtection"] = mutation
                with self.assertRaisesRegex(ValueError, "sourceTagProtection"):
                    self.issue(decision)

    def test_source_tree_and_publisher_dependency_map_are_exact(self) -> None:
        decision = valid_decision()
        decision["sourceTreeSha"] = "INVALID"
        with self.assertRaises(ValueError):
            self.issue(decision, expected_source_tree_sha="INVALID")

        for mutation in (
            {},
            {issuer.PUBLISHER_DEPENDENCY_PATHS[0]: "1" * 64},
            {**PUBLISHER_DEPENDENCY_DIGESTS, "unexpected.py": "4" * 64},
            {**PUBLISHER_DEPENDENCY_DIGESTS, issuer.PUBLISHER_DEPENDENCY_PATHS[0]: "INVALID"},
        ):
            with self.subTest(mutation=mutation):
                decision = valid_decision()
                decision["publisherFiles"] = {
                    issuer.PUBLISHER_SCRIPT_PATH: PUBLISHER_SCRIPT_DIGEST,
                    **mutation,
                }
                with self.assertRaises(ValueError):
                    self.issue(
                        decision,
                        expected_publisher_dependency_digests=mutation,
                    )

    def test_path_traversal_cannot_select_an_unprotected_decision(self) -> None:
        self.write_decision(valid_decision())
        with self.assertRaisesRegex(ValueError, "안전한"):
            self.issue(decision_path="decisions/../outside.json")

    def test_bad_private_key_is_rejected_without_fallback(self) -> None:
        with self.assertRaisesRegex(ValueError, "32-byte"):
            self.issue(private_key_b64=base64.b64encode(b"short").decode("ascii"))

    def test_all_deploy_artifact_digests_must_be_lowercase_sha256(self) -> None:
        for override in (
            "expected_installer_digest",
            "expected_latest_manifest_digest",
            "expected_publisher_script_digest",
        ):
            with self.subTest(override=override):
                decision = valid_decision()
                field = {
                    "expected_installer_digest": "installerDigest",
                    "expected_latest_manifest_digest": "latestManifestDigest",
                    "expected_publisher_script_digest": "publisherScriptDigest",
                }[override]
                decision[field] = "INVALID"
                with self.assertRaises(ValueError):
                    self.issue(decision, **{override: "INVALID"})


if __name__ == "__main__":
    unittest.main()
