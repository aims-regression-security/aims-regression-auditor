#!/usr/bin/env python3
"""Issue a domain-separated, decision-bound Ed25519 deploy attestation.

The protected Regression Auditor key is reused deliberately.  A caller cannot
choose an arbitrary payload: the certified source SHA and artifact digest must
already be authorized by a short-lived decision merged to the protected
default branch.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any


PRIVATE_KEY_ENV = "AIMS_REGRESSION_AUDITOR_ED25519_PRIVATE_KEY_B64"
ATTESTATION_SCHEMA = "aims.bounded_deploy_attestation.v1"
DECISION_SCHEMA = "aims.bounded_deploy_attestation_decision.v1"
ISSUER = "github-environment:regression-auditor"
KEY_ID = "primary-2026-07"
SIGNATURE_ALGORITHM = "ed25519"
ARTIFACT_KIND = "aims-auto-clicker-distribution-manifest"
COMMAND_CONTRACT = "aims.auto_clicker.publish_provenance_release.v1"
PUBLISHER_DEPENDENCY_PATHS = (
    "tools/auto_clicker_v2/scripts/ac_build_provenance.py",
    "tools/auto_clicker_v2/execution_provenance.py",
    "tools/auto_clicker_v2/provenance_trust.py",
)
PUBLISHER_SCRIPT_PATH = "tools/auto_clicker_v2/scripts/publish_provenance_release.ps1"
MAX_ATTESTATION_VALIDITY_SECONDS = 600
DECISION_PREFIX = "decisions/"
SOURCE_TAG = re.compile(r"^refs/tags/ac-source-[A-Za-z0-9._-]+$")
LOWER_SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
AUDITOR_IDENTITY = re.compile(r"^regression-auditor-agent:[A-Za-z0-9._-]+$")
IMPLEMENTATION_IDENTITY = re.compile(r"^github-actor-id:[1-9][0-9]*$")
REVIEWER_IDENTITY = re.compile(r"^github-app-id:[1-9][0-9]*$")
SIGNATURE_DOMAIN = b"AIMS_BOUNDED_DEPLOY_ATTESTATION_V1\x00"


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("protected decision은 JSON object여야 합니다.")
    return value


def _decision_path(root: Path, relative_path: str) -> Path:
    normalized = relative_path.replace("\\", "/").strip()
    parts = Path(normalized).parts
    if (
        not normalized.startswith(DECISION_PREFIX)
        or not normalized.endswith(".json")
        or Path(normalized).is_absolute()
        or ".." in parts
        or any(character in normalized for character in "*?[]")
    ):
        raise ValueError("decision은 안전한 decisions/*.json 상대 경로여야 합니다.")
    root = root.resolve()
    resolved = (root / normalized).resolve()
    if root not in resolved.parents:
        raise ValueError("decision 경로가 trust root 밖을 가리킵니다.")
    return resolved


def _private_key(encoded_key: str):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - workflow installs a pinned wheel
        raise RuntimeError("cryptography package가 필요합니다.") from exc
    raw = base64.b64decode(encoded_key, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 private key는 raw 32-byte base64여야 합니다.")
    return Ed25519PrivateKey.from_private_bytes(raw)


def signature_message(payload: dict[str, Any]) -> bytes:
    """Return the canonical, domain-separated deploy authorization bytes."""
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SIGNATURE_DOMAIN + canonical


def issue_attestation(
    *,
    trust_root: Path,
    decision_path: str,
    repository: str,
    expected_reviewer_identity: str,
    expected_certified_sha: str,
    expected_artifact_digest: str,
    expected_installer_digest: str,
    expected_latest_manifest_digest: str,
    expected_publisher_script_digest: str,
    expected_source_tag: str,
    expected_tag_object_sha: str,
    expected_publisher_commit_sha: str,
    expected_source_tree_sha: str,
    expected_publisher_dependency_digests: dict[str, str],
    private_key_b64: str,
    now: int | None = None,
) -> dict[str, Any]:
    issued_at = int(time.time()) if now is None else now
    decision_file = _decision_path(trust_root, decision_path)
    decision = _object(decision_file)

    exact_fields = {
        "schema": DECISION_SCHEMA,
        "verdict": "PASS",
        "repository": repository,
        "operation": "deploy",
        "artifactKind": ARTIFACT_KIND,
        "issuer": ISSUER,
        "keyId": KEY_ID,
        "signatureAlgorithm": SIGNATURE_ALGORITHM,
        "decisionReviewerIdentity": expected_reviewer_identity,
        "certifiedSha": expected_certified_sha,
        "artifactDigest": expected_artifact_digest,
        "installerDigest": expected_installer_digest,
        "latestManifestDigest": expected_latest_manifest_digest,
        "publisherScriptDigest": expected_publisher_script_digest,
        "commandContract": COMMAND_CONTRACT,
        "sourceTag": expected_source_tag,
        "tagObjectSha": expected_tag_object_sha,
        "publisherCommitSha": expected_publisher_commit_sha,
        "sourceTreeSha": expected_source_tree_sha,
        "publisherFiles": {
            PUBLISHER_SCRIPT_PATH: expected_publisher_script_digest,
            **expected_publisher_dependency_digests,
        },
    }
    mismatched = [key for key, value in exact_fields.items() if decision.get(key) != value]
    if mismatched:
        raise ValueError(
            "protected deploy decision binding이 일치하지 않습니다: "
            + ", ".join(mismatched)
        )

    if repository != "aim2nasa/aims":
        raise ValueError("허용된 candidate repository는 aim2nasa/aims뿐입니다.")
    if not REVIEWER_IDENTITY.fullmatch(expected_reviewer_identity):
        raise ValueError("decision reviewer identity가 유효하지 않습니다.")
    if not LOWER_SHA40.fullmatch(expected_certified_sha):
        raise ValueError("certified SHA는 lowercase 40-character SHA여야 합니다.")
    if not LOWER_SHA256.fullmatch(expected_artifact_digest):
        raise ValueError("artifact digest는 lowercase SHA-256이어야 합니다.")
    digest_fields = {
        "installerDigest": expected_installer_digest,
        "latestManifestDigest": expected_latest_manifest_digest,
        "publisherScriptDigest": expected_publisher_script_digest,
    }
    invalid_digests = [name for name, value in digest_fields.items() if not LOWER_SHA256.fullmatch(value)]
    if invalid_digests:
        raise ValueError(
            "추가 deploy digest는 lowercase SHA-256이어야 합니다: "
            + ", ".join(invalid_digests)
        )
    if not SOURCE_TAG.fullmatch(expected_source_tag):
        raise ValueError("sourceTag는 refs/tags/ac-source-* annotated tag여야 합니다.")
    if not LOWER_SHA40.fullmatch(expected_tag_object_sha):
        raise ValueError("tagObjectSha는 lowercase 40-character SHA여야 합니다.")
    if not LOWER_SHA40.fullmatch(expected_publisher_commit_sha):
        raise ValueError("publisherCommitSha는 lowercase 40-character SHA여야 합니다.")
    if not LOWER_SHA40.fullmatch(expected_source_tree_sha):
        raise ValueError("sourceTreeSha는 lowercase 40-character Git tree SHA여야 합니다.")
    if set(expected_publisher_dependency_digests) != set(PUBLISHER_DEPENDENCY_PATHS) or any(
        not LOWER_SHA256.fullmatch(value)
        for value in expected_publisher_dependency_digests.values()
    ):
        raise ValueError("publisherDependencyDigests 경로/digest가 유효하지 않습니다.")
    expected_tag_protection = {
        "rulesetId": 19181898,
        "target": "tag",
        "enforcement": "active",
        "include": ["refs/tags/ac-source-*"],
        "rules": ["deletion", "non_fast_forward"],
        "bypassActors": [],
    }
    if decision.get("sourceTagProtection") != expected_tag_protection:
        raise ValueError("protected decision의 sourceTagProtection evidence가 유효하지 않습니다.")

    auditor_identity = decision.get("auditorIdentity")
    auditor_session_id = decision.get("auditorSessionId")
    implementation_identity = decision.get("implementationIdentity")
    evidence = decision.get("evidence")
    if not isinstance(auditor_identity, str) or not AUDITOR_IDENTITY.fullmatch(auditor_identity):
        raise ValueError("독립 Auditor identity가 유효하지 않습니다.")
    if not isinstance(auditor_session_id, str) or not auditor_session_id.strip():
        raise ValueError("독립 Auditor session이 없습니다.")
    if (
        not isinstance(implementation_identity, str)
        or not IMPLEMENTATION_IDENTITY.fullmatch(implementation_identity)
    ):
        raise ValueError("implementation identity가 유효하지 않습니다.")
    if not isinstance(evidence, list) or not evidence or not all(
        isinstance(item, str) and item.strip() for item in evidence
    ):
        raise ValueError("protected decision evidence가 없습니다.")

    decision_issued_at = decision.get("issuedAt")
    decision_expires_at = decision.get("expiresAt")
    if (
        type(decision_issued_at) is not int
        or type(decision_expires_at) is not int
        or decision_issued_at > issued_at
        or decision_expires_at <= issued_at
        or decision_expires_at - decision_issued_at > MAX_ATTESTATION_VALIDITY_SECONDS
    ):
        raise ValueError("protected deploy decision 유효기간이 올바르지 않습니다.")

    private_key = _private_key(private_key_b64)
    decision_digest = hashlib.sha256(decision_file.read_bytes()).hexdigest()
    expires_at = min(
        issued_at + MAX_ATTESTATION_VALIDITY_SECONDS,
        decision_expires_at,
    )
    payload = {
        "schema": ATTESTATION_SCHEMA,
        "repository": repository,
        "operation": "deploy",
        "artifactKind": ARTIFACT_KIND,
        "issuer": ISSUER,
        "keyId": KEY_ID,
        "signatureAlgorithm": SIGNATURE_ALGORITHM,
        "certifiedSha": expected_certified_sha,
        "artifactDigest": expected_artifact_digest,
        "installerDigest": expected_installer_digest,
        "latestManifestDigest": expected_latest_manifest_digest,
        "publisherScriptDigest": expected_publisher_script_digest,
        "commandContract": COMMAND_CONTRACT,
        "sourceTag": expected_source_tag,
        "tagObjectSha": expected_tag_object_sha,
        "publisherCommitSha": expected_publisher_commit_sha,
        "sourceTreeSha": expected_source_tree_sha,
        "publisherFiles": {
            PUBLISHER_SCRIPT_PATH: expected_publisher_script_digest,
            **expected_publisher_dependency_digests,
        },
        "decisionDigest": decision_digest,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }
    signature = base64.b64encode(private_key.sign(signature_message(payload))).decode("ascii")
    return {**payload, "signature": signature}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trust-root", type=Path, required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--decision-reviewer-identity", required=True)
    parser.add_argument("--expected-certified-sha", required=True)
    parser.add_argument("--expected-artifact-digest", required=True)
    parser.add_argument("--expected-installer-digest", required=True)
    parser.add_argument("--expected-latest-manifest-digest", required=True)
    parser.add_argument("--expected-publisher-script-digest", required=True)
    parser.add_argument("--expected-source-tag", required=True)
    parser.add_argument("--expected-tag-object-sha", required=True)
    parser.add_argument("--expected-publisher-commit-sha", required=True)
    parser.add_argument("--expected-source-tree-sha", required=True)
    parser.add_argument("--expected-ac-build-provenance-digest", required=True)
    parser.add_argument("--expected-execution-provenance-digest", required=True)
    parser.add_argument("--expected-provenance-trust-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    private_key_b64 = os.environ.get(PRIVATE_KEY_ENV, "").strip()
    if not private_key_b64:
        print(f"[BOUNDED DEPLOY ISSUER] BLOCK: {PRIVATE_KEY_ENV}가 없습니다.", file=sys.stderr)
        return 2
    try:
        attestation = issue_attestation(
            trust_root=args.trust_root,
            decision_path=args.decision,
            repository=args.repository,
            expected_reviewer_identity=args.decision_reviewer_identity,
            expected_certified_sha=args.expected_certified_sha,
            expected_artifact_digest=args.expected_artifact_digest,
            expected_installer_digest=args.expected_installer_digest,
            expected_latest_manifest_digest=args.expected_latest_manifest_digest,
            expected_publisher_script_digest=args.expected_publisher_script_digest,
            expected_source_tag=args.expected_source_tag,
            expected_tag_object_sha=args.expected_tag_object_sha,
            expected_publisher_commit_sha=args.expected_publisher_commit_sha,
            expected_source_tree_sha=args.expected_source_tree_sha,
            expected_publisher_dependency_digests={
                PUBLISHER_DEPENDENCY_PATHS[0]: args.expected_ac_build_provenance_digest,
                PUBLISHER_DEPENDENCY_PATHS[1]: args.expected_execution_provenance_digest,
                PUBLISHER_DEPENDENCY_PATHS[2]: args.expected_provenance_trust_digest,
            },
            private_key_b64=private_key_b64,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(attestation, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"[BOUNDED DEPLOY ISSUER] BLOCK: {exc}", file=sys.stderr)
        return 2
    print(
        "[BOUNDED DEPLOY ISSUER] PASS: protected decision에 결속된 exact attestation을 발급했습니다."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
