#!/usr/bin/env python3
"""Issue a protected Ed25519 Regression Auditor receipt."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

try:
    import regression_auditor_check as gate
except ModuleNotFoundError:
    from scripts import regression_auditor_check as gate


MAX_TTL_SECONDS = 900
PRIVATE_KEY_ENV = "AIMS_REGRESSION_AUDITOR_ED25519_PRIVATE_KEY_B64"
AUDITOR_DECISION_PREFIX = "decisions/"


def repo_path(root: Path, relative_path: str) -> Path:
    normalized = gate.normalize(relative_path)
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in Path(normalized).parts
        or any(character in normalized for character in "*?[]")
    ):
        raise ValueError(f"repository-relative path가 필요합니다: {relative_path}")
    resolved = (root / normalized).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"repository root 밖의 경로입니다: {relative_path}")
    return resolved


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object가 필요합니다: {path}")
    return value


def load_private_key(encoded_key: str):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        key_bytes = base64.b64decode(encoded_key, validate=True)
        if len(key_bytes) != 32:
            raise ValueError("Ed25519 private key는 raw 32-byte base64여야 합니다.")
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    except ImportError as exc:
        raise RuntimeError("cryptography package가 필요합니다.") from exc


def issue_receipt(
    *,
    candidate_root: Path,
    trust_root: Path,
    output_root: Path,
    subject_path: str,
    output_path: str,
    decision_path: str,
    repository: str,
    issuer: str,
    key_id: str,
    implementation_identity: str,
    decision_reviewer_identity: str,
    private_key_b64: str,
    ttl_seconds: int,
    now: int | None = None,
) -> dict[str, Any]:
    candidate_root = candidate_root.resolve()
    trust_root = trust_root.resolve()
    output_root = output_root.resolve()
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(f"ttl-seconds는 1..{MAX_TTL_SECONDS} 범위여야 합니다.")
    required_values = {
        "issuer": issuer,
        "repository": repository,
        "key-id": key_id,
        "implementation-identity": implementation_identity,
        "decision-reviewer-identity": decision_reviewer_identity,
        "decision": decision_path,
    }
    missing = [name for name, value in required_values.items() if not value.strip()]
    if missing:
        raise ValueError("필수 값이 없습니다: " + ", ".join(missing))
    normalized_subject = gate.normalize(subject_path)
    normalized_output = gate.normalize(output_path)
    normalized_decision = gate.normalize(decision_path)
    if (
        not normalized_decision.startswith(AUDITOR_DECISION_PREFIX)
        or not normalized_decision.endswith(".json")
    ):
        raise ValueError(f"decision은 {AUDITOR_DECISION_PREFIX}*.json 이어야 합니다.")
    subject = read_object(repo_path(candidate_root, normalized_subject))
    candidate_output = repo_path(candidate_root, normalized_output)
    if candidate_output.exists():
        raise ValueError("candidate commit에는 signed output receipt가 없어야 합니다.")
    if subject.get("schema") != "aims.regression_auditor.v1":
        raise ValueError("subject receipt schema가 유효하지 않습니다.")
    if gate.text(subject.get("auditorReceipt")) != normalized_output:
        raise ValueError("subject auditorReceipt가 output path와 일치하지 않습니다.")

    subject_auditor = gate.object_at(subject, "auditor")
    if gate.text(subject_auditor.get("agent")) != "Regression Auditor":
        raise ValueError("subject Auditor agent가 유효하지 않습니다.")
    if gate.text(subject_auditor.get("implementationRole")).lower() != "independent":
        raise ValueError("subject Auditor role은 independent여야 합니다.")
    if gate.text(subject_auditor.get("status")).upper() != "PASS":
        raise ValueError("subject Auditor status가 PASS가 아닙니다.")

    subject_hash = gate.sha256_json(
        {key: value for key, value in subject.items() if key != "auditorReceipt"}
    )
    classification_path = gate.text(subject.get("workClassification"))
    classification: dict[str, Any] | None = None
    candidate_context = gate.candidate_audit_context(
        candidate_root,
        [],
        staged=False,
        repository=repository,
        excluded_receipt=normalized_output,
    )
    candidate_files = set(candidate_context["candidateFiles"])
    recognized_behavior_files = {
        path
        for path in candidate_files
        if gate.is_behavior_file(path)
    }
    behavior_files: list[str] = []
    behavior_digest = ""
    if classification_path:
        classification = read_object(repo_path(candidate_root, classification_path))
        if classification.get("schema") != "aims.regression_work.v1":
            raise ValueError("work classification schema가 유효하지 않습니다.")
        classified_behavior_files = [
            gate.normalize(path)
            for path in gate.string_list(classification.get("stagedBehaviorFiles"))
        ]
        if len(classified_behavior_files) != len(set(classified_behavior_files)):
            raise ValueError("work classification behavior manifest에 중복 경로가 있습니다.")
        behavior_files = sorted(classified_behavior_files)
        explicit_behavior_files = set(behavior_files)
        behavior_digest = gate.text(classification.get("stagedBehaviorDigest"))
        recomputed_behavior_digest = gate.git_files_digest(
            candidate_root,
            behavior_files,
            ref="HEAD",
        )
        if not recognized_behavior_files.issubset(explicit_behavior_files):
            raise ValueError(
                "자동 인식된 candidate behavior 파일이 work classification에서 누락됐습니다."
            )
        if not explicit_behavior_files.issubset(candidate_files):
            raise ValueError(
                "work classification behavior manifest에 candidate 변경 외 파일이 있습니다."
            )
        if recomputed_behavior_digest != behavior_digest:
            raise ValueError(
                "candidate staged digest가 work classification과 일치하지 않습니다."
            )
    elif recognized_behavior_files:
        raise ValueError(
            "candidate behavior manifest가 있지만 work classification이 없습니다."
        )

    issued_at = int(time.time()) if now is None else now
    decision = read_object(repo_path(trust_root, normalized_decision))
    if decision.get("schema") != "aims.regression_auditor_decision.v1":
        raise ValueError("protected Auditor decision schema가 유효하지 않습니다.")
    if gate.text(decision.get("verdict")).upper() != "PASS":
        raise ValueError("protected Auditor decision verdict가 PASS가 아닙니다.")
    auditor_identity = gate.text(decision.get("auditorIdentity"))
    auditor_session_id = gate.text(decision.get("auditorSessionId"))
    protected_reviewer_identity = gate.text(
        decision.get("decisionReviewerIdentity")
    )
    reviewed_files = gate.string_list(decision.get("reviewedFiles"))
    evidence = gate.string_list(decision.get("evidence"))
    if not auditor_identity or not auditor_session_id or not reviewed_files or not evidence:
        raise ValueError("protected Auditor decision의 identity/session/evidence가 불완전합니다.")
    if implementation_identity == auditor_identity:
        raise ValueError("implementation identity와 Auditor identity는 달라야 합니다.")
    if (
        protected_reviewer_identity != decision_reviewer_identity
        or decision_reviewer_identity == implementation_identity
    ):
        raise ValueError(
            "protected decision reviewer identity가 실제 승인 reviewer와 일치하지 않습니다."
        )
    if gate.text(subject_auditor.get("agentId")) != auditor_identity:
        raise ValueError("protected Auditor identity가 subject agentId와 일치하지 않습니다.")
    decision_issued_at = decision.get("issuedAt")
    decision_expires_at = decision.get("expiresAt")
    if (
        type(decision_issued_at) is not int
        or type(decision_expires_at) is not int
        or decision_issued_at > issued_at
        or decision_expires_at <= issued_at
        or decision_expires_at - decision_issued_at > MAX_TTL_SECONDS
    ):
        raise ValueError("protected Auditor decision 유효기간이 올바르지 않습니다.")
    candidate_commit_sha = gate.run_git_at(candidate_root, ["rev-parse", "HEAD"])
    expected_decision_binding = {
        "repository": repository,
        "candidateCommitSha": candidate_commit_sha,
        "candidateTreeSha": candidate_context["candidateTreeSha"],
        "subjectReceipt": normalized_subject,
        "subjectReceiptSha256": subject_hash,
    }
    mismatched_decision_fields = [
        key
        for key, expected in expected_decision_binding.items()
        if gate.text(decision.get(key)) != expected
    ]
    if mismatched_decision_fields:
        raise ValueError(
            "protected Auditor decision이 candidate와 일치하지 않습니다: "
            + ", ".join(mismatched_decision_fields)
        )
    if gate.has_forbidden_completion_text(decision):
        raise ValueError("protected Auditor decision에 금지된 미완료 문구가 있습니다.")

    audit_bundle = gate.build_audit_bundle(
        subject,
        subject_hash,
        behavior_files,
        behavior_digest,
        work_classification_path=classification_path,
        work_classification=classification,
        repository=candidate_context["repository"],
        base_commit_sha=candidate_context["baseCommitSha"],
        candidate_tree_sha=candidate_context["candidateTreeSha"],
        candidate_files=candidate_context["candidateFiles"],
        candidate_digest=candidate_context["candidateDigest"],
    )
    signed_receipt = {
        "schema": "aims.regression_auditor_receipt.v1",
        "agent": "Regression Auditor",
        "agentId": auditor_identity,
        "auditorIdentity": auditor_identity,
        "implementationIdentity": implementation_identity,
        "auditorSessionId": auditor_session_id,
        "decisionReviewerIdentity": decision_reviewer_identity,
        "implementationRole": "independent",
        "verdict": "PASS",
        "issuer": issuer,
        "keyId": key_id,
        "signatureAlgorithm": "ed25519",
        "nonce": secrets.token_urlsafe(32),
        "issuedAt": issued_at,
        "expiresAt": min(issued_at + ttl_seconds, decision_expires_at),
        "auditorDecision": normalized_decision,
        "auditorDecisionSha256": gate.sha256_json(decision),
        "subjectReceipt": normalized_subject,
        "subjectReceiptSha256": subject_hash,
        "stagedBehaviorFiles": behavior_files,
        "stagedBehaviorDigest": behavior_digest,
        "reviewedFiles": reviewed_files,
        "evidence": evidence,
        "auditBundle": audit_bundle,
    }
    private_key = load_private_key(private_key_b64)
    payload = gate.auditor_signature_payload(signed_receipt)
    signed_receipt["signature"] = base64.b64encode(
        private_key.sign(payload)
    ).decode("ascii")

    trust_context = gate.load_trust_context(
        trust_root,
        staged=False,
        implementation_identity=implementation_identity,
        now=issued_at,
    )
    verifier = trust_context.get("verifier")
    if gate.text(trust_context.get("policyError")) or not callable(verifier):
        raise ValueError("trusted default-branch public-key policy를 불러오지 못했습니다.")
    if not verifier(payload, signed_receipt["signature"], issuer):
        raise ValueError("private key가 trusted public-key policy와 일치하지 않습니다.")

    output = repo_path(output_root, normalized_output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(signed_receipt, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return signed_receipt


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument("--trust-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--implementation-identity", required=True)
    parser.add_argument("--decision-reviewer-identity", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=600)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    private_key = os.environ.get(PRIVATE_KEY_ENV, "")
    if not private_key:
        print(f"[AUDITOR ISSUER] BLOCK: {PRIVATE_KEY_ENV}가 없습니다.", file=sys.stderr)
        return 2
    try:
        receipt = issue_receipt(
            candidate_root=Path(args.candidate_root),
            trust_root=Path(args.trust_root),
            output_root=Path(args.output_root),
            subject_path=args.subject,
            output_path=args.output,
            decision_path=args.decision,
            repository=args.repository,
            issuer=args.issuer,
            key_id=args.key_id,
            implementation_identity=args.implementation_identity,
            decision_reviewer_identity=args.decision_reviewer_identity,
            private_key_b64=private_key,
            ttl_seconds=args.ttl_seconds,
        )
    except Exception as exc:
        print(f"[AUDITOR ISSUER] BLOCK: {exc}", file=sys.stderr)
        return 2
    print(
        "[AUDITOR ISSUER] PASS: "
        f"issuer={receipt['issuer']} keyId={receipt['keyId']} "
        f"subject={receipt['subjectReceiptSha256']}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
