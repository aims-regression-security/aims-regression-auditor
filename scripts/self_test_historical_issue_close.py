#!/usr/bin/env python3
"""Self-test historical issue-close behavior binding in the protected issuer."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import regression_auditor_check as gate  # noqa: E402
import regression_auditor_issue as issue  # noqa: E402


def run_git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def init_candidate(root: Path) -> tuple[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    run_git(root, "init")
    run_git(root, "config", "core.autocrlf", "false")
    run_git(root, "config", "user.email", "issuer-test@example.com")
    run_git(root, "config", "user.name", "Issuer Test")
    sample = root / "scripts" / "sample.py"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text("print('historic')\n", encoding="utf-8")
    run_git(root, "add", "scripts/sample.py")
    run_git(root, "commit", "-m", "historic behavior")
    historic = run_git(root, "rev-parse", "HEAD")
    digest = gate.git_files_digest(root, ["scripts/sample.py"], ref=historic)
    return historic, digest


def subject_and_classification(historic: str, digest: str) -> tuple[dict, dict]:
    classification = {
        "schema": "aims.regression_work.v1",
        "workKind": "bugfix",
        "stagedBehaviorFiles": ["scripts/sample.py"],
        "stagedBehaviorDigest": digest,
        "targetBinding": {
            "issues": ["#265"],
            "releaseTags": [],
            "requirements": ["self-test"],
        },
        "auditorReview": {
            "agent": "Regression Auditor",
            "agentId": "regression-auditor-agent:self-test",
            "implementationRole": "independent",
            "status": "PASS",
            "evidence": ["self-test"],
        },
    }
    subject = {
        "schema": "aims.regression_auditor.v1",
        "mode": "issue-close",
        "workClassification": "docs/regression-work/sample.json",
        "auditorReceipt": "docs/regression-audits/auditor-receipts/sample.json",
        "runnerBinding": {"postRef": historic},
        "historicalBehavior": {
            "postCommitSha": historic,
            "files": ["scripts/sample.py"],
            "digest": digest,
        },
        "auditor": {
            "agent": "Regression Auditor",
            "agentId": "regression-auditor-agent:self-test",
            "implementationRole": "independent",
            "status": "PASS",
        },
    }
    return subject, classification


def test_historical_close_helper_accepts_only_immutable_matching_blobs(root: Path) -> None:
    historic, digest = init_candidate(root)
    subject, classification = subject_and_classification(historic, digest)
    write_json(root / "docs/regression-work/sample.json", classification)

    assert issue.historical_close_behavior(root, subject, classification, historic) == (
        ["scripts/sample.py"],
        digest,
    )
    _work_kind, errors = gate.validate_work_classification(
        root,
        "docs/regression-work/sample.json",
        ["scripts/sample.py"],
        digest,
        staged=False,
        trust_context={},
    )
    assert errors == []

    tampered = json.loads(json.dumps(subject))
    tampered["historicalBehavior"]["digest"] = "0" * 64
    try:
        issue.historical_close_behavior(root, tampered, classification, historic)
    except ValueError as exc:
        assert "digest" in str(exc)
    else:
        raise AssertionError("tampered historical digest must be rejected")


def test_issue_receipt_rejects_historical_candidate_with_new_behavior(root: Path) -> None:
    historic, digest = init_candidate(root)
    subject, classification = subject_and_classification(historic, digest)
    write_json(root / "docs/regression-audits/sample.json", subject)
    write_json(root / "docs/regression-work/sample.json", classification)
    (root / "scripts" / "new_behavior.py").write_text("print('new')\n", encoding="utf-8")
    run_git(root, "add", "docs", "scripts/new_behavior.py")
    run_git(root, "commit", "-m", "close candidate with new behavior")

    try:
        issue.issue_receipt(
            candidate_root=root,
            trust_root=root,
            output_root=root,
            subject_path="docs/regression-audits/sample.json",
            output_path="docs/regression-audits/auditor-receipts/sample.json",
            decision_path="decisions/not-needed.json",
            repository="aim2nasa/aims",
            issuer="github-environment:regression-auditor",
            key_id="primary-2026-07",
            implementation_identity="github-actor-id:1",
            decision_reviewer_identity="github-app-id:4291228",
            private_key_b64="unused",
            ttl_seconds=600,
            now=1_784_184_000,
        )
    except ValueError as exc:
        assert "새 behavior 변경" in str(exc)
    else:
        raise AssertionError("historical close candidate with new behavior must be rejected")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="issuer-historical-close-") as temp_dir:
        test_historical_close_helper_accepts_only_immutable_matching_blobs(Path(temp_dir) / "helper")
    with tempfile.TemporaryDirectory(prefix="issuer-historical-close-") as temp_dir:
        test_issue_receipt_rejects_historical_candidate_with_new_behavior(Path(temp_dir) / "issuer")
    print("[SELF-TEST] historical issue-close binding PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
