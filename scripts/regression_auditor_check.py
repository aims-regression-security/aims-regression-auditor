#!/usr/bin/env python3
"""Regression and live verification gate.

Bug/regression work must carry machine-readable proof that a fail-first
regression harness failed before the fix, the same harness passed after the
fix, live-only acceptance has been separated, and an independent Regression
Auditor approved the evidence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

AUDIT_PREFIX = "docs/regression-audits/"
AUDITOR_RECEIPT_PREFIX = "docs/regression-audits/auditor-receipts/"
AUDITOR_DECISION_PREFIX = "decisions/"
EVIDENCE_PREFIX = "docs/regression-evidence/"
WORK_CLASSIFICATION_PREFIX = "docs/regression-work/"
REPORT_PREFIX = "docs/ace-reports/"
TRUST_POLICY_PATH = ".github/regression-auditor-trust.json"
TRUST_ROOT_ENV = "AIMS_REGRESSION_AUDITOR_TRUST_ROOT"
TRUSTED_CHECK_NAME = "Regression Auditor / trusted-verifier"
ACTIVE_TRUST_STATE = "ACTIVE"
VALID_LIVE_STATUS = {"none", "OPEN_UNTIL_LIVE_PASS", "LIVE_VERIFIED"}
VALID_WORK_KINDS = {
    "bugfix",
    "regression",
    "issue-reopen",
    "verification-gate",
    "feature",
    "refactor",
    "chore",
    "docs",
}
FAIL_FIRST_WORK_KINDS = {
    "bugfix",
    "regression",
    "issue-reopen",
    "verification-gate",
}
GIT_TIMEOUT_SECONDS = 30
FORBIDDEN_TOKENS = ("pending", "예정", "todo", "미실행", "나중에 확인")
BEHAVIOR_EXTENSIONS = {
    ".bat",
    ".c",
    ".cmd",
    ".cjs",
    ".conf",
    ".cpp",
    ".css",
    ".cs",
    ".cts",
    ".go",
    ".h",
    ".hpp",
    ".htm",
    ".html",
    ".ini",
    ".iss",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".less",
    ".mjs",
    ".mts",
    ".php",
    ".py",
    ".pyw",
    ".ps1",
    ".rb",
    ".rs",
    ".sass",
    ".scss",
    ".sh",
    ".sql",
    ".spec",
    ".service",
    ".svelte",
    ".timer",
    ".toml",
    ".ts",
    ".tsx",
    ".vbs",
    ".vue",
    ".webmanifest",
    ".xml",
    ".yml",
    ".yaml",
    ".json",
}
BEHAVIOR_FILENAMES = {
    ".claude/settings.json",
    ".husky/pre-commit",
    "AGENTS.md",
    "CLAUDE.md",
    "Dockerfile",
    "Makefile",
}
IGNORED_BEHAVIOR_PREFIXES = (
    "docs/",
    "node_modules/",
)


def normalize(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def run_git(args: list[str]) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return [normalize(line.strip()) for line in result.stdout.splitlines() if line.strip()]


def run_git_at(
    root: Path,
    args: list[str],
    *,
    extra_env: dict[str, str] | None = None,
) -> str:
    environment = os.environ.copy()
    if extra_env:
        environment.update(extra_env)
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def repository_identity(root: Path) -> str:
    configured = text(
        os.environ.get("AIMS_REPOSITORY_ID")
        or os.environ.get("GITHUB_REPOSITORY")
    )
    if configured:
        return configured
    remote = run_git_at(root, ["config", "--get", "remote.origin.url"])
    normalized = remote.removesuffix(".git").rstrip("/")
    if normalized.startswith("git@github.com:"):
        return normalized.split(":", 1)[1]
    marker = "github.com/"
    if marker in normalized:
        return normalized.split(marker, 1)[1]
    raise RuntimeError("GitHub repository identity를 확인할 수 없습니다.")


def git_files_digest(
    root: Path,
    files: list[str],
    *,
    ref: str = "",
) -> str:
    manifest: list[dict[str, str]] = []
    for path in sorted(normalize(path) for path in files):
        if ref:
            result = run_git_at(root, ["ls-tree", "-z", ref, "--", path])
            lines = [line for line in result.split("\0") if line]
            if not lines:
                manifest.append({"path": path, "state": "deleted"})
                continue
            for line in lines:
                metadata, separator, indexed_path = line.partition("\t")
                parts = metadata.split()
                if not separator or len(parts) != 3 or normalize(indexed_path) != path:
                    raise RuntimeError(f"malformed git tree entry: {line}")
                mode, object_type, object_id = parts
                if object_type != "blob":
                    raise RuntimeError(f"unsupported git tree object: {line}")
                manifest.append(
                    {
                        "path": path,
                        "state": "present",
                        "mode": mode,
                        "objectId": object_id,
                        "stage": "0",
                    }
                )
            continue

        result = run_git_at(root, ["ls-files", "-z", "--stage", "--", path])
        lines = [line for line in result.split("\0") if line]
        if not lines:
            manifest.append({"path": path, "state": "deleted"})
            continue
        for line in lines:
            metadata, separator, indexed_path = line.partition("\t")
            parts = metadata.split()
            if not separator or len(parts) != 3 or normalize(indexed_path) != path:
                raise RuntimeError(f"malformed git index entry: {line}")
            mode, object_id, stage = parts
            manifest.append(
                {
                    "path": path,
                    "state": "present",
                    "mode": mode,
                    "objectId": object_id,
                    "stage": stage,
                }
            )
    canonical = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def git_index_text(path: str, root: Path | None = None) -> str | None:
    result = subprocess.run(
        ["git", "show", f":{normalize(path)}"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def staged_files(root: Path | None = None) -> list[str]:
    if root is None:
        return run_git(["diff", "--cached", "--name-only"])
    output = run_git_at(root, ["diff", "--cached", "--name-only"])
    return [normalize(line) for line in output.splitlines() if line]


def git_index_bytes(path: str, root: Path | None = None) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f":{normalize(path)}"],
        cwd=root,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def staged_behavior_digest(
    files: list[str],
    root: Path | None = None,
) -> tuple[list[str], str]:
    behavior = sorted(path for path in files if is_behavior_file(path))
    return behavior, staged_files_digest(behavior, root=root)


def staged_files_digest(files: list[str], root: Path | None = None) -> str:
    return git_files_digest((root or Path.cwd()).resolve(), files)


def candidate_audit_context(
    root: Path,
    files: list[str],
    *,
    staged: bool,
    repository: str = "",
    excluded_receipt: str = "",
) -> dict[str, Any]:
    excluded_receipt = normalize(excluded_receipt)
    if excluded_receipt and not excluded_receipt.startswith(AUDITOR_RECEIPT_PREFIX):
        raise RuntimeError("excluded receipt path가 Auditor receipt 경로가 아닙니다.")
    candidate_files = sorted(
        normalize(path)
        for path in files
        if normalize(path) != excluded_receipt
    )
    if staged:
        base_commit_sha = run_git_at(root, ["rev-parse", "HEAD"])
        git_index_path = Path(
            run_git_at(root, ["rev-parse", "--path-format=absolute", "--git-path", "index"])
        )
        with tempfile.TemporaryDirectory(prefix="aims-auditor-index-") as temporary:
            temporary_index = Path(temporary) / "index"
            shutil.copy2(git_index_path, temporary_index)
            environment = {"GIT_INDEX_FILE": str(temporary_index)}
            if excluded_receipt:
                run_git_at(
                    root,
                    ["reset", "-q", "HEAD", "--", excluded_receipt],
                    extra_env=environment,
                )
            candidate_tree_sha = run_git_at(
                root,
                ["write-tree"],
                extra_env=environment,
            )
        candidate_digest = git_files_digest(root, candidate_files)
    else:
        base_commit_sha = run_git_at(root, ["rev-parse", "HEAD^"])
        changed = run_git_at(
            root,
            ["diff", "--name-only", "-z", base_commit_sha, "HEAD"],
        )
        candidate_files = sorted(
            normalize(path)
            for path in changed.split("\0")
            if path and normalize(path) != excluded_receipt
        )
        if excluded_receipt:
            with tempfile.TemporaryDirectory(prefix="aims-auditor-tree-") as temporary:
                temporary_index = Path(temporary) / "index"
                environment = {"GIT_INDEX_FILE": str(temporary_index)}
                run_git_at(root, ["read-tree", "HEAD"], extra_env=environment)
                run_git_at(
                    root,
                    ["reset", "-q", base_commit_sha, "--", excluded_receipt],
                    extra_env=environment,
                )
                candidate_tree_sha = run_git_at(
                    root,
                    ["write-tree"],
                    extra_env=environment,
                )
        else:
            candidate_tree_sha = run_git_at(root, ["rev-parse", "HEAD^{tree}"])
        candidate_digest = git_files_digest(root, candidate_files, ref="HEAD")
    return {
        "repository": repository or repository_identity(root),
        "baseCommitSha": base_commit_sha,
        "candidateTreeSha": candidate_tree_sha,
        "candidateFiles": candidate_files,
        "candidateDigest": candidate_digest,
    }


def current_branch() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    return result.stdout.strip()


def is_behavior_file(path: str) -> bool:
    normalized = normalize(path)
    if normalized.startswith(IGNORED_BEHAVIOR_PREFIXES):
        return False
    name = Path(normalized).name
    if normalized.startswith(".husky/"):
        return True
    if normalized in BEHAVIOR_FILENAMES or name in BEHAVIOR_FILENAMES:
        return True
    if name == ".dockerignore" or name == ".env" or name.startswith(".env."):
        return True
    return Path(normalized).suffix.lower() in BEHAVIOR_EXTENSIONS


def is_audit_receipt(path: str) -> bool:
    normalized = normalize(path)
    return (
        normalized.startswith(AUDIT_PREFIX)
        and not normalized.startswith(AUDITOR_RECEIPT_PREFIX)
        and normalized.endswith(".json")
    )


def git_ref_bytes(root: Path, path: str, ref: str) -> bytes | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{normalize(path)}"],
        cwd=root,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def read_text(
    root: Path,
    path: str,
    *,
    staged: bool = False,
    ref: str = "",
) -> tuple[str | None, str | None]:
    normalized = normalize(path)
    if staged and ref:
        return None, f"{normalized}: staged와 ref를 동시에 지정할 수 없습니다."
    if staged:
        staged_text = git_index_text(normalized, root=root)
        if staged_text is None:
            return None, f"{normalized}: staged index에서 읽을 수 없습니다."
        return staged_text, None
    if ref:
        committed = git_ref_bytes(root, normalized, ref)
        if committed is None:
            return None, f"{normalized}: {ref}에서 읽을 수 없습니다."
        try:
            return committed.decode("utf-8"), None
        except UnicodeDecodeError as exc:
            return None, f"{normalized}: UTF-8 읽기 실패: {exc}"
    try:
        return (root / normalized).read_text(encoding="utf-8"), None
    except Exception as exc:
        return None, f"{normalized}: 파일 읽기 실패: {exc}"


def read_json(
    root: Path,
    path: str,
    *,
    staged: bool = False,
    ref: str = "",
) -> tuple[dict[str, Any] | None, str | None]:
    content, read_error = read_text(root, path, staged=staged, ref=ref)
    if read_error:
        return None, read_error
    try:
        value = json.loads(content or "")
    except Exception as exc:
        return None, f"{path}: JSON 읽기 실패: {exc}"
    if not isinstance(value, dict):
        return None, f"{path}: 최상위 값은 object여야 합니다."
    return value, None


def read_bytes(
    root: Path,
    path: str,
    *,
    staged: bool = False,
    ref: str = "",
) -> tuple[bytes | None, str | None]:
    normalized = normalize(path)
    if staged and ref:
        return None, f"{normalized}: staged와 ref를 동시에 지정할 수 없습니다."
    if staged:
        content = git_index_bytes(normalized, root=root)
        if content is None:
            return None, f"{normalized}: staged index에서 읽을 수 없습니다."
        return content, None
    if ref:
        content = git_ref_bytes(root, normalized, ref)
        if content is None:
            return None, f"{normalized}: {ref}에서 읽을 수 없습니다."
        return content, None
    try:
        return (root / normalized).read_bytes(), None
    except Exception as exc:
        return None, f"{normalized}: 파일 읽기 실패: {exc}"


def text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def github_numeric_identity(value: str) -> str:
    for prefix in ("github-actor-id:", "github-user-id:"):
        if value.startswith(prefix):
            identity = value.removeprefix(prefix)
            return identity if identity.isdigit() else ""
    return ""


def string_list(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def object_at(receipt: dict[str, Any], key: str) -> dict[str, Any]:
    value = receipt.get(key)
    return value if isinstance(value, dict) else {}


def sha256_json(value: dict[str, Any]) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sha256_json_value(value: Any) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_audit_bundle(
    receipt: dict[str, Any],
    subject_hash: str,
    behavior_files: list[str],
    behavior_digest: str,
    *,
    work_classification_path: str = "",
    work_classification: dict[str, Any] | None = None,
    repository: str = "",
    base_commit_sha: str = "",
    candidate_tree_sha: str = "",
    candidate_files: list[str] | None = None,
    candidate_digest: str = "",
) -> dict[str, Any]:
    return {
        "schema": "aims.regression_audit_bundle.v1",
        "repository": repository,
        "baseCommitSha": base_commit_sha,
        "candidateTreeSha": candidate_tree_sha,
        "candidateFiles": sorted(normalize(path) for path in (candidate_files or [])),
        "candidateDigest": candidate_digest,
        "subjectReceiptSha256": subject_hash,
        "runnerEvidenceSha256": text(
            object_at(receipt, "runnerEvidence").get("sha256")
        ),
        "stagedBehaviorFiles": sorted(normalize(path) for path in behavior_files),
        "stagedBehaviorDigest": behavior_digest,
        "userEntryMatrixSha256": sha256_json_value(
            object_at(receipt, "userEntryMatrix")
        ),
        "acceptanceCriteriaSha256": sha256_json_value(
            receipt.get("acceptanceCriteria", [])
        ),
        "workClassification": normalize(work_classification_path),
        "workClassificationSha256": (
            sha256_json(work_classification)
            if isinstance(work_classification, dict)
            else ""
        ),
    }


def register_nonce(
    registry: dict[str, str],
    nonce: str,
    binding: str,
) -> str:
    existing = registry.get(nonce)
    if existing is None:
        registry[nonce] = binding
        return "ACCEPT"
    return "ACCEPT" if existing == binding else "REPLAY"


def auditor_signature_payload(auditor: dict[str, Any]) -> bytes:
    signed_fields = {
        key: value for key, value in auditor.items() if key != "signature"
    }
    return json.dumps(
        signed_fields,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_trust_context(
    root: Path,
    *,
    staged: bool,
    implementation_identity: str = "",
    now: int | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "trustedIssuers": set(),
        "implementationIdentity": implementation_identity,
        "consumedNonces": {},
        "now": int(time.time()) if now is None else now,
        "requiresKeyId": True,
        "requiresSessionId": True,
        "requiresAuditBundle": True,
        "requiresDecision": True,
    }
    policy, error = read_json(root, TRUST_POLICY_PATH, staged=staged)
    if error:
        context["policyError"] = error
        return context
    assert policy is not None
    if policy.get("schema") != "aims.regression_auditor_trust.v1":
        context["policyError"] = (
            f"{TRUST_POLICY_PATH}: schema는 aims.regression_auditor_trust.v1 이어야 합니다."
        )
        return context
    if policy.get("provisioned") is not True:
        context["policyError"] = (
            f"{TRUST_POLICY_PATH}: protected issuer가 provisioned 상태가 아닙니다."
        )
        return context

    activation = policy.get("activation")
    if not isinstance(activation, dict):
        context["policyError"] = (
            f"{TRUST_POLICY_PATH}: activation metadata가 없습니다."
        )
        return context
    issuer_repository = text(activation.get("issuerRepository"))
    candidate_repository = text(activation.get("candidateRepository"))
    reviewer_identity = text(activation.get("activationReviewerIdentity"))
    integration_id = activation.get("requiredCheckIntegrationId")
    expected_reviewer_identity = (
        f"github-app-id:{integration_id}"
        if type(integration_id) is int and integration_id > 0
        else ""
    )
    raw_activation_evidence = activation.get("evidence")
    activation_evidence = string_list(raw_activation_evidence)
    repositories = (issuer_repository, candidate_repository)
    if (
        text(activation.get("state")) != ACTIVE_TRUST_STATE
        or text(activation.get("requiredCheckName")) != TRUSTED_CHECK_NAME
        or type(integration_id) is not int
        or integration_id <= 0
        or any(
            repository.count("/") != 1
            or any(not part for part in repository.split("/"))
            for repository in repositories
        )
        or reviewer_identity != expected_reviewer_identity
        or not isinstance(raw_activation_evidence, list)
        or not activation_evidence
        or len(activation_evidence) != len(raw_activation_evidence)
        or any(
            token in json.dumps(activation, ensure_ascii=False).lower()
            for token in FORBIDDEN_TOKENS
        )
    ):
        context["policyError"] = (
            f"{TRUST_POLICY_PATH}: activation metadata가 유효하지 않습니다."
        )
        return context

    raw_issuers = policy.get("issuers")
    if not isinstance(raw_issuers, list) or not raw_issuers:
        context["policyError"] = f"{TRUST_POLICY_PATH}: issuers가 없습니다."
        return context

    issuer_policies: dict[str, dict[str, Any]] = {}
    max_validity_by_issuer: dict[str, int] = {}
    for candidate in raw_issuers:
        if not isinstance(candidate, dict):
            context["policyError"] = f"{TRUST_POLICY_PATH}: issuer 항목이 object가 아닙니다."
            return context
        issuer = text(candidate.get("issuer"))
        keys = candidate.get("publicKeys")
        max_validity = candidate.get("maxValiditySeconds")
        if (
            not issuer
            or text(candidate.get("algorithm")).lower() != "ed25519"
            or not isinstance(keys, dict)
            or not keys
            or type(max_validity) is not int
            or max_validity <= 0
        ):
            context["policyError"] = f"{TRUST_POLICY_PATH}: issuer 정책이 유효하지 않습니다."
            return context
        normalized_keys: dict[str, bytes] = {}
        for key_id, encoded_key in keys.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(encoded_key, str):
                context["policyError"] = f"{TRUST_POLICY_PATH}: public key 항목이 유효하지 않습니다."
                return context
            try:
                key_bytes = base64.b64decode(encoded_key, validate=True)
            except Exception:
                key_bytes = b""
            if len(key_bytes) != 32:
                context["policyError"] = (
                    f"{TRUST_POLICY_PATH}: {issuer}/{key_id} Ed25519 public key가 유효하지 않습니다."
                )
                return context
            normalized_keys[key_id] = key_bytes
        issuer_policies[issuer] = {
            "publicKeys": normalized_keys,
        }
        max_validity_by_issuer[issuer] = max_validity

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        context["policyError"] = (
            "[AUDITOR_TRUST:DEPENDENCY_MISSING] cryptography package가 필요합니다."
        )
        return context

    def verifier(payload: bytes, signature: str, issuer: str) -> bool:
        try:
            signed_fields = json.loads(payload.decode("utf-8"))
            key_id = text(signed_fields.get("keyId"))
            policy_for_issuer = issuer_policies.get(issuer, {})
            public_key = policy_for_issuer.get("publicKeys", {}).get(key_id)
            if not isinstance(public_key, bytes):
                return False
            signature_bytes = base64.b64decode(signature, validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature_bytes,
                payload,
            )
            return True
        except (InvalidSignature, ValueError, TypeError, json.JSONDecodeError):
            return False
        except Exception:
            return False

    context.update(
        {
            "trustedIssuers": set(issuer_policies),
            "maxValiditySecondsByIssuer": max_validity_by_issuer,
            "verifier": verifier,
            "activation": activation,
            "requiredCheckIntegrationId": integration_id,
            "requiredCheckName": TRUSTED_CHECK_NAME,
        }
    )
    return context


def load_authoritative_trust_context(
    candidate_root: Path,
    *,
    implementation_identity: str = "",
    now: int | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    values = os.environ if environment is None else environment
    configured_root = text(values.get(TRUST_ROOT_ENV, ""))
    if not configured_root:
        return {
            "trustedIssuers": set(),
            "implementationIdentity": implementation_identity,
            "consumedNonces": {},
            "now": int(time.time()) if now is None else now,
            "requiresKeyId": True,
            "requiresSessionId": True,
            "requiresAuditBundle": True,
            "requiresDecision": True,
            "policyError": f"{TRUST_ROOT_ENV}: protected external trust root가 설정되지 않았습니다.",
        }

    candidate_root = candidate_root.resolve()
    trust_root = Path(configured_root).expanduser().resolve()
    if (
        trust_root == candidate_root
        or trust_root in candidate_root.parents
        or candidate_root in trust_root.parents
    ):
        return {
            "trustedIssuers": set(),
            "implementationIdentity": implementation_identity,
            "consumedNonces": {},
            "now": int(time.time()) if now is None else now,
            "requiresKeyId": True,
            "requiresSessionId": True,
            "requiresAuditBundle": True,
            "requiresDecision": True,
            "policyError": f"{TRUST_ROOT_ENV}: candidate 저장소와 분리된 경로여야 합니다.",
        }
    context = load_trust_context(
        trust_root,
        staged=False,
        implementation_identity=implementation_identity,
        now=now,
    )
    context["trustRoot"] = str(trust_root)
    return context


def has_forbidden_completion_text(value: Any) -> bool:
    blob = json.dumps(value, ensure_ascii=False).lower()
    return any(token in blob for token in FORBIDDEN_TOKENS)


def is_work_classification(path: str) -> bool:
    normalized = normalize(path)
    return (
        normalized.startswith(WORK_CLASSIFICATION_PREFIX)
        and normalized.endswith(".json")
    )


def work_classifications_for_files(files: list[str]) -> list[str]:
    return [normalize(path) for path in files if is_work_classification(path)]


def declared_work_files(
    root: Path,
    path: str,
    *,
    staged: bool,
) -> tuple[list[str], str | None]:
    classification, error = read_json(root, path, staged=staged)
    if error:
        return [], error
    assert classification is not None
    raw_files = [normalize(item) for item in string_list(classification.get("stagedBehaviorFiles"))]
    if not raw_files:
        return [], f"{path}: stagedBehaviorFiles가 없습니다."
    if len(raw_files) != len(set(raw_files)):
        return [], f"{path}: stagedBehaviorFiles에 중복 경로가 있습니다."
    return sorted(raw_files), None


def validate_work_classification(
    root: Path,
    path: str,
    behavior_files: list[str],
    behavior_digest: str,
    *,
    staged: bool,
) -> tuple[str, list[str]]:
    classification, error = read_json(root, path, staged=staged)
    if error:
        return "", [error]
    assert classification is not None

    errors: list[str] = []
    if classification.get("schema") != "aims.regression_work.v1":
        errors.append("schema는 aims.regression_work.v1 이어야 합니다.")
    work_kind = text(classification.get("workKind"))
    if work_kind not in VALID_WORK_KINDS:
        errors.append(
            "workKind는 " + ", ".join(sorted(VALID_WORK_KINDS)) + " 중 하나여야 합니다."
        )

    classified_files = sorted(
        normalize(item) for item in string_list(classification.get("stagedBehaviorFiles"))
    )
    if classified_files != sorted(behavior_files):
        errors.append("stagedBehaviorFiles가 현재 staged behavior files와 일치하지 않습니다.")
    if behavior_digest and text(classification.get("stagedBehaviorDigest")) != behavior_digest:
        errors.append("stagedBehaviorDigest가 현재 staged behavior digest와 일치하지 않습니다.")

    target_binding = object_at(classification, "targetBinding")
    target_values = [
        *string_list(target_binding.get("issues")),
        *string_list(target_binding.get("releaseTags")),
        *string_list(target_binding.get("requirements")),
    ]
    if not target_values:
        errors.append("targetBinding에 issue, release tag, 또는 requirement가 필요합니다.")

    auditor = object_at(classification, "auditorReview")
    if text(auditor.get("agent")) != "Regression Auditor":
        errors.append("auditorReview.agent는 Regression Auditor여야 합니다.")
    if not text(auditor.get("agentId")):
        errors.append("auditorReview.agentId가 없습니다.")
    if text(auditor.get("implementationRole")).lower() != "independent":
        errors.append("auditorReview.implementationRole은 independent여야 합니다.")
    if text(auditor.get("status")).upper() != "PASS":
        errors.append("auditorReview.status는 PASS여야 합니다.")
    if not string_list(auditor.get("evidence")):
        errors.append("auditorReview.evidence가 없습니다.")
    if has_forbidden_completion_text(classification):
        errors.append("pending/예정/TODO/미실행/나중에 확인 문구가 있습니다.")

    return work_kind, [f"{path}: {item}" for item in errors]


def validate_step(
    receipt: dict[str, Any],
    key: str,
    required_status: str,
    required_exit_code: int | None,
    label: str,
    errors: list[str],
) -> None:
    step = object_at(receipt, key)
    if not step:
        errors.append(f"{label} 항목이 없습니다.")
        return
    if text(step.get("status")).upper() != required_status:
        errors.append(f"{label}.status는 {required_status}여야 합니다.")
    if not text(step.get("harnessId")):
        errors.append(f"{label}.harnessId가 없습니다.")
    if not text(step.get("harnessCommand")):
        errors.append(f"{label}.harnessCommand가 없습니다.")
    if not text(step.get("harnessDigest")):
        errors.append(f"{label}.harnessDigest가 없습니다.")
    if not text(step.get("command")):
        errors.append(f"{label}.command가 없습니다.")
    exit_code = step.get("exitCode")
    if required_status == "FAIL":
        if not isinstance(exit_code, int) or exit_code == 0:
            errors.append(f"{label}.exitCode는 0이 아닌 정수여야 합니다.")
    elif required_exit_code is not None and exit_code != required_exit_code:
        errors.append(f"{label}.exitCode는 {required_exit_code}이어야 합니다.")
    if not string_list(step.get("evidence")):
        errors.append(f"{label}.evidence가 없습니다.")


def validate_auditor_receipt(
    root: Path,
    path: str,
    subject_path: str,
    subject_hash: str,
    behavior_files: list[str],
    behavior_digest: str,
    *,
    staged: bool,
    trust_context: dict[str, Any] | None = None,
    required_reviewed_files: list[str] | None = None,
    expected_audit_bundle: dict[str, Any] | None = None,
) -> tuple[list[str], str, str]:
    auditor, error = read_json(root, path, staged=staged)
    if error:
        return [error], "", ""
    assert auditor is not None

    errors: list[str] = []
    if auditor.get("schema") != "aims.regression_auditor_receipt.v1":
        errors.append(f"{path}: schema는 aims.regression_auditor_receipt.v1 이어야 합니다.")
    if text(auditor.get("agent")) != "Regression Auditor":
        errors.append(f"{path}: agent는 Regression Auditor여야 합니다.")
    if not text(auditor.get("agentId")):
        errors.append(f"{path}: agentId가 없습니다.")
    if text(auditor.get("implementationRole")).lower() != "independent":
        errors.append(f"{path}: implementationRole은 independent여야 합니다.")
    if text(auditor.get("verdict")).upper() != "PASS":
        errors.append(f"{path}: verdict는 PASS여야 합니다.")
    if text(auditor.get("subjectReceipt")) != normalize(subject_path):
        errors.append(f"{path}: subjectReceipt가 대상 receipt와 일치하지 않습니다.")
    if text(auditor.get("subjectReceiptSha256")) != subject_hash:
        errors.append(f"{path}: subjectReceiptSha256이 대상 receipt와 일치하지 않습니다.")
    if behavior_digest:
        audited_files = sorted(normalize(item) for item in string_list(auditor.get("stagedBehaviorFiles")))
        if audited_files != sorted(behavior_files):
            errors.append(f"{path}: stagedBehaviorFiles가 현재 staged behavior files와 일치하지 않습니다.")
        if text(auditor.get("stagedBehaviorDigest")) != behavior_digest:
            errors.append(f"{path}: stagedBehaviorDigest가 현재 staged behavior digest와 일치하지 않습니다.")
    reviewed_files = {
        normalize(item) for item in string_list(auditor.get("reviewedFiles"))
    }
    if not reviewed_files:
        errors.append(f"{path}: reviewedFiles가 없습니다.")
    missing_reviewed_files = sorted(set(required_reviewed_files or []) - reviewed_files)
    if missing_reviewed_files:
        errors.append(
            f"{path}: reviewedFiles에 필수 검수 파일이 없습니다: "
            + ", ".join(missing_reviewed_files)
        )
    if not string_list(auditor.get("evidence")):
        errors.append(f"{path}: evidence가 없습니다.")
    if has_forbidden_completion_text(auditor):
        errors.append(f"{path}: pending/예정/TODO/미실행/나중에 확인 문구가 있습니다.")

    nonce_to_consume = ""
    nonce_binding = ""
    if trust_context is not None:
        policy_error = text(trust_context.get("policyError"))
        verifier = trust_context.get("verifier")
        signature = text(auditor.get("signature"))
        issuer = text(auditor.get("issuer"))
        trusted_issuers = {
            text(item)
            for item in trust_context.get("trustedIssuers", set())
            if text(item)
        }
        auditor_identity = text(auditor.get("auditorIdentity"))
        implementation_identity = text(auditor.get("implementationIdentity"))
        decision_reviewer_identity = text(
            auditor.get("decisionReviewerIdentity")
        )
        expected_implementation_identity = text(
            trust_context.get("implementationIdentity")
        )
        nonce = text(auditor.get("nonce"))
        consumed_nonces = trust_context.get("consumedNonces")
        now = trust_context.get("now")
        issued_at = auditor.get("issuedAt")
        expires_at = auditor.get("expiresAt")

        if policy_error:
            errors.append(
                f"{path}: [AUDITOR_TRUST:POLICY_INVALID] {policy_error}"
            )
        if not issuer or issuer not in trusted_issuers:
            errors.append(f"{path}: [AUDITOR_TRUST:UNTRUSTED_ISSUER]")
        if trust_context.get("requiresKeyId") is True and not text(auditor.get("keyId")):
            errors.append(f"{path}: [AUDITOR_TRUST:KEY_ID_MISSING]")
        if (
            trust_context.get("requiresKeyId") is True
            and text(auditor.get("signatureAlgorithm")).lower() != "ed25519"
        ):
            errors.append(f"{path}: [AUDITOR_TRUST:SIGNATURE_ALGORITHM_UNSUPPORTED]")
        if (
            trust_context.get("requiresSessionId") is True
            and not text(auditor.get("auditorSessionId"))
        ):
            errors.append(f"{path}: [AUDITOR_TRUST:AUDITOR_SESSION_MISSING]")
        if (
            trust_context.get("requiresAuditBundle") is True
            and auditor.get("auditBundle") != expected_audit_bundle
        ):
            errors.append(f"{path}: [AUDITOR_TRUST:AUDIT_BUNDLE_MISMATCH]")
        if trust_context.get("requiresDecision") is True:
            decision_path = text(auditor.get("auditorDecision"))
            decision_digest = text(auditor.get("auditorDecisionSha256"))
            if (
                not decision_path.startswith(AUDITOR_DECISION_PREFIX)
                or not decision_path.endswith(".json")
                or len(decision_digest) != 64
                or any(character not in "0123456789abcdef" for character in decision_digest)
            ):
                errors.append(f"{path}: [AUDITOR_TRUST:PROTECTED_DECISION_MISSING]")
        if (
            not auditor_identity
            or not implementation_identity
            or auditor_identity == implementation_identity
        ):
            errors.append(f"{path}: [AUDITOR_TRUST:IDENTITY_NOT_INDEPENDENT]")
        elif text(auditor.get("agentId")) != auditor_identity:
            errors.append(f"{path}: [AUDITOR_TRUST:AUDITOR_IDENTITY_MISMATCH]")
        implementation_user_id = github_numeric_identity(implementation_identity)
        reviewer_user_id = github_numeric_identity(decision_reviewer_identity)
        if (
            not decision_reviewer_identity
            or decision_reviewer_identity == implementation_identity
            or (
                implementation_user_id
                and reviewer_user_id
                and implementation_user_id == reviewer_user_id
            )
        ):
            errors.append(
                f"{path}: [AUDITOR_TRUST:DECISION_REVIEWER_NOT_INDEPENDENT]"
            )
        if (
            expected_implementation_identity
            and implementation_identity != expected_implementation_identity
        ):
            errors.append(f"{path}: [AUDITOR_TRUST:IMPLEMENTATION_IDENTITY_MISMATCH]")
        if text(auditor.get("subjectReceiptSha256")) != subject_hash:
            errors.append(f"{path}: [AUDITOR_TRUST:SUBJECT_DIGEST_MISMATCH]")

        nonce_binding = sha256_json_value(
            {
                "issuer": issuer,
                "subjectReceiptSha256": subject_hash,
                "auditBundle": auditor.get("auditBundle"),
            }
        )
        if not nonce:
            errors.append(f"{path}: [AUDITOR_TRUST:NONCE_MISSING]")
        elif isinstance(consumed_nonces, set):
            if nonce in consumed_nonces:
                errors.append(f"{path}: [AUDITOR_TRUST:NONCE_REPLAY]")
        elif isinstance(consumed_nonces, dict):
            existing_binding = consumed_nonces.get(nonce)
            if existing_binding is not None and existing_binding != nonce_binding:
                errors.append(f"{path}: [AUDITOR_TRUST:NONCE_REPLAY]")
        else:
            errors.append(f"{path}: [AUDITOR_TRUST:NONCE_STORE_MISSING]")

        valid_timestamps = (
            type(now) in {int, float}
            and type(issued_at) in {int, float}
            and type(expires_at) in {int, float}
            and issued_at < expires_at
        )
        if not valid_timestamps:
            errors.append(f"{path}: [AUDITOR_TRUST:TIMESTAMP_INVALID]")
        else:
            if issued_at > now:
                errors.append(f"{path}: [AUDITOR_TRUST:RECEIPT_NOT_YET_VALID]")
            if expires_at <= now:
                errors.append(f"{path}: [AUDITOR_TRUST:RECEIPT_EXPIRED]")
            validity_by_issuer = trust_context.get("maxValiditySecondsByIssuer")
            max_validity_seconds = (
                validity_by_issuer.get(issuer)
                if isinstance(validity_by_issuer, dict)
                else trust_context.get("maxValiditySeconds")
            )
            if (
                type(max_validity_seconds) in {int, float}
                and max_validity_seconds > 0
                and expires_at - issued_at > max_validity_seconds
            ):
                errors.append(f"{path}: [AUDITOR_TRUST:VALIDITY_WINDOW_TOO_LONG]")

        if not callable(verifier):
            errors.append(f"{path}: [AUDITOR_TRUST:VERIFIER_MISSING]")
        elif not signature or not issuer:
            errors.append(f"{path}: [AUDITOR_TRUST:SIGNATURE_MISSING]")
        else:
            payload = auditor_signature_payload(auditor)
            if not verifier(payload, signature, issuer):
                errors.append(f"{path}: [AUDITOR_TRUST:SIGNATURE_INVALID]")
        if not errors and nonce:
            nonce_to_consume = nonce
    return errors, nonce_to_consume, nonce_binding


def validate_runner_evidence(
    root: Path,
    receipt: dict[str, Any],
    *,
    staged: bool,
    behavior_digest: str,
    trust_context: dict[str, Any] | None,
    expected_metadata: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, list[str]]:
    reference = object_at(receipt, "runnerEvidence")
    if not reference:
        return None, [
            "[RUNNER_EVIDENCE:MISSING] trusted runner evidence가 없습니다. "
            "missing harness, collection failure, typed digest/exit code는 증거가 아닙니다."
        ]

    evidence_path = text(reference.get("path"))
    evidence_sha256 = text(reference.get("sha256")).lower()
    if not evidence_path.startswith(EVIDENCE_PREFIX) or not evidence_path.endswith(".json"):
        return None, [f"[RUNNER_EVIDENCE:PATH_INVALID] {EVIDENCE_PREFIX}*.json 경로가 필요합니다."]
    if len(evidence_sha256) != 64 or any(character not in "0123456789abcdef" for character in evidence_sha256):
        return None, ["[RUNNER_EVIDENCE:DIGEST_INVALID] sha256 값이 유효하지 않습니다."]

    content, read_error = read_bytes(root, evidence_path, staged=staged)
    if read_error:
        return None, [f"[RUNNER_EVIDENCE:NOT_FOUND] {read_error}"]
    assert content is not None
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != evidence_sha256:
        return None, ["[RUNNER_EVIDENCE:DIGEST_MISMATCH] evidence 파일 digest가 일치하지 않습니다."]
    try:
        evidence = json.loads(content.decode("utf-8"))
    except Exception as exc:
        return None, [f"[RUNNER_EVIDENCE:JSON_INVALID] {exc}"]
    if not isinstance(evidence, dict):
        return None, ["[RUNNER_EVIDENCE:STRUCTURE_INVALID] evidence는 object여야 합니다."]

    execution = object_at(evidence, "execution")
    if behavior_digest and text(execution.get("stagedDigest")) != behavior_digest:
        return None, [
            "[RUNNER_EVIDENCE:STAGED_DIGEST_MISMATCH] evidence가 현재 staged behavior digest에 묶이지 않았습니다."
        ]

    validator = trust_context.get("evidenceValidator") if trust_context else None
    if callable(validator):
        validation = validator(evidence, evidence_path, evidence_sha256)
    else:
        if expected_metadata is None:
            return None, [
                "[RUNNER_EVIDENCE:METADATA_BINDING_MISSING] runnerBinding이 없습니다."
            ]
        try:
            runner_path = Path(__file__).resolve().with_name("regression_evidence_runner.py")
            spec = importlib.util.spec_from_file_location(
                "aims_regression_evidence_runner",
                runner_path,
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"runner module을 불러올 수 없습니다: {runner_path}")
            runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runner)

            validation = runner.validate_evidence(
                evidence,
                text(execution.get("preCwd")),
                text(execution.get("postCwd")),
                expected_metadata=expected_metadata,
                source_root=root,
            )
        except Exception as exc:
            return None, [f"[RUNNER_EVIDENCE:VALIDATOR_ERROR] {exc}"]

    if not isinstance(validation, dict) or validation.get("accepted") is not True:
        code = text(validation.get("code")) if isinstance(validation, dict) else "VALIDATOR_INVALID"
        return None, [f"[RUNNER_EVIDENCE:{code or 'REJECTED'}]"]
    if text(validation.get("code")) != "VALID":
        return None, [f"[RUNNER_EVIDENCE:{text(validation.get('code')) or 'INVALID_SUCCESS'}]"]
    if not callable(validator):
        phases = [object_at(evidence, phase) for phase in ("preFix", "postFix")]
        structured_reports = [object_at(phase, "pytestReport") for phase in phases]
        if any(report.get("format") != "junit-xml" for report in structured_reports):
            return None, [
                "[RUNNER_EVIDENCE:STRUCTURED_PYTEST_REQUIRED] "
                "pre/post 실행 모두 JUnit XML pytest 결과가 필요합니다."
            ]
        if any(phase.get("executionMode") != "hardened-pytest-bootstrap" for phase in phases):
            return None, [
                "[RUNNER_EVIDENCE:HARDENED_EXECUTION_REQUIRED] "
                "pre/post 실행 모두 격리된 pytest bootstrap 증거가 필요합니다."
            ]
    return evidence, []


def validate_runner_metadata_binding(
    receipt: dict[str, Any],
    behavior_digest: str,
    *,
    trust_context: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, list[str]]:
    binding = receipt.get("runnerBinding")
    injected_validator = trust_context.get("evidenceValidator") if trust_context else None
    if not isinstance(binding, dict):
        if callable(injected_validator):
            return None, []
        return None, [
            "runnerBinding은 독립 Auditor receipt가 결속할 실행 메타데이터 object여야 합니다."
        ]

    errors: list[str] = []
    for key in ("preRef", "postRef", "testId"):
        if not text(binding.get(key)):
            errors.append(f"runnerBinding.{key}가 없습니다.")
    if not isinstance(binding.get("stagedDigest"), str):
        errors.append("runnerBinding.stagedDigest는 문자열이어야 합니다.")
    elif behavior_digest and text(binding.get("stagedDigest")) != behavior_digest:
        errors.append("runnerBinding.stagedDigest가 현재 staged behavior digest와 일치하지 않습니다.")
    started_at_unix_ns = binding.get("startedAtUnixNs")
    if type(started_at_unix_ns) is not int or started_at_unix_ns <= 0:
        errors.append("runnerBinding.startedAtUnixNs는 양의 정수여야 합니다.")
    return binding, errors


def validate_receipt_runner_binding(
    receipt: dict[str, Any],
    evidence: dict[str, Any],
) -> list[str]:
    execution = object_at(evidence, "execution")
    harness = object_at(evidence, "harness")
    pre_fix_evidence = object_at(evidence, "preFix")
    post_fix_evidence = object_at(evidence, "postFix")
    command = execution.get("command")
    command_text = json.dumps(
        command,
        ensure_ascii=False,
        separators=(",", ":"),
    ) if isinstance(command, list) else ""
    harness_digest = "sha256:" + text(harness.get("closureSha256"))
    harness_id = text(execution.get("testId"))

    errors: list[str] = []
    for key, phase_evidence, expected_status in (
        ("failFirst", pre_fix_evidence, "FAIL"),
        ("postFix", post_fix_evidence, "PASS"),
    ):
        phase = object_at(receipt, key)
        if text(phase.get("status")).upper() != expected_status:
            continue
        if text(phase.get("harnessId")) != harness_id:
            errors.append(f"{key}.harnessId가 runner evidence와 일치하지 않습니다.")
        if text(phase.get("harnessCommand")) != command_text:
            errors.append(f"{key}.harnessCommand가 runner evidence와 일치하지 않습니다.")
        if text(phase.get("command")) != command_text:
            errors.append(f"{key}.command가 runner evidence와 일치하지 않습니다.")
        if text(phase.get("harnessDigest")) != harness_digest:
            errors.append(f"{key}.harnessDigest가 runner evidence와 일치하지 않습니다.")
        if phase.get("exitCode") != phase_evidence.get("exitCode"):
            errors.append(f"{key}.exitCode가 runner evidence와 일치하지 않습니다.")
    return errors


def validate_receipt(
    root: Path,
    path: str,
    mode: str,
    *,
    staged: bool,
    issue: str = "",
    release_tag: str = "",
    behavior_files: list[str] | None = None,
    behavior_digest: str = "",
    trust_context: dict[str, Any] | None = None,
    work_classification_path: str = "",
    changed_files: list[str] | None = None,
) -> list[str]:
    receipt, error = read_json(root, path, staged=staged)
    if error:
        return [error]
    assert receipt is not None

    errors: list[str] = []
    if receipt.get("schema") != "aims.regression_auditor.v1":
        errors.append(f"{path}: schema는 aims.regression_auditor.v1 이어야 합니다.")

    receipt_mode = text(receipt.get("mode"))
    if receipt_mode not in {"bugfix", "regression", "issue-reopen", "issue-close", "release-pass", "process"}:
        errors.append(f"{path}: mode가 유효하지 않습니다.")
    if mode in {"issue-close", "release-pass"} and receipt_mode == "process":
        errors.append(f"{mode}에는 process receipt를 사용할 수 없습니다.")

    report_path = text(receipt.get("report"))
    committed_ref = (
        "HEAD"
        if (
            not staged
            and mode in {"issue-close", "release-pass"}
            and trust_context is not None
            and trust_context.get("requiresAuditBundle") is True
        )
        else ""
    )
    if not report_path.startswith(REPORT_PREFIX) or not report_path.endswith(".md"):
        errors.append(f"{path}: report는 {REPORT_PREFIX}*.md 이어야 합니다.")
    else:
        _, report_error = read_text(
            root,
            report_path,
            staged=staged,
            ref=committed_ref,
        )
        if report_error:
            errors.append(f"{path}: report 파일이 없습니다: {report_path}")

    validate_step(receipt, "failFirst", "FAIL", 1, "failFirst", errors)
    validate_step(receipt, "postFix", "PASS", 0, "postFix", errors)
    runner_binding, binding_errors = validate_runner_metadata_binding(
        receipt,
        behavior_digest,
        trust_context=trust_context,
    )
    errors.extend(binding_errors)
    runner_evidence, runner_errors = validate_runner_evidence(
        root,
        receipt,
        staged=staged,
        behavior_digest=behavior_digest,
        trust_context=trust_context,
        expected_metadata=runner_binding,
    )
    errors.extend(runner_errors)
    if runner_evidence is not None:
        errors.extend(validate_receipt_runner_binding(receipt, runner_evidence))
    fail_first = object_at(receipt, "failFirst")
    post_fix = object_at(receipt, "postFix")
    fail_harness = text(fail_first.get("harnessId"))
    post_harness = text(post_fix.get("harnessId"))
    if fail_harness and post_harness and fail_harness != post_harness:
        errors.append("failFirst.harnessId와 postFix.harnessId가 일치해야 합니다.")
    fail_harness_command = text(fail_first.get("harnessCommand"))
    post_harness_command = text(post_fix.get("harnessCommand"))
    if fail_harness_command and post_harness_command and fail_harness_command != post_harness_command:
        errors.append("failFirst.harnessCommand와 postFix.harnessCommand가 일치해야 합니다.")
    fail_harness_digest = text(fail_first.get("harnessDigest"))
    post_harness_digest = text(post_fix.get("harnessDigest"))
    if fail_harness_digest and post_harness_digest and fail_harness_digest != post_harness_digest:
        errors.append("failFirst.harnessDigest와 postFix.harnessDigest가 일치해야 합니다.")

    entry_matrix = object_at(receipt, "userEntryMatrix")
    if text(entry_matrix.get("status")).upper() != "PASS":
        errors.append("userEntryMatrix.status는 PASS여야 합니다.")
    if not text(entry_matrix.get("entryPath")):
        errors.append("userEntryMatrix.entryPath가 없습니다.")
    if not string_list(entry_matrix.get("stateCombinations")):
        errors.append("userEntryMatrix.stateCombinations가 없습니다.")
    if not string_list(entry_matrix.get("evidence")):
        errors.append("userEntryMatrix.evidence가 없습니다.")

    targets = object_at(receipt, "targets")
    if mode == "issue-close":
        issues = {item.lstrip("#") for item in string_list(targets.get("issues"))}
        if not issue:
            errors.append("issue-close mode에는 --issue가 필요합니다.")
        elif issue.lstrip("#") not in issues:
            errors.append(f"targets.issues에 issue #{issue.lstrip('#')}가 없습니다.")
    if mode == "release-pass":
        release_tags = set(string_list(targets.get("releaseTags")))
        if not release_tag:
            errors.append("release-pass mode에는 --release-tag가 필요합니다.")
        elif release_tag not in release_tags:
            errors.append(f"targets.releaseTags에 release tag {release_tag}가 없습니다.")

    live_status = text(receipt.get("liveOnlyStatus"))
    live_dependency = object_at(receipt, "liveDependency")
    dependency_status = text(live_dependency.get("status"))
    if live_status not in VALID_LIVE_STATUS:
        errors.append(f"liveOnlyStatus는 {', '.join(sorted(VALID_LIVE_STATUS))} 중 하나여야 합니다.")
    if dependency_status not in VALID_LIVE_STATUS:
        errors.append("liveDependency.status가 유효하지 않습니다.")
    if live_status and dependency_status and live_status != dependency_status:
        errors.append("liveOnlyStatus와 liveDependency.status가 일치해야 합니다.")
    if not text(live_dependency.get("rationale")):
        errors.append("liveDependency.rationale이 없습니다.")

    auditor = object_at(receipt, "auditor")
    if text(auditor.get("agent")) != "Regression Auditor":
        errors.append("auditor.agent는 Regression Auditor여야 합니다.")
    if not text(auditor.get("agentId")):
        errors.append("auditor.agentId가 없습니다.")
    if text(auditor.get("implementationRole")).lower() != "independent":
        errors.append("auditor.implementationRole은 independent여야 합니다.")
    if text(auditor.get("status")).upper() != "PASS":
        errors.append("auditor.status는 PASS여야 합니다.")
    if not string_list(auditor.get("reviewedFiles")):
        errors.append("auditor.reviewedFiles가 없습니다.")
    if not string_list(auditor.get("evidence")):
        errors.append("auditor.evidence가 없습니다.")

    required_reviewed_files = [text(object_at(receipt, "runnerEvidence").get("path"))]
    required_reviewed_files = [path for path in required_reviewed_files if path]
    work_classification: dict[str, Any] | None = None
    if work_classification_path:
        if text(receipt.get("workClassification")) != work_classification_path:
            errors.append("workClassification이 현재 staged classification과 일치하지 않습니다.")
        classification, classification_error = read_json(
            root,
            work_classification_path,
            staged=staged,
        )
        if classification_error:
            errors.append(classification_error)
        else:
            assert classification is not None
            work_classification = classification
            classification_auditor = object_at(classification, "auditorReview")
            if text(classification_auditor.get("agentId")) != text(auditor.get("agentId")):
                errors.append(
                    "work classification auditorReview.agentId가 subject receipt auditor.agentId와 일치하지 않습니다."
                )
        required_reviewed_files.append(work_classification_path)
    receipt_reviewed_files = {
        normalize(item) for item in string_list(auditor.get("reviewedFiles"))
    }
    missing_receipt_reviews = sorted(set(required_reviewed_files) - receipt_reviewed_files)
    if missing_receipt_reviews:
        errors.append(
            "auditor.reviewedFiles에 필수 검수 파일이 없습니다: "
            + ", ".join(missing_receipt_reviews)
        )

    if has_forbidden_completion_text(receipt):
        errors.append("receipt에 pending/예정/TODO/미실행/나중에 확인 문구가 있습니다.")

    if report_path:
        report_content, report_read_error = read_text(
            root,
            report_path,
            staged=staged,
            ref=committed_ref,
        )
        if report_read_error:
            errors.append(f"{report_path}: 완료 증거 report를 읽을 수 없습니다.")
            report_text = ""
        else:
            report_text = (report_content or "").lower()
        if any(token in report_text for token in FORBIDDEN_TOKENS):
            errors.append(f"{report_path}: 완료 증거에 금지 문구가 있습니다.")

    if mode in {"issue-close", "release-pass"} and live_status == "OPEN_UNTIL_LIVE_PASS":
        errors.append(f"{mode}는 OPEN_UNTIL_LIVE_PASS 상태에서 차단됩니다.")
    if mode in {"issue-close", "release-pass"} and live_status not in {"none", "LIVE_VERIFIED"}:
        errors.append(f"{mode}는 liveOnlyStatus가 none 또는 LIVE_VERIFIED일 때만 허용됩니다.")
    if live_status == "LIVE_VERIFIED":
        live_verification = object_at(receipt, "liveVerification")
        if text(live_verification.get("status")).upper() != "PASS":
            errors.append("LIVE_VERIFIED에는 liveVerification.status PASS가 필요합니다.")
        if not text(live_verification.get("command")):
            errors.append("LIVE_VERIFIED에는 liveVerification.command가 필요합니다.")
        if not string_list(live_verification.get("evidence")):
            errors.append("LIVE_VERIFIED에는 liveVerification.evidence가 필요합니다.")

    auditor_receipt = text(receipt.get("auditorReceipt"))
    if not auditor_receipt.startswith(AUDITOR_RECEIPT_PREFIX):
        errors.append(f"auditorReceipt는 {AUDITOR_RECEIPT_PREFIX}*.json 이어야 합니다.")
    else:
        audit_context = object_at(trust_context or {}, "auditContext")
        if (
            trust_context is not None
            and trust_context.get("requiresAuditBundle") is True
            and not audit_context
        ):
            try:
                audit_context = candidate_audit_context(
                    root,
                    changed_files or [],
                    staged=staged,
                    excluded_receipt=auditor_receipt,
                )
            except Exception as exc:
                errors.append(f"[AUDITOR_TRUST:AUDIT_CONTEXT_INVALID] {exc}")
        subject_hash = sha256_json({k: v for k, v in receipt.items() if k != "auditorReceipt"})
        expected_audit_bundle = build_audit_bundle(
            receipt,
            subject_hash,
            behavior_files or [],
            behavior_digest,
            work_classification_path=work_classification_path,
            work_classification=work_classification,
            repository=text(audit_context.get("repository")),
            base_commit_sha=text(audit_context.get("baseCommitSha")),
            candidate_tree_sha=text(audit_context.get("candidateTreeSha")),
            candidate_files=string_list(audit_context.get("candidateFiles")),
            candidate_digest=text(audit_context.get("candidateDigest")),
        )
        auditor_errors, nonce_to_consume, nonce_binding = validate_auditor_receipt(
            root,
            auditor_receipt,
            path,
            subject_hash,
            behavior_files or [],
            behavior_digest,
            staged=staged,
            trust_context=trust_context,
            required_reviewed_files=required_reviewed_files,
            expected_audit_bundle=expected_audit_bundle,
        )
        errors.extend(auditor_errors)
        if not errors and nonce_to_consume and trust_context is not None:
            consumed_nonces = trust_context.get("consumedNonces")
            if isinstance(consumed_nonces, set):
                consumed_nonces.add(nonce_to_consume)
            elif isinstance(consumed_nonces, dict):
                register_nonce(
                    consumed_nonces,
                    nonce_to_consume,
                    nonce_binding,
                )

    return [f"{path}: {item}" for item in errors]


def receipts_for_files(files: list[str]) -> list[str]:
    return [path for path in files if is_audit_receipt(path)]


def receipt_work_classification(
    root: Path,
    path: str,
    *,
    staged: bool,
) -> tuple[str, str | None]:
    receipt, error = read_json(root, path, staged=staged)
    if error:
        return "", error
    assert receipt is not None
    return text(receipt.get("workClassification")), None


def needs_commit_gate(
    files: list[str],
    force: bool,
    *,
    work_kind: str | None = None,
) -> bool:
    if force:
        return True
    if work_kind is not None:
        return work_kind in FAIL_FIRST_WORK_KINDS or work_kind not in VALID_WORK_KINDS
    return any(is_behavior_file(path) for path in files)


def check(
    root: Path,
    files: list[str],
    mode: str,
    force: bool,
    explicit_receipts: list[str],
    *,
    staged: bool = False,
    issue: str = "",
    release_tag: str = "",
    trust_context: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    receipts = [normalize(path) for path in explicit_receipts] or receipts_for_files(files)
    normalized_files = {normalize(path) for path in files}
    recognized_behavior_files = sorted(path for path in normalized_files if is_behavior_file(path))
    behavior_files = recognized_behavior_files
    behavior_digest = staged_files_digest(behavior_files, root=root) if staged else ""
    classifications = work_classifications_for_files(files)
    work_classification_path = ""
    classification_bindings: dict[str, tuple[list[str], str, str]] = {}

    if mode == "commit" and classifications:
        declared_by_classification: dict[str, list[str]] = {}
        binding_errors: list[str] = []
        for classification_path in classifications:
            declared_files, declared_error = declared_work_files(
                root,
                classification_path,
                staged=staged,
            )
            if declared_error:
                binding_errors.append(declared_error)
                continue

            declared_by_classification[classification_path] = declared_files
            declared_digest = (
                staged_files_digest(declared_files, root=root)
                if staged
                else git_files_digest(root, declared_files)
            )
            classification_bindings[classification_path] = (
                declared_files,
                declared_digest,
                "",
            )

        if binding_errors:
            return (
                False,
                "[REGRESSION AUDITOR GATE] BLOCK:\n"
                + "\n".join(f"  - {error}" for error in binding_errors),
            )

        covering_classifications = [
            path
            for path, declared_files in declared_by_classification.items()
            if sorted(declared_files) == recognized_behavior_files
        ]
        if len(classifications) > 1:
            if len(covering_classifications) != 1:
                detail = (
                    "없습니다."
                    if not covering_classifications
                    else "여러 개입니다."
                )
                return (
                    False,
                    "[REGRESSION AUDITOR GATE] BLOCK: staged/PR 전체 behavior 변경을 덮는 "
                    f"work classification이 {detail}",
                )
            work_classification_path = covering_classifications[0]
        else:
            work_classification_path = classifications[0]

        if work_classification_path:
            behavior_files, behavior_digest, _ = classification_bindings[
                work_classification_path
            ]
        else:
            behavior_files = []
            behavior_digest = ""

        unstaged_declared = sorted(set(behavior_files) - normalized_files)
        missing_recognized = sorted(set(recognized_behavior_files) - set(behavior_files))
        if unstaged_declared:
            binding_errors.append(
                f"{work_classification_path}: stagedBehaviorFiles에 staged/PR 변경이 아닌 경로가 있습니다: "
                + ", ".join(unstaged_declared)
            )
        if missing_recognized:
            binding_errors.append(
                "work classification이 staged/PR behavior files를 누락했습니다: "
                + ", ".join(missing_recognized)
            )
        if binding_errors:
            return (
                False,
                "[REGRESSION AUDITOR GATE] BLOCK:\n"
                + "\n".join(f"  - {error}" for error in binding_errors),
            )

        if work_classification_path:
            work_kind, classification_errors = validate_work_classification(
                root,
                work_classification_path,
                behavior_files,
                behavior_digest,
                staged=staged,
            )
            binding_errors.extend(classification_errors)
            classification_bindings[work_classification_path] = (
                behavior_files,
                behavior_digest,
                work_kind,
            )

        if binding_errors:
            return (
                False,
                "[REGRESSION AUDITOR GATE] BLOCK:\n"
                + "\n".join(f"  - {error}" for error in binding_errors),
            )

        if work_classification_path:
            behavior_files, behavior_digest, work_kind = classification_bindings[
                work_classification_path
            ]
        else:
            work_kind = "verification-gate"
        if not needs_commit_gate(files, force, work_kind=work_kind):
            return (
                True,
                f"[REGRESSION AUDITOR GATE] PASS: {work_kind} work classification; "
                "fail-first 대상 아님",
            )
    elif mode == "commit" and behavior_files:
        return (
            False,
            "[REGRESSION AUDITOR GATE] BLOCK: staged behavior 변경에는 정확히 하나의 "
            f"{WORK_CLASSIFICATION_PREFIX}*.json work classification이 필요합니다.",
        )
    elif mode == "commit" and not needs_commit_gate(files, force):
        return True, "[REGRESSION AUDITOR GATE] PASS: 대상 변경 없음"

    if not receipts:
        return (
            False,
            "[REGRESSION AUDITOR GATE] BLOCK: Regression Auditor receipt가 없습니다.\n"
            f"  {AUDIT_PREFIX}*.json 파일을 추가하고 fail-first/post-fix/Auditor/live 상태 증거를 기록하세요.",
        )

    errors: list[str] = []
    if mode == "commit" and work_classification_path:
        filtered_receipts: list[str] = []
        for receipt in receipts:
            receipt_classification, receipt_error = receipt_work_classification(
                root,
                receipt,
                staged=staged,
            )
            if receipt_error:
                errors.append(receipt_error)
            elif receipt_classification == work_classification_path:
                filtered_receipts.append(receipt)
        if not errors:
            if not filtered_receipts:
                errors.append(
                    f"{work_classification_path}: PR 전체 behavior 변경을 덮는 "
                    "Regression Auditor subject receipt가 없습니다."
                )
            else:
                receipts = filtered_receipts

    for receipt in receipts:
        receipt_classification_path = work_classification_path
        receipt_behavior_files = behavior_files
        receipt_behavior_digest = behavior_digest
        if mode == "commit" and classifications and not work_classification_path:
            receipt_classification_path, receipt_error = receipt_work_classification(
                root,
                receipt,
                staged=staged,
            )
            if receipt_error:
                errors.append(receipt_error)
                continue
            if receipt_classification_path not in classification_bindings:
                errors.append(
                    f"{receipt}: workClassification이 현재 staged/PR classification에 없습니다."
                )
                continue
            (
                receipt_behavior_files,
                receipt_behavior_digest,
                _,
            ) = classification_bindings[receipt_classification_path]
        errors.extend(validate_receipt(
            root,
            receipt,
            mode,
            staged=staged,
            issue=issue,
            release_tag=release_tag,
            behavior_files=receipt_behavior_files,
            behavior_digest=receipt_behavior_digest,
            trust_context=trust_context,
            work_classification_path=receipt_classification_path,
            changed_files=sorted(normalized_files),
        ))

    if errors:
        return False, "[REGRESSION AUDITOR GATE] BLOCK:\n" + "\n".join(f"  - {error}" for error in errors)
    return True, f"[REGRESSION AUDITOR GATE] PASS ({len(receipts)} receipt)"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Regression Auditor receipts.")
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--mode", choices=["commit", "issue-close", "release-pass"], default="commit")
    parser.add_argument("--staged", action="store_true", help="Read staged files from git.")
    parser.add_argument("--files", nargs="*", default=None, help="Explicit changed file list.")
    parser.add_argument("--receipt", action="append", default=[], help="Explicit receipt path.")
    parser.add_argument("--issue", default="", help="Issue number for issue-close mode.")
    parser.add_argument("--release-tag", default="", help="Release tag for release-pass mode.")
    parser.add_argument("--force", action="store_true", help="Require a receipt even if the file set is not auto-detected.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root).resolve()
    try:
        files = staged_files(root) if args.staged else [normalize(path) for path in (args.files or [])]
        ok, message = check(
            root,
            files,
            args.mode,
            args.force,
            args.receipt,
            staged=args.staged,
            issue=args.issue,
            release_tag=args.release_tag,
            trust_context=load_authoritative_trust_context(
                root,
                implementation_identity=text(
                    os.environ.get("AIMS_IMPLEMENTATION_IDENTITY", "")
                ),
            ),
        )
    except Exception as exc:
        print(f"[REGRESSION AUDITOR GATE] BLOCK: {exc}", file=sys.stderr)
        return 2

    print(message, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
