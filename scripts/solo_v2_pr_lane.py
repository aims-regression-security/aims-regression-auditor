#!/usr/bin/env python3
"""Classify an exact AIMS PR delta with the protected Solo-v2 snapshot.

This module lives in the external verifier repository intentionally.  It never
imports classifier code from the candidate checkout.  Direct and Core PRs can
therefore reuse their already-completed local Solo-v2 verification, while
Protected, legacy, ambiguous, and classifier-changing PRs stay on the signed
receipt verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Collection, Sequence


SNAPSHOT_VERSION = "solo-v2-external-2026-07-21.1"
SOLO_POLICY_VERSION = "solo-v2"
LEGACY_POLICY_VERSION = "legacy-v1"
POLICY_POINTER_PATH = "docs/requirements/solo-agent-quality-gate-policy.json"
CLASSIFIER_PATH = "scripts/solo_agent_quality_gate_policy.py"
EXPECTED_CANDIDATE_CLASSIFIER_SHA256S = frozenset(
    {
        # Current AIMS main / PR #371.
        "2aa1ba6698eb78d7e43cc509ef802b2b8a268e2675dd0d41565762a4de80c088",
        # #372 transition candidate. Its own delta remains Protected below;
        # after that candidate merges, ordinary future Core PRs are recognized.
        "6689e7ef95a95c4e777dec3c304c34c4000bd26e28456eb9ef9d329399152a95",
        # AIMS main after #384 runtime PNG classifier correction.
        "2ff30f54ebb235b59a373925d8dbf5314cdb3675cdaf36fe8069074d80ef4dda",
    }
)
AC_RUNTIME_IMAGE_CLASSIFIER_SHA256S = frozenset(
    {
        # AIMS #384 introduced the exact runtime-PNG semantics mirrored below.
        # Older accepted classifier snapshots must not inherit this capability.
        "2ff30f54ebb235b59a373925d8dbf5314cdb3675cdaf36fe8069074d80ef4dda",
    }
)
EXPECTED_CANDIDATE_POINTER_SHA256 = (
    "84c91604534a30fe771e6ed4fd05a7a49e955030194b577afa44f29ec9556fb7"
)

DIRECT_SUFFIXES = {".md", ".txt"}
CODE_SUFFIXES = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".css",
    ".html",
    ".ps1",
    ".bat",
    ".sh",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".conf",
    ".ini",
    ".webmanifest",
    ".iss",
}
RUNTIME_METADATA_PATHS = {
    "tools/auto_clicker_v2/version",
    "backend/api/aims_api/version",
    "backend/api/aims_rag_api/version",
    "backend/api/annual_report_api/version",
    "backend/api/pdf_proxy/version",
}
EVIDENCE_ASSET_PATH_PATTERN = re.compile(
    r"^docs/ace-reports/assets/issue[0-9]+(?:-[a-z0-9][a-z0-9-]*)?/"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}/[a-z0-9][a-z0-9._-]*\.png$"
)
AC_RUNTIME_IMAGE_PREFIX = "tools/auto_clicker_v2/img/"
PROTECTED_PREFIXES = ("deploy", "migration", "migrations", "infrastructure/")
PROTECTED_FILENAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "docker-compose.yml",
    "docker-compose.yaml",
}
PROTECTED_KEYWORDS = (
    "auth",
    "permission",
    "security",
    "secret",
    "credential",
    "delete",
    "remove",
)
NON_DOWNGRADABLE_TRUST_PREFIXES = (
    ".github/",
    ".husky/",
    ".agents/",
    ".claude/",
    ".codex/",
    "agents.md",
    "claude.md",
    "docs/ai_workflow.md",
    "docs/requirements/solo-agent-quality-gate",
    "scripts/regression",
    "scripts/gate",
    "scripts/pre_",
    "scripts/bounded",
    "scripts/solo_",
    "scripts/ac_release_candidate.py",
    "scripts/finish_branch.py",
)
CANONICAL_GATE_PATHS = {
    "scripts/check_ace_assets_policy.py",
    "scripts/agent_audit_check.py",
    "scripts/tier0_issue_close.py",
    "scripts/work_gate_check.py",
    "docs/requirements/regression-auditor-agent.md",
    "docs/requirements/regression-quality-gate-operating-report-2026-07-16.md",
}
HARD_OPERATIONAL_MARKERS = (
    "deploy",
    "release",
    "publish",
    "auth",
    "oauth",
    "login",
    "permission",
    "security",
    "secret",
    "credential",
    "token",
    "session",
    "revocation",
    "admin",
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MODE_PATTERN = re.compile(r"^[0-7]{6}$")


@dataclass(frozen=True)
class LaneDecision:
    lane: str
    policy_version: str
    requires_protected_verifier: bool
    reason_code: str
    reason: str
    snapshot_version: str = SNAPSHOT_VERSION

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def protected(reason_code: str, reason: str, policy_version: str = "unknown") -> LaneDecision:
    return LaneDecision(
        lane="protected",
        policy_version=policy_version,
        requires_protected_verifier=True,
        reason_code=reason_code,
        reason=reason,
    )


def _normalize_path(path: str) -> str | None:
    normalized = path.replace("\\", "/").lower()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    pure = PurePosixPath(normalized)
    if not normalized or pure.is_absolute() or ".." in pure.parts:
        return None
    return normalized


def _is_direct_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return pure.suffix in DIRECT_SUFFIXES and (
        "/" not in path
        or path.startswith("docs/")
        or pure.name.startswith(("readme", "changelog", "license", "notice"))
    )


def _is_dependency_manifest(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        name in PROTECTED_FILENAMES
        or name in {"setup.py", "setup.cfg", "uv.lock", "environment.yml", "environment.yaml"}
        or (name.startswith("requirements") and name.endswith(".txt"))
        or (name.startswith("constraints") and name.endswith(".txt"))
    )


def _is_deployment_manifest(path: str) -> bool:
    name = PurePosixPath(path).name
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.startswith("docker-compose.")
        or name.startswith("compose.")
    )


def _is_hard_operational_path(path: str) -> bool:
    return (
        any(marker in path for marker in HARD_OPERATIONAL_MARKERS)
        or path.startswith(("runtime/", "fixtures/", "test-data/", "test_data/"))
        or any(
            segment in {"fixtures", "test-data", "test_data", "snapshots"}
            for segment in path.split("/")
        )
    )


def _is_evidence_asset_path(path: str) -> bool:
    return EVIDENCE_ASSET_PATH_PATTERN.fullmatch(path) is not None


def _is_ac_runtime_image_path(path: str) -> bool:
    if not path.startswith(AC_RUNTIME_IMAGE_PREFIX):
        return False
    relative_path = path[len(AC_RUNTIME_IMAGE_PREFIX) :]
    parts = relative_path.split("/")
    return (
        PurePosixPath(relative_path).suffix == ".png"
        and bool(relative_path)
        and all(part not in {"", ".", ".."} for part in parts)
    )


def _is_executable_agent_or_gate_path(path: str) -> bool:
    suffix = PurePosixPath(path).suffix
    name = PurePosixPath(path).name
    if path.startswith((".agents/", ".claude/", ".codex/")):
        return suffix not in DIRECT_SUFFIXES
    if not path.startswith("scripts/") or suffix not in CODE_SUFFIXES:
        return False
    return any(
        marker in name
        for marker in (
            "gate",
            "verify",
            "verifier",
            "review",
            "auditor",
            "finish_branch",
            "e2e_matrix",
            "smoke",
            "orchestrator",
            "forward_sync",
            "tag_wcs_verified",
            "update_wcs_verified",
        )
    )


def _is_protected_path(path: str, *, allow_ac_runtime_images: bool = False) -> bool:
    name = PurePosixPath(path).name
    return (
        path == POLICY_POINTER_PATH
        or path == CLASSIFIER_PATH
        or path.startswith(PROTECTED_PREFIXES)
        or path.startswith(NON_DOWNGRADABLE_TRUST_PREFIXES)
        or path in CANONICAL_GATE_PATHS
        or _is_dependency_manifest(path)
        or _is_deployment_manifest(path)
        or _is_executable_agent_or_gate_path(path)
        or (
            not (allow_ac_runtime_images and _is_ac_runtime_image_path(path))
            and (
                _is_hard_operational_path(path)
                or any(keyword in PurePosixPath(path).stem for keyword in PROTECTED_KEYWORDS)
                or any(
                    segment in {"auth", "security", "permission"}
                    for segment in path.split("/")
                )
            )
        )
        or name in {"agents.md", "claude.md"}
    )


def parse_raw_diff(raw: bytes) -> tuple[list[str], str | None]:
    """Return normalized paths or a fail-closed structural reason.

    Rename/copy records and every non-ordinary mode transition are Protected.
    The caller uses ``git diff --raw -z --find-renames`` so path delimiters are
    unambiguous and candidate-controlled whitespace cannot alter parsing.
    """

    tokens = raw.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    if not tokens:
        return [], "empty_diff"

    paths: list[str] = []
    index = 0
    while index < len(tokens):
        try:
            header = tokens[index].decode("ascii")
        except UnicodeDecodeError:
            return [], "malformed_raw_diff"
        index += 1
        fields = header.split()
        if len(fields) != 5 or not fields[0].startswith(":"):
            return [], "malformed_raw_diff"
        old_mode, new_mode = fields[0][1:], fields[1]
        old_sha, new_sha, status_token = fields[2], fields[3], fields[4]
        if (
            not MODE_PATTERN.fullmatch(old_mode)
            or not MODE_PATTERN.fullmatch(new_mode)
            or not SHA_PATTERN.fullmatch(old_sha)
            or not SHA_PATTERN.fullmatch(new_sha)
            or not status_token
        ):
            return [], "malformed_raw_diff"

        status = status_token[0]
        path_count = 2 if status in {"R", "C"} else 1
        if index + path_count > len(tokens):
            return [], "malformed_raw_diff"
        record_paths: list[str] = []
        for token in tokens[index : index + path_count]:
            try:
                decoded = token.decode("utf-8")
            except UnicodeDecodeError:
                return [], "malformed_raw_diff"
            normalized = _normalize_path(decoded)
            if normalized is None:
                return [], "malformed_raw_diff"
            record_paths.append(normalized)
        index += path_count

        if status in {"R", "C"}:
            return [], "rename_or_copy"
        safe_modes = {
            "A": ("000000", "100644"),
            "M": ("100644", "100644"),
            "D": ("100644", "000000"),
        }
        if status not in safe_modes:
            return [], "unsupported_delta_status"
        if (old_mode, new_mode) != safe_modes[status]:
            return [], "mode_change"
        paths.extend(record_paths)

    return paths, None


def classify_paths(
    paths: Sequence[str],
    policy_version: str,
    *,
    allow_ac_runtime_images: bool = False,
) -> LaneDecision:
    if policy_version == LEGACY_POLICY_VERSION:
        return protected(
            "legacy_policy",
            "legacy-v1 candidates require the signed receipt verifier",
            policy_version,
        )
    if policy_version != SOLO_POLICY_VERSION:
        return protected(
            "invalid_policy_pointer",
            "unknown or invalid policy pointer fails closed",
            policy_version,
        )
    if not paths:
        return protected("empty_diff", "empty PR delta fails closed", policy_version)
    if POLICY_POINTER_PATH in paths:
        return protected(
            "policy_pointer_change",
            "policy pointer changes require the signed receipt verifier",
            policy_version,
        )
    if CLASSIFIER_PATH in paths:
        return protected(
            "classifier_self_change",
            "candidate classifier changes require the signed receipt verifier",
            policy_version,
        )
    protected_paths = [
        path
        for path in paths
        if _is_protected_path(
            path,
            allow_ac_runtime_images=allow_ac_runtime_images,
        )
    ]
    if protected_paths:
        return protected(
            "protected_path",
            "deploy, release, security, dependency, or gate trust-boundary path changed",
            policy_version,
        )
    if all(_is_direct_path(path) for path in paths):
        return LaneDecision(
            lane="direct",
            policy_version=policy_version,
            requires_protected_verifier=False,
            reason_code="direct_text",
            reason="documentation or text-only PR reuses the Direct verification result",
        )
    if all(
        PurePosixPath(path).suffix in CODE_SUFFIXES
        or _is_direct_path(path)
        or _is_evidence_asset_path(path)
        or (allow_ac_runtime_images and _is_ac_runtime_image_path(path))
        or path in RUNTIME_METADATA_PATHS
        for path in paths
    ):
        return LaneDecision(
            lane="core",
            policy_version=policy_version,
            requires_protected_verifier=False,
            reason_code="core_behavior",
            reason="ordinary behavior PR reuses the completed Solo-v2 Core verification",
        )
    return protected(
        "unknown_path",
        "unrecognized candidate path fails closed",
        policy_version,
    )


def read_candidate_blob(root: Path, head: str, path: str) -> bytes | None:
    completed = subprocess.run(
        ["git", "-C", str(root), "show", f"{head}:{path}"],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=10,
    )
    if completed.returncode:
        return None
    return completed.stdout


def parse_policy_pointer(raw: bytes | None) -> str:
    if raw is None:
        return "invalid-pointer"
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "invalid-pointer"
    if not isinstance(payload, dict):
        return "invalid-pointer"
    version = payload.get("activePolicyVersion")
    return version if isinstance(version, str) else "invalid-pointer"


def is_expected_classifier_sha256(
    digest: str,
    expected: Collection[str] = EXPECTED_CANDIDATE_CLASSIFIER_SHA256S,
) -> bool:
    return SHA256_PATTERN.fullmatch(digest) is not None and digest in expected


def classify_git_delta(
    root: Path,
    base: str,
    head: str,
    *,
    expected_classifier_sha256s: Collection[str] = EXPECTED_CANDIDATE_CLASSIFIER_SHA256S,
    expected_pointer_sha256: str = EXPECTED_CANDIDATE_POINTER_SHA256,
    ac_runtime_image_classifier_sha256s: Collection[
        str
    ] = AC_RUNTIME_IMAGE_CLASSIFIER_SHA256S,
) -> LaneDecision:
    if not SHA_PATTERN.fullmatch(base) or not SHA_PATTERN.fullmatch(head):
        return protected("invalid_coordinates", "invalid PR commit coordinates")
    pointer_blob = read_candidate_blob(root, head, POLICY_POINTER_PATH)
    policy_version = parse_policy_pointer(pointer_blob)
    if policy_version == LEGACY_POLICY_VERSION:
        return protected(
            "legacy_policy",
            "legacy-v1 candidates require the signed receipt verifier",
            policy_version,
        )
    if policy_version != SOLO_POLICY_VERSION:
        return protected(
            "invalid_policy_pointer",
            "unknown or invalid policy pointer fails closed",
            policy_version,
        )
    if pointer_blob is None or hashlib.sha256(pointer_blob).hexdigest() != expected_pointer_sha256:
        return protected(
            "policy_pointer_snapshot_mismatch",
            "candidate policy pointer differs from the protected external snapshot",
            policy_version,
        )
    classifier_blob = read_candidate_blob(root, head, CLASSIFIER_PATH)
    classifier_sha256 = (
        hashlib.sha256(classifier_blob).hexdigest()
        if classifier_blob is not None
        else ""
    )
    if (
        classifier_blob is None
        or not is_expected_classifier_sha256(
            classifier_sha256,
            expected_classifier_sha256s,
        )
    ):
        return protected(
            "classifier_snapshot_mismatch",
            "candidate classifier differs from the protected external snapshot",
            policy_version,
        )
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "diff",
                "--raw",
                "-z",
                "--no-abbrev",
                "--find-renames",
                f"{base}...{head}",
            ],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return protected(
            "git_diff_error",
            "authoritative PR raw diff inspection failed closed",
            policy_version,
        )
    if completed.returncode:
        return protected(
            "git_diff_error",
            "authoritative PR raw diff inspection failed closed",
            policy_version,
        )
    paths, structural_error = parse_raw_diff(completed.stdout)
    if structural_error:
        reasons = {
            "rename_or_copy": "rename or copy delta requires the signed receipt verifier",
            "mode_change": "file mode change requires the signed receipt verifier",
            "empty_diff": "empty PR delta fails closed",
        }
        return protected(
            structural_error,
            reasons.get(structural_error, "malformed or unsupported raw diff fails closed"),
            policy_version,
        )
    return classify_paths(
        paths,
        policy_version,
        allow_ac_runtime_images=(
            classifier_sha256 in ac_runtime_image_classifier_sha256s
        ),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify an exact AIMS PR lane.")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    decision = classify_git_delta(args.root.resolve(), args.base, args.head)
    print(json.dumps(decision.as_dict(), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
