#!/usr/bin/env python3
"""Validate Gate Change Firewall and risk-based quality gate policy.

This harness implements two process controls:

1. Gate Change Firewall
   Product behavior changes and quality-gate changes cannot be mixed in the
   same candidate. Gate-only changes are allowed, but must be explicitly
   declared as Tier 3 gate-change work.

2. Risk-Based Quality Gate
   Behavior changes must carry a machine-readable risk tier manifest so the
   required verification cost is tied to the actual risk of the change.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


POLICY_SCHEMA = "aims.risk_quality_gate.v1"
POLICY_PREFIX = "docs/quality-gates/"
VALID_CHANGE_TYPES = {
    "docs-only",
    "low-risk",
    "standard",
    "regression",
    "gate-change",
    "release-critical",
}
VALID_PROTECTED_MECHANISMS = {
    "regression-auditor",
    "trusted-verifier",
    "signed-receipt",
    "required-check",
}

GATE_EXACT_PATHS = {
    ".github/regression-auditor-trust.json",
    ".github/regression-auditor-external-verifier.yml",
    ".github/regression-auditor-key-attestation.yml",
    ".husky/pre-commit",
    ".husky/pre-push",
    "AGENTS.md",
    "CLAUDE.md",
    "scripts/check_ace_assets_policy.py",
    "scripts/e2e_matrix_check.py",
    "scripts/gate_policy_check.py",
    "scripts/pre_commit_review.py",
    "scripts/pre_push_review.py",
    "scripts/regression_auditor_candidate.py",
    "scripts/regression_auditor_check.py",
    "scripts/regression_auditor_issue.py",
    "scripts/regression_gate_fast_finish.py",
    "scripts/regression_github_state_gate.py",
    "scripts/regression_github_state_marker.py",
    "scripts/regression_live_state_publish.py",
    "scripts/tier0_issue_close.py",
    "scripts/work_gate_check.py",
}
GATE_PREFIXES = (
    ".github/workflows/regression-",
    ".github/regression-auditor-",
    ".agents/skills/github-markdown-guard/",
)
GATE_POLICY_DOCS = {
    "docs/requirements/regression-auditor-agent.md",
    "docs/requirements/regression-quality-gate-operating-report-2026-07-16.md",
}

SUPPORT_PREFIXES = (
    "docs/ace-reports/",
    "docs/e2e-matrices/",
    "docs/plans/",
    "docs/quality-gates/",
    "docs/regression-audits/",
    "docs/regression-evidence/",
    "docs/regression-work/",
    "scripts/tests/",
    "tests/",
)
SUPPORT_EXACT_PATHS = {
    "docs/requirements/requirements-log.md",
}

HIGH_RISK_PREFIXES = (
    "backend/",
    "deploy",
    "infrastructure/",
    "migrations/",
)
HIGH_RISK_KEYWORDS = (
    "auth",
    "permission",
    "security",
    "secret",
    "token",
    "credential",
    "migration",
    "schema",
    "delete",
    "remove",
    "deploy",
    "release",
)

BEHAVIOR_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".cjs",
    ".conf",
    ".css",
    ".html",
    ".ini",
    ".iss",
    ".js",
    ".jsx",
    ".json",
    ".mjs",
    ".ps1",
    ".py",
    ".pyw",
    ".service",
    ".sh",
    ".sql",
    ".timer",
    ".toml",
    ".ts",
    ".tsx",
    ".xml",
    ".yaml",
    ".yml",
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


def staged_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff --cached failed")
    return [normalize(line.strip()) for line in result.stdout.splitlines() if line.strip()]


def git_index_text(root: Path, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f":{normalize(path)}"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def read_text(root: Path, path: str, *, staged: bool) -> str | None:
    if staged:
        return git_index_text(root, path)
    try:
        return (root / normalize(path)).read_text(encoding="utf-8")
    except OSError:
        return None


def read_json(root: Path, path: str, *, staged: bool) -> tuple[dict[str, Any] | None, str | None]:
    raw = read_text(root, path, staged=staged)
    if raw is None:
        return None, f"{path}: 파일을 읽을 수 없습니다."
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"{path}: JSON 파싱 실패: {exc}"
    if not isinstance(value, dict):
        return None, f"{path}: JSON object가 아닙니다."
    return value, None


def is_gate_path(path: str) -> bool:
    normalized = normalize(path)
    return (
        normalized in GATE_EXACT_PATHS
        or normalized in GATE_POLICY_DOCS
        or any(normalized.startswith(prefix) for prefix in GATE_PREFIXES)
    )


def is_support_path(path: str) -> bool:
    normalized = normalize(path)
    return normalized in SUPPORT_EXACT_PATHS or any(
        normalized.startswith(prefix) for prefix in SUPPORT_PREFIXES
    )


def is_behavior_file(path: str) -> bool:
    normalized = normalize(path)
    if is_gate_path(normalized):
        return True
    if normalized.startswith(IGNORED_BEHAVIOR_PREFIXES):
        return False
    return Path(normalized).suffix.lower() in BEHAVIOR_EXTENSIONS


def is_high_risk_path(path: str) -> bool:
    normalized = normalize(path)
    lowered = normalized.lower()
    return any(normalized.startswith(prefix) for prefix in HIGH_RISK_PREFIXES) or any(
        keyword in lowered for keyword in HIGH_RISK_KEYWORDS
    )


def policy_files(files: list[str]) -> list[str]:
    return sorted(
        path
        for path in (normalize(item) for item in files)
        if path.startswith(POLICY_PREFIX) and path.endswith(".json")
    )


def automatic_min_tier(
    *,
    gate_paths: list[str],
    product_paths: list[str],
    behavior_files: list[str],
) -> int:
    if gate_paths:
        return 3
    if any(is_high_risk_path(path) for path in product_paths):
        return 3
    if any(path.startswith("scripts/") or path.startswith(".husky/") for path in behavior_files):
        return 2
    if behavior_files:
        return 1
    return 0


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def object_at(value: dict[str, Any], key: str) -> dict[str, Any]:
    nested = value.get(key)
    return nested if isinstance(nested, dict) else {}


def validate_verification_items(policy_path: str, policy: dict[str, Any], tier: int) -> list[str]:
    errors: list[str] = []
    items = policy.get("verification")
    if tier == 0 and items is None:
        return errors
    if not isinstance(items, list) or not items:
        errors.append(f"{policy_path}: tier {tier}에는 verification 항목이 필요합니다.")
        return errors
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            errors.append(f"{policy_path}: verification[{index}]가 object가 아닙니다.")
            continue
        label = f"{policy_path}: verification[{index}]"
        if str(item.get("status", "")).upper() != "PASS":
            errors.append(f"{label}.status는 PASS여야 합니다.")
        if not str(item.get("command", "")).strip():
            errors.append(f"{label}.command가 필요합니다.")
        if not string_list(item.get("evidence")):
            errors.append(f"{label}.evidence가 필요합니다.")
    return errors


def validate_risk_policy(
    root: Path,
    policy_path: str,
    *,
    policy: dict[str, Any],
    staged: bool,
    behavior_files: list[str],
    gate_paths: list[str],
    product_paths: list[str],
    min_tier: int,
) -> list[str]:
    errors: list[str] = []
    if policy.get("schema") != POLICY_SCHEMA:
        errors.append(f"{policy_path}: schema는 {POLICY_SCHEMA}여야 합니다.")

    tier_value = policy.get("tier")
    if not isinstance(tier_value, int) or tier_value < 0 or tier_value > 3:
        errors.append(f"{policy_path}: tier는 0~3 정수여야 합니다.")
        tier = -1
    else:
        tier = tier_value
        if tier < min_tier:
            errors.append(
                f"{policy_path}: tier {tier}는 자동 산정 최소 tier {min_tier}보다 낮습니다."
            )

    change_type = str(policy.get("changeType", "")).strip()
    if change_type not in VALID_CHANGE_TYPES:
        errors.append(
            f"{policy_path}: changeType은 {', '.join(sorted(VALID_CHANGE_TYPES))} 중 하나여야 합니다."
        )
    if gate_paths and change_type != "gate-change":
        errors.append(f"{policy_path}: gate path 변경은 changeType=gate-change여야 합니다.")

    scope = object_at(policy, "scope")
    covered_files = sorted(normalize(path) for path in string_list(scope.get("changedFiles")))
    missing = sorted(set(behavior_files) - set(covered_files))
    if missing:
        errors.append(
            f"{policy_path}: scope.changedFiles가 behavior 변경을 누락했습니다: "
            + ", ".join(missing)
        )

    firewall = object_at(policy, "gateChangeFirewall")
    if gate_paths:
        if str(firewall.get("classification", "")).strip() != "gate-only":
            errors.append(
                f"{policy_path}: gate 변경은 gateChangeFirewall.classification=gate-only가 필요합니다."
            )
        declared_gate_paths = sorted(normalize(path) for path in string_list(firewall.get("gatePaths")))
        missing_gate = sorted(set(gate_paths) - set(declared_gate_paths))
        if missing_gate:
            errors.append(
                f"{policy_path}: gateChangeFirewall.gatePaths 누락: "
                + ", ".join(missing_gate)
            )
        declared_product_paths = string_list(firewall.get("productPaths"))
        if declared_product_paths:
            errors.append(
                f"{policy_path}: gate-only 변경의 productPaths는 비어 있어야 합니다."
            )

    if tier >= 0:
        errors.extend(validate_verification_items(policy_path, policy, tier))

    if tier >= 2:
        regression_evidence = string_list(policy.get("regressionEvidence"))
        verification_kinds = [
            str(item.get("kind", "")).strip()
            for item in policy.get("verification", [])
            if isinstance(item, dict)
        ]
        has_regression_kind = any("regression" in kind for kind in verification_kinds)
        if not regression_evidence and not has_regression_kind:
            errors.append(
                f"{policy_path}: tier {tier}에는 regressionEvidence 또는 regression verification이 필요합니다."
            )

    if tier == 3:
        protected = object_at(policy, "protectedGate")
        if protected.get("required") is not True:
            errors.append(f"{policy_path}: tier 3에는 protectedGate.required=true가 필요합니다.")
        mechanisms = set(string_list(protected.get("mechanisms")))
        if not mechanisms:
            single = str(protected.get("mechanism", "")).strip()
            mechanisms = {single} if single else set()
        unknown = sorted(mechanisms - VALID_PROTECTED_MECHANISMS)
        if unknown:
            errors.append(
                f"{policy_path}: 알 수 없는 protectedGate mechanism: "
                + ", ".join(unknown)
            )
        if not mechanisms:
            errors.append(f"{policy_path}: tier 3에는 protectedGate mechanism이 필요합니다.")

    # Ensure the policy file can be read from the same source used by the gate.
    if read_text(root, policy_path, staged=staged) is None:
        errors.append(f"{policy_path}: policy 파일을 검증 소스에서 읽을 수 없습니다.")
    return errors


def check_files(
    root: Path,
    files: list[str],
    *,
    staged: bool = False,
) -> tuple[bool, str]:
    normalized_files = sorted({normalize(path) for path in files if normalize(path)})
    if not normalized_files:
        return True, "[GATE POLICY] PASS: no changed files"

    behavior_files = sorted(path for path in normalized_files if is_behavior_file(path))
    gate_paths = sorted(path for path in behavior_files if is_gate_path(path))
    product_paths = sorted(
        path
        for path in behavior_files
        if not is_gate_path(path) and not is_support_path(path)
    )

    if gate_paths and product_paths:
        return (
            False,
            "[GATE POLICY] BLOCK: Gate Change Firewall 위반입니다.\n"
            "  제품 behavior 변경과 gate 변경을 같은 PR/커밋에 섞을 수 없습니다.\n"
            "  Gate paths:\n"
            + "\n".join(f"    - {path}" for path in gate_paths)
            + "\n  Product paths:\n"
            + "\n".join(f"    - {path}" for path in product_paths)
            + "\n  조치: 제품 변경과 gate 변경을 별도 브랜치/PR로 분리하세요.",
        )

    min_tier = automatic_min_tier(
        gate_paths=gate_paths,
        product_paths=product_paths,
        behavior_files=behavior_files,
    )
    manifests = policy_files(normalized_files)
    if not behavior_files:
        return True, "[GATE POLICY] PASS: tier 0 docs-only change"
    if not manifests:
        return (
            False,
            "[GATE POLICY] BLOCK: behavior 변경에는 risk quality gate manifest가 필요합니다.\n"
            f"  최소 tier: {min_tier}\n"
            f"  위치: {POLICY_PREFIX}*.json\n"
            "  조치: 변경 파일, tier, 검증 증거, protected gate 필요 여부를 기록하세요.",
        )
    if len(manifests) != 1:
        return (
            False,
            "[GATE POLICY] BLOCK: 한 커밋/PR에는 정확히 하나의 risk quality gate manifest만 허용합니다.\n"
            + "\n".join(f"  - {path}" for path in manifests),
        )

    policy_path = manifests[0]
    policy, read_error = read_json(root, policy_path, staged=staged)
    if read_error:
        return False, "[GATE POLICY] BLOCK:\n  - " + read_error
    assert policy is not None
    errors = validate_risk_policy(
        root,
        policy_path,
        policy=policy,
        staged=staged,
        behavior_files=behavior_files,
        gate_paths=gate_paths,
        product_paths=product_paths,
        min_tier=min_tier,
    )
    if errors:
        return (
            False,
            "[GATE POLICY] BLOCK:\n" + "\n".join(f"  - {error}" for error in errors),
        )

    tier = policy.get("tier")
    change_type = policy.get("changeType")
    return (
        True,
        f"[GATE POLICY] PASS: tier {tier} / {change_type} "
        f"({len(behavior_files)} behavior files)",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Gate Change Firewall and risk-based quality gate policy."
    )
    parser.add_argument("--root", default=".", help="Repository root.")
    parser.add_argument("--staged", action="store_true", help="Read file list from git index.")
    parser.add_argument("--files", nargs="*", default=None, help="Explicit changed file list.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root).resolve()
    try:
        files = staged_files(root) if args.staged else [normalize(path) for path in (args.files or [])]
        ok, message = check_files(root, files, staged=args.staged)
    except Exception as exc:  # noqa: BLE001 - command-line gate needs a single clear block.
        print(f"[GATE POLICY] BLOCK: {exc}", file=sys.stderr)
        return 2
    print(message, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
