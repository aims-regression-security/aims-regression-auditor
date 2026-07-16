#!/usr/bin/env python3
"""Select the signed audit-bundle base used by the external verifier."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


RECEIPT_PREFIX = "docs/regression-audits/auditor-receipts/"
RECEIPT_SCHEMA = "aims.regression_auditor_receipt.v1"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class BaseSelectionError(RuntimeError):
    """Raised when a candidate cannot safely select an audit base."""


def run_git(root: Path, arguments: list[str], *, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=not binary,
        encoding=None if binary else "utf-8",
        errors=None if binary else "replace",
        check=False,
    )
    if result.returncode != 0:
        stderr = (
            result.stderr.decode("utf-8", errors="replace")
            if binary
            else result.stderr
        )
        raise BaseSelectionError(stderr.strip() or "git command failed")
    return result.stdout


def require_commit(root: Path, sha: str, label: str) -> None:
    if not SHA_PATTERN.fullmatch(sha):
        raise BaseSelectionError(f"{label} is not a lowercase 40-character SHA")
    run_git(root, ["cat-file", "-e", f"{sha}^{{commit}}"])


def changed_receipt_paths(root: Path, base_sha: str, head_sha: str) -> list[str]:
    raw = run_git(
        root,
        [
            "diff",
            "--diff-filter=ACMR",
            "--name-only",
            "-z",
            f"{base_sha}...{head_sha}",
        ],
        binary=True,
    )
    assert isinstance(raw, bytes)
    paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    return sorted(
        path
        for path in paths
        if path.startswith(RECEIPT_PREFIX) and path.endswith(".json")
    )


def receipt_base(root: Path, receipt_path: str) -> str:
    path = root / Path(receipt_path)
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaseSelectionError(f"invalid signed receipt {receipt_path}: {exc}") from exc

    if not isinstance(receipt, dict):
        raise BaseSelectionError(f"signed receipt is not a JSON object: {receipt_path}")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise BaseSelectionError(f"unexpected signed receipt schema: {receipt_path}")
    audit_bundle = receipt.get("auditBundle")
    if not isinstance(audit_bundle, dict):
        raise BaseSelectionError(f"signed receipt has no auditBundle: {receipt_path}")
    base_sha = audit_bundle.get("baseCommitSha")
    if not isinstance(base_sha, str) or not SHA_PATTERN.fullmatch(base_sha):
        raise BaseSelectionError(
            f"signed receipt has an invalid auditBundle.baseCommitSha: {receipt_path}"
        )
    return base_sha


def select_effective_base(root: Path, authoritative_base: str, head_sha: str) -> str:
    require_commit(root, authoritative_base, "authoritative PR base")
    require_commit(root, head_sha, "authoritative PR head")

    receipt_paths = changed_receipt_paths(root, authoritative_base, head_sha)
    if not receipt_paths:
        return authoritative_base

    receipt_bases = {receipt_base(root, path) for path in receipt_paths}
    if len(receipt_bases) != 1:
        raise BaseSelectionError(
            "changed signed receipts do not bind one unambiguous audit base"
        )
    selected_base = receipt_bases.pop()
    require_commit(root, selected_base, "signed receipt audit base")

    ancestry = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "merge-base",
            "--is-ancestor",
            selected_base,
            authoritative_base,
        ],
        capture_output=True,
        check=False,
    )
    if ancestry.returncode != 0:
        raise BaseSelectionError(
            "signed receipt audit base is not an ancestor of the authoritative PR base"
        )
    return selected_base


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--authoritative-base", required=True)
    parser.add_argument("--head", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        selected = select_effective_base(
            args.root.resolve(),
            args.authoritative_base,
            args.head,
        )
    except BaseSelectionError as exc:
        print(f"[AUDIT BASE BLOCK] {exc}", file=sys.stderr)
        return 2
    print(selected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
