from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.solo_v2_pr_lane import (
    AC_RUNTIME_IMAGE_CLASSIFIER_SHA256S,
    CLASSIFIER_PATH,
    EXPECTED_CANDIDATE_CLASSIFIER_SHA256S,
    POLICY_POINTER_PATH,
    classify_git_delta,
    classify_paths,
    is_expected_classifier_sha256,
    parse_raw_diff,
)


ZERO_SHA = "0" * 40
OLD_SHA = "1" * 40
NEW_SHA = "2" * 40


def raw_record(
    status: str,
    path: str,
    *,
    old_mode: str = "100644",
    new_mode: str = "100644",
    second_path: str | None = None,
) -> bytes:
    old_sha, new_sha = OLD_SHA, NEW_SHA
    if status == "A":
        old_mode, old_sha = "000000", ZERO_SHA
    elif status == "D":
        new_mode, new_sha = "000000", ZERO_SHA
    header = f":{old_mode} {new_mode} {old_sha} {new_sha} {status}".encode("ascii")
    tokens = [header, path.encode("utf-8")]
    if second_path is not None:
        tokens.append(second_path.encode("utf-8"))
    return b"\0".join(tokens) + b"\0"


class RawDiffTests(unittest.TestCase):
    def test_ordinary_add_modify_delete_are_parsed(self) -> None:
        raw = b"".join(
            (
                raw_record("A", "docs/new.md"),
                raw_record("M", "src/app.ts"),
                raw_record("D", "src/old.ts"),
            )
        )
        paths, error = parse_raw_diff(raw)
        self.assertIsNone(error)
        self.assertEqual(paths, ["docs/new.md", "src/app.ts", "src/old.ts"])

    def test_rename_is_protected(self) -> None:
        paths, error = parse_raw_diff(
            raw_record("R100", "docs/old.md", second_path="docs/new.md")
        )
        self.assertEqual(paths, [])
        self.assertEqual(error, "rename_or_copy")

    def test_mode_change_is_protected(self) -> None:
        paths, error = parse_raw_diff(
            raw_record("M", "scripts/run.py", old_mode="100644", new_mode="100755")
        )
        self.assertEqual(paths, [])
        self.assertEqual(error, "mode_change")

    def test_malformed_diff_is_protected(self) -> None:
        paths, error = parse_raw_diff(b"not-a-header\0docs/a.md\0")
        self.assertEqual(paths, [])
        self.assertEqual(error, "malformed_raw_diff")


class SnapshotClassificationTests(unittest.TestCase):
    def test_current_and_transition_classifier_snapshots_are_accepted(self) -> None:
        current = "2aa1ba6698eb78d7e43cc509ef802b2b8a268e2675dd0d41565762a4de80c088"
        transition = "6689e7ef95a95c4e777dec3c304c34c4000bd26e28456eb9ef9d329399152a95"
        issue384 = "2ff30f54ebb235b59a373925d8dbf5314cdb3675cdaf36fe8069074d80ef4dda"
        self.assertEqual(
            EXPECTED_CANDIDATE_CLASSIFIER_SHA256S,
            {current, transition, issue384},
        )
        self.assertTrue(is_expected_classifier_sha256(current))
        self.assertTrue(is_expected_classifier_sha256(transition))
        self.assertTrue(is_expected_classifier_sha256(issue384))

    def test_unknown_classifier_snapshot_fails_closed(self) -> None:
        self.assertFalse(is_expected_classifier_sha256("f" * 64))

    def test_direct_document_lane_skips_protected_verifier(self) -> None:
        decision = classify_paths(["docs/guide.md"], "solo-v2")
        self.assertEqual(decision.lane, "direct")
        self.assertFalse(decision.requires_protected_verifier)

    def test_core_code_and_runtime_version_skip_protected_verifier(self) -> None:
        decision = classify_paths(
            ["backend/api/aims_api/routes/ac-routes.js", "backend/api/aims_api/version"],
            "solo-v2",
        )
        self.assertEqual(decision.lane, "core")
        self.assertFalse(decision.requires_protected_verifier)

    def test_gate_path_uses_protected_verifier(self) -> None:
        decision = classify_paths(["scripts/pre_push_review.py"], "solo-v2")
        self.assertEqual(decision.lane, "protected")
        self.assertEqual(decision.reason_code, "protected_path")

    def test_gate_helper_name_uses_protected_verifier(self) -> None:
        decision = classify_paths(["scripts/custom_verify_helper.py"], "solo-v2")
        self.assertEqual(decision.lane, "protected")

    def test_evidence_asset_is_core_not_unknown(self) -> None:
        decision = classify_paths(
            ["docs/ace-reports/assets/issue372-lane/2026-07-20/check.png"],
            "solo-v2",
        )
        self.assertEqual(decision.lane, "core")

    def test_ac_runtime_png_assets_are_core(self) -> None:
        for path in (
            "tools/auto_clicker_v2/img/alert.png",
            "tools/auto_clicker_v2/img/dialogs/error/retry.png",
            "tools/auto_clicker_v2/img/security/remove-login-button.png",
        ):
            with self.subTest(path=path):
                decision = classify_paths(
                    [path],
                    "solo-v2",
                    allow_ac_runtime_images=True,
                )
                self.assertEqual(decision.lane, "core")
                self.assertFalse(decision.requires_protected_verifier)

    def test_ac_runtime_image_allowlist_rejects_lookalikes_and_non_pngs(self) -> None:
        for path in (
            "tools/auto_clicker_v2/img/../payload.png",
            "tools/auto_clicker_v2/img/dialogs/../../payload.png",
            "tools/auto_clicker_v2/img/./payload.png",
            "tools/auto_clicker_v2/img//payload.png",
            "tools/auto_clicker_v2/img_evil/payload.png",
            "tools/auto_clicker_v2/img.png/payload.png",
            "tools/auto_clicker_v2/img/payload.jpg",
            "tools/auto_clicker_v2/img/payload.png.jpg",
            "tools/auto_clicker_v2/img/payload.txt",
            "tools/auto_clicker_v2/icons/payload.png",
            "screenshots/payload.png",
        ):
            with self.subTest(path=path):
                decision = classify_paths([path], "solo-v2")
                self.assertEqual(decision.lane, "protected")
                self.assertTrue(decision.requires_protected_verifier)

    def test_dependency_manifest_uses_protected_verifier(self) -> None:
        decision = classify_paths(["package-lock.json"], "solo-v2")
        self.assertEqual(decision.lane, "protected")

    def test_unknown_path_fails_closed(self) -> None:
        decision = classify_paths(["artifacts/data.bin"], "solo-v2")
        self.assertEqual(decision.lane, "protected")
        self.assertEqual(decision.reason_code, "unknown_path")

    def test_legacy_pointer_uses_protected_verifier(self) -> None:
        decision = classify_paths(["src/app.ts"], "legacy-v1")
        self.assertEqual(decision.lane, "protected")
        self.assertEqual(decision.reason_code, "legacy_policy")

    def test_invalid_pointer_fails_closed(self) -> None:
        decision = classify_paths(["src/app.ts"], "unexpected-v3")
        self.assertEqual(decision.lane, "protected")
        self.assertEqual(decision.reason_code, "invalid_policy_pointer")

    def test_pointer_change_uses_protected_verifier(self) -> None:
        decision = classify_paths([POLICY_POINTER_PATH], "solo-v2")
        self.assertEqual(decision.lane, "protected")
        self.assertEqual(decision.reason_code, "policy_pointer_change")

    def test_classifier_self_change_uses_protected_verifier(self) -> None:
        decision = classify_paths([CLASSIFIER_PATH], "solo-v2")
        self.assertEqual(decision.lane, "protected")
        self.assertEqual(decision.reason_code, "classifier_self_change")


class WorkflowAttestationContractTests(unittest.TestCase):
    def test_lightweight_lane_requires_exact_pr_author_dispatch(self) -> None:
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/regression-auditor-verify.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('EVENT_NAME: ${{ github.event_name }}', workflow)
        self.assertIn('DISPATCH_ACTOR_ID: ${{ github.actor_id }}', workflow)
        self.assertIn('echo "skip_check=true"', workflow)
        self.assertIn("steps.verify.outputs.skip_check != 'true'", workflow)
        self.assertIn('[[ "$EVENT_NAME" != "workflow_dispatch" ]]', workflow)
        self.assertIn('[[ "$MANUAL_PR_NUMBER" != "$PR_NUMBER" ]]', workflow)
        self.assertIn('[[ "$DISPATCH_ACTOR_ID" != "$IMPLEMENTATION_USER_ID" ]]', workflow)
        self.assertIn("protected receipt and product-test rerun skipped", workflow)


class GitDeltaIntegrationTests(unittest.TestCase):
    def git(self, root: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        return completed.stdout.strip()

    def write(self, root: Path, path: str, text: str) -> None:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def classify(self, root: Path, base: str, head: str):
        pointer = subprocess.run(
            ["git", "-C", str(root), "show", f"{head}:{POLICY_POINTER_PATH}"],
            capture_output=True,
            check=True,
        ).stdout
        classifier = subprocess.run(
            ["git", "-C", str(root), "show", f"{head}:{CLASSIFIER_PATH}"],
            capture_output=True,
            check=True,
        ).stdout
        return classify_git_delta(
            root,
            base,
            head,
            expected_pointer_sha256=hashlib.sha256(pointer).hexdigest(),
            expected_classifier_sha256s={hashlib.sha256(classifier).hexdigest()},
        )

    def classify_runtime_image_candidate(
        self,
        classifier_text: str,
        *,
        grant_runtime_image_capability: bool,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.email", "test@example.invalid")
            self.git(root, "config", "user.name", "Verifier Test")
            self.write(
                root,
                POLICY_POINTER_PATH,
                json.dumps({"activePolicyVersion": "solo-v2"}),
            )
            self.write(root, CLASSIFIER_PATH, classifier_text)
            self.write(root, "src/app.ts", "export const value = 1;\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            self.write(
                root,
                "tools/auto_clicker_v2/img/security/remove-login-button.png",
                "synthetic image bytes",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "runtime image")
            head = self.git(root, "rev-parse", "HEAD")
            pointer = subprocess.run(
                ["git", "-C", str(root), "show", f"{head}:{POLICY_POINTER_PATH}"],
                capture_output=True,
                check=True,
            ).stdout
            classifier = subprocess.run(
                ["git", "-C", str(root), "show", f"{head}:{CLASSIFIER_PATH}"],
                capture_output=True,
                check=True,
            ).stdout
            classifier_sha256 = hashlib.sha256(classifier).hexdigest()
            return classify_git_delta(
                root,
                base,
                head,
                expected_pointer_sha256=hashlib.sha256(pointer).hexdigest(),
                expected_classifier_sha256s={classifier_sha256},
                ac_runtime_image_classifier_sha256s=(
                    {classifier_sha256} if grant_runtime_image_capability else set()
                ),
            )

    def write_snapshot(self, root: Path) -> None:
        self.write(
            root,
            POLICY_POINTER_PATH,
            json.dumps({"activePolicyVersion": "solo-v2"}),
        )
        self.write(root, CLASSIFIER_PATH, "# protected classifier snapshot\n")

    def test_exact_git_delta_reads_head_pointer_and_classifies_core(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.email", "test@example.invalid")
            self.git(root, "config", "user.name", "Verifier Test")
            self.write_snapshot(root)
            self.write(root, "src/app.ts", "export const value = 1;\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            self.write(root, "src/app.ts", "export const value = 2;\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "core")
            head = self.git(root, "rev-parse", "HEAD")

            decision = self.classify(root, base, head)

            self.assertEqual(decision.lane, "core")
            self.assertEqual(decision.reason_code, "core_behavior")

    def test_runtime_png_capability_is_bound_to_classifier_snapshot(self) -> None:
        old_decision = self.classify_runtime_image_candidate(
            "# classifier before issue 384\n",
            grant_runtime_image_capability=False,
        )
        new_decision = self.classify_runtime_image_candidate(
            "# classifier after issue 384\n",
            grant_runtime_image_capability=True,
        )

        self.assertEqual(old_decision.lane, "protected")
        self.assertTrue(old_decision.requires_protected_verifier)
        self.assertEqual(new_decision.lane, "core")
        self.assertFalse(new_decision.requires_protected_verifier)

    def test_runtime_png_capability_set_contains_only_issue384_snapshot(self) -> None:
        self.assertEqual(
            AC_RUNTIME_IMAGE_CLASSIFIER_SHA256S,
            {
                "2ff30f54ebb235b59a373925d8dbf5314cdb3675cdaf36fe8069074d80ef4dda"
            },
        )

    def test_exact_git_rename_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.email", "test@example.invalid")
            self.git(root, "config", "user.name", "Verifier Test")
            self.write_snapshot(root)
            self.write(root, "docs/old.md", "same content\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            self.git(root, "mv", "docs/old.md", "docs/new.md")
            self.git(root, "commit", "-m", "rename")
            head = self.git(root, "rev-parse", "HEAD")

            decision = self.classify(root, base, head)

            self.assertEqual(decision.lane, "protected")
            self.assertEqual(decision.reason_code, "rename_or_copy")

    def test_unsynchronised_classifier_snapshot_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.email", "test@example.invalid")
            self.git(root, "config", "user.name", "Verifier Test")
            self.write_snapshot(root)
            self.write(root, "src/app.ts", "export const value = 1;\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base = self.git(root, "rev-parse", "HEAD")
            self.write(root, "src/app.ts", "export const value = 2;\n")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "core")
            head = self.git(root, "rev-parse", "HEAD")

            decision = classify_git_delta(root, base, head)

            self.assertEqual(decision.lane, "protected")
            self.assertEqual(decision.reason_code, "policy_pointer_snapshot_mismatch")


if __name__ == "__main__":
    unittest.main()
