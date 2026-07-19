import json
import tempfile
import unittest
from pathlib import Path

from scripts import gate_policy_check as gate


GATE_PATH = "scripts/solo_agent_quality_gate_policy.py"
AC_TEST_PATH = "tools/auto_clicker_v2/tests/test_pdf_window_guard.py"
AC_PRODUCT_PATH = "tools/auto_clicker_v2/pdf_window_guard.py"


def write_gate_policy(root: Path) -> str:
    policy_path = root / "docs" / "quality-gates" / "issue355.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        json.dumps(
            {
                "schema": gate.POLICY_SCHEMA,
                "tier": 3,
                "changeType": "gate-change",
                "scope": {"changedFiles": [GATE_PATH, AC_TEST_PATH]},
                "verification": [
                    {
                        "id": "V-001",
                        "kind": "regression",
                        "status": "PASS",
                        "command": "python -m unittest discover -s scripts/tests",
                        "evidence": ["focused gate policy self-test"],
                    }
                ],
                "regressionEvidence": ["gate/support/product classification matrix"],
                "gateChangeFirewall": {
                    "classification": "gate-only",
                    "gatePaths": [GATE_PATH],
                    "productPaths": [],
                },
                "protectedGate": {
                    "required": True,
                    "mechanisms": ["trusted-verifier", "signed-receipt"],
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return "docs/quality-gates/issue355.json"


class GatePolicyClassificationTests(unittest.TestCase):
    def test_solo_quality_policy_is_an_exact_gate_path(self) -> None:
        self.assertTrue(gate.is_gate_path(GATE_PATH))

    def test_auto_clicker_tests_are_support_paths(self) -> None:
        self.assertTrue(gate.is_support_path(AC_TEST_PATH))
        self.assertFalse(gate.is_support_path(AC_PRODUCT_PATH))

    def test_gate_can_include_ac_test_support_but_not_ac_product(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = write_gate_policy(root)

            ok, message = gate.check_files(
                root,
                [GATE_PATH, AC_TEST_PATH, policy_path],
            )
            self.assertTrue(ok, message)

            blocked, blocked_message = gate.check_files(
                root,
                [GATE_PATH, AC_PRODUCT_PATH, policy_path],
            )
            self.assertFalse(blocked)
            self.assertIn("Gate Change Firewall", blocked_message)
            self.assertIn(AC_PRODUCT_PATH, blocked_message)


if __name__ == "__main__":
    unittest.main()
