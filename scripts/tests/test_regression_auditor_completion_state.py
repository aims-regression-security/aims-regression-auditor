from __future__ import annotations

import sys
import unittest
from pathlib import Path


SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import regression_auditor_check as gate


class CompletionStateGuardTests(unittest.TestCase):
    def test_canonical_pending_state_is_allowed_in_descriptive_fields(self) -> None:
        subject = {
            "stateCombinations": [
                "live or data-integrity acceptance remains OPEN_PENDING_LIVE"
            ],
            "evidence": [
                "A real PENDING state is covered by the negative-path test."
            ],
            "status": "PASS",
        }

        self.assertEqual(gate.forbidden_completion_state_paths(subject), [])
        self.assertFalse(gate.has_forbidden_completion_text(subject))
        self.assertFalse(
            gate.has_forbidden_completion_text(
                "If acceptance remains, OPEN_PENDING_LIVE blocks close."
            )
        )

    def test_actual_pending_structured_status_reports_exact_path(self) -> None:
        subject = {
            "acceptanceCriteria": [{"status": "PENDING"}],
            "postFix": {"status": "PASS"},
        }

        self.assertEqual(
            gate.forbidden_completion_state_paths(subject),
            ["$.acceptanceCriteria[0].status"],
        )
        self.assertTrue(gate.has_forbidden_completion_text(subject))

    def test_pending_terminal_enum_is_blocked_only_as_current_state(self) -> None:
        subject = {
            "terminalState": "OPEN_PENDING_LIVE",
            "description": "OPEN_PENDING_LIVE is a safe close-blocking policy.",
        }

        self.assertEqual(
            gate.forbidden_completion_state_paths(subject),
            ["$.terminalState"],
        )


if __name__ == "__main__":
    unittest.main()
