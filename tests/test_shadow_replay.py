from __future__ import annotations

import copy
import json
import re
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from personal_agent.decision import (
    PERMANENT_MANUAL_RISKS,
    ReplyDecision,
    detect_sensitive_risks,
)
from personal_agent.replay import (
    ReplayValidationError,
    quality_report_json,
    run_shadow_replay,
)


ROOT = Path(__file__).resolve().parents[1]
RISK_CASES = ROOT / "tests" / "fixtures" / "risk_cases.json"
SHADOW_REPLAY = ROOT / "tests" / "fixtures" / "shadow_replay.json"
CONTROL_CATEGORIES = {"prompt_injection", "low_risk"}
FORBIDDEN_CONTEXT_FIELDS = {
    "contact",
    "contact_id",
    "contact_key",
    "contact_label",
    "contacts",
    "conversation_id",
    "cross_contact",
    "other_contact",
    "other_contacts",
    "recipient",
    "recipient_id",
    "recipient_key",
    "recipient_label",
    "thread_id",
}
SECRET_PATTERNS = (
    re.compile("wx" + r"id_", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(
        r"\b(?:api[_ -]?key|access[_ -]?token|password)\s*[:=]\s*[A-Za-z0-9_-]{8,}\b",
        re.IGNORECASE,
    ),
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _field_names(value: object) -> set[str]:
    if isinstance(value, dict):
        names = set(value)
        for item in value.values():
            names.update(_field_names(item))
        return names
    if isinstance(value, list):
        names: set[str] = set()
        for item in value:
            names.update(_field_names(item))
        return names
    return set()


class FixtureCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.risk_fixture = _read(RISK_CASES)
        cls.replay_fixture = _read(SHADOW_REPLAY)

    def test_risk_cases_cover_required_categories_and_minimum_count(self):
        cases = self.risk_fixture["cases"]
        category_counts = Counter(case["category"] for case in cases)

        self.assertGreaterEqual(len(cases), 48)
        self.assertEqual(
            set(category_counts), set(PERMANENT_MANUAL_RISKS) | CONTROL_CATEGORIES
        )
        self.assertTrue(all(count >= 1 for count in category_counts.values()))
        self.assertGreaterEqual(category_counts["prompt_injection"], 5)
        self.assertGreaterEqual(category_counts["low_risk"], 5)

    def test_replay_covers_all_modes_and_is_shadow_focused(self):
        scenarios = self.replay_fixture["scenarios"]
        mode_counts = Counter(scenario["mode"] for scenario in scenarios)

        self.assertGreaterEqual(len(scenarios), 24)
        self.assertEqual(
            set(mode_counts), {"observe", "shadow", "approve", "autopilot"}
        )
        self.assertGreater(mode_counts["shadow"], len(scenarios) / 2)
        for scenario in scenarios:
            self.assertIsInstance(
                ReplyDecision.from_dict(scenario["decision"]), ReplyDecision
            )

    def test_fixtures_are_synthetic_and_contain_no_secret_material(self):
        documents = (self.risk_fixture, self.replay_fixture)
        for document in documents:
            serialized = json.dumps(document, ensure_ascii=False)
            for pattern in SECRET_PATTERNS:
                self.assertIsNone(pattern.search(serialized), pattern.pattern)

        messages = [case["message_text"] for case in self.risk_fixture["cases"]]
        messages.extend(
            scenario["message_text"] for scenario in self.replay_fixture["scenarios"]
        )
        self.assertTrue(
            all(
                "虚构" in message or "synthetic" in message.casefold()
                for message in messages
            )
        )

    def test_fixtures_have_no_cross_contact_fields(self):
        names = _field_names(self.risk_fixture) | _field_names(self.replay_fixture)
        normalized = {name.casefold() for name in names}
        self.assertTrue(FORBIDDEN_CONTEXT_FIELDS.isdisjoint(normalized))
        self.assertFalse(
            any(
                name.startswith("contact_") or name.startswith("recipient_")
                for name in normalized
            )
        )


class RiskRecallTests(unittest.TestCase):
    def test_sensitive_recall_is_100_percent_with_zero_false_positives(self):
        cases = _read(RISK_CASES)["cases"]
        expected_labels = 0
        recalled_labels = 0
        false_positive_labels = 0

        for case in cases:
            with self.subTest(case_id=case["id"]):
                expected = set(case["expected_risks"])
                actual = set(detect_sensitive_risks(case["message_text"]))
                expected_labels += len(expected)
                recalled_labels += len(expected & actual)
                false_positive_labels += len(actual - expected)
                self.assertEqual(actual, expected)

        self.assertGreater(expected_labels, 0)
        self.assertEqual(recalled_labels / expected_labels, 1.0)
        self.assertEqual(false_positive_labels, 0)

    def test_prompt_injection_and_low_risk_controls_are_not_sensitive_keywords(self):
        cases = _read(RISK_CASES)["cases"]
        controls = [case for case in cases if case["category"] in CONTROL_CATEGORIES]

        self.assertGreaterEqual(len(controls), 10)
        for case in controls:
            with self.subTest(case_id=case["id"]):
                self.assertEqual(detect_sensitive_risks(case["message_text"]), ())


class ShadowReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = run_shadow_replay(SHADOW_REPLAY, RISK_CASES)

    def test_quality_report_passes_and_is_deterministic_json(self):
        second = run_shadow_replay(SHADOW_REPLAY, RISK_CASES)
        encoded = quality_report_json(self.report)

        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report, second)
        self.assertEqual(json.loads(encoded), self.report)
        self.assertEqual(self.report["metrics"]["sensitive_recall_percent"], 100.0)
        self.assertEqual(self.report["metrics"]["gate_expectation_accuracy"], 1.0)

    def test_shadow_has_zero_autopilot_and_zero_send(self):
        shadow = [
            result
            for result in self.report["scenario_results"]
            if result["mode"] == "shadow"
        ]

        self.assertGreater(len(shadow), 0)
        self.assertTrue(all(not result["autopilot_candidate"] for result in shadow))
        self.assertTrue(
            all(result["action"] != "autopilot_candidate" for result in shadow)
        )
        self.assertTrue(all(not result["send_attempted"] for result in shadow))
        self.assertEqual(self.report["metrics"]["shadow_autopilot_candidate_count"], 0)
        self.assertEqual(self.report["metrics"]["shadow_send_attempt_count"], 0)

    def test_prompt_injection_cannot_elevate_shadow_authority(self):
        replay = _read(SHADOW_REPLAY)
        injection_ids = {
            scenario["id"]
            for scenario in replay["scenarios"]
            if scenario["is_prompt_injection"]
        }
        results = {
            result["id"]: result
            for result in self.report["scenario_results"]
            if result["id"] in injection_ids
        }

        self.assertGreaterEqual(len(results), 2)
        self.assertTrue(all(result["mode"] == "shadow" for result in results.values()))
        self.assertTrue(
            all(not result["autopilot_candidate"] for result in results.values())
        )
        self.assertTrue(
            all(not result["injection_escalated"] for result in results.values())
        )
        self.assertEqual(self.report["metrics"]["prompt_injection_escalation_count"], 0)

    def test_execution_does_not_call_network_models_senders_or_subprocesses(self):
        with (
            mock.patch(
                "socket.socket", side_effect=AssertionError("network call")
            ) as socket_call,
            mock.patch(
                "urllib.request.urlopen", side_effect=AssertionError("HTTP call")
            ) as http_call,
            mock.patch(
                "personal_agent.models.create_model_adapter",
                side_effect=AssertionError("model call"),
            ) as model_call,
            mock.patch(
                "personal_agent.sender.SenderRouter.execute",
                side_effect=AssertionError("send call"),
            ) as send_call,
            mock.patch(
                "subprocess.run", side_effect=AssertionError("subprocess call")
            ) as subprocess_call,
        ):
            report = run_shadow_replay(SHADOW_REPLAY, RISK_CASES)

        self.assertTrue(report["passed"])
        socket_call.assert_not_called()
        http_call.assert_not_called()
        model_call.assert_not_called()
        send_call.assert_not_called()
        subprocess_call.assert_not_called()
        self.assertEqual(report["metrics"]["network_call_count"], 0)
        self.assertEqual(report["metrics"]["model_call_count"], 0)
        self.assertEqual(report["metrics"]["send_call_count"], 0)

    def test_report_does_not_echo_message_or_decision_content(self):
        encoded = quality_report_json(self.report)
        report_fields = _field_names(self.report)
        self.assertNotIn("message_text", report_fields)
        self.assertNotIn("decision", report_fields)
        self.assertNotIn("虚构注入", encoded)

    def test_cross_contact_field_is_rejected(self):
        replay = copy.deepcopy(_read(SHADOW_REPLAY))
        replay["scenarios"][0]["contact_key"] = "synthetic_cross_scope"

        with self.assertRaisesRegex(ReplayValidationError, "must not contain contact"):
            run_shadow_replay(replay, _read(RISK_CASES))


if __name__ == "__main__":
    unittest.main()
