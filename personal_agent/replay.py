"""Deterministic, offline-only shadow replay for structured reply decisions."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .decision import (
    GATE_ACTIONS,
    GATE_MODES,
    PERMANENT_MANUAL_RISKS,
    ReplyDecision,
    detect_sensitive_risks,
    evaluate_gate,
)


RISK_CASES_SCHEMA = "ginger_risk_cases_v1"
SHADOW_REPLAY_SCHEMA = "ginger_shadow_replay_v1"
SHADOW_REPORT_SCHEMA = "ginger_shadow_replay_report_v1"
MODE_ORDER = ("observe", "shadow", "approve", "autopilot")
RISK_CONTROL_CATEGORIES = frozenset({"prompt_injection", "low_risk"})

_FORBIDDEN_CONTEXT_FIELDS = frozenset(
    {
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
)


class ReplayValidationError(ValueError):
    """Raised when a replay fixture is malformed or crosses isolation bounds."""


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], location: str
) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    details = []
    if missing:
        details.append(f"missing={missing}")
    if extra:
        details.append(f"extra={extra}")
    raise ReplayValidationError(
        f"{location} fields do not match schema: {', '.join(details)}"
    )


def _require_text(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReplayValidationError(f"{location} must be a non-empty string")
    return value.strip()


def _require_bool(value: Any, location: str) -> bool:
    if type(value) is not bool:
        raise ReplayValidationError(f"{location} must be a boolean")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReplayValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_fixture(source: Mapping[str, Any] | str | Path) -> Mapping[str, Any]:
    """Load one local JSON object; URLs and provider-backed inputs are unsupported."""
    if isinstance(source, Mapping):
        return source
    if not isinstance(source, (str, Path)):
        raise TypeError("fixture source must be a mapping or local path")
    path = Path(source)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReplayValidationError(f"cannot load local fixture: {path}") from exc
    if not isinstance(value, Mapping):
        raise ReplayValidationError("fixture root must be a JSON object")
    return value


def _is_forbidden_context_field(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    normalized = key.casefold()
    return (
        normalized in _FORBIDDEN_CONTEXT_FIELDS
        or normalized.startswith("contact_")
        or normalized.startswith("recipient_")
    )


def _count_forbidden_context_fields(value: Any) -> int:
    if isinstance(value, Mapping):
        return sum(
            int(_is_forbidden_context_field(key))
            + _count_forbidden_context_fields(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return sum(_count_forbidden_context_fields(item) for item in value)
    return 0


def _validate_risk_cases(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    _require_exact_keys(document, {"schema", "description", "cases"}, "risk fixture")
    if document["schema"] != RISK_CASES_SCHEMA:
        raise ReplayValidationError(f"risk fixture schema must be {RISK_CASES_SCHEMA}")
    _require_text(document["description"], "risk fixture description")
    raw_cases = document["cases"]
    if not isinstance(raw_cases, list):
        raise ReplayValidationError("risk fixture cases must be an array")

    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    allowed_categories = PERMANENT_MANUAL_RISKS | RISK_CONTROL_CATEGORIES
    for index, raw_case in enumerate(raw_cases):
        location = f"risk fixture cases[{index}]"
        if not isinstance(raw_case, Mapping):
            raise ReplayValidationError(f"{location} must be an object")
        _require_exact_keys(
            raw_case,
            {
                "id",
                "category",
                "message_text",
                "expected_risks",
                "is_prompt_injection",
            },
            location,
        )
        case_id = _require_text(raw_case["id"], f"{location}.id")
        if case_id in identifiers:
            raise ReplayValidationError(f"duplicate risk case id: {case_id}")
        identifiers.add(case_id)
        category = _require_text(raw_case["category"], f"{location}.category")
        if category not in allowed_categories:
            raise ReplayValidationError(f"unsupported risk category: {category}")
        message_text = _require_text(
            raw_case["message_text"], f"{location}.message_text"
        )
        raw_expected = raw_case["expected_risks"]
        if not isinstance(raw_expected, list) or any(
            not isinstance(item, str) or item not in PERMANENT_MANUAL_RISKS
            for item in raw_expected
        ):
            raise ReplayValidationError(
                f"{location}.expected_risks must contain permanent-manual risks"
            )
        expected_risks = tuple(raw_expected)
        if len(expected_risks) != len(set(expected_risks)):
            raise ReplayValidationError(
                f"{location}.expected_risks contains duplicates"
            )
        is_injection = _require_bool(
            raw_case["is_prompt_injection"], f"{location}.is_prompt_injection"
        )
        if category in PERMANENT_MANUAL_RISKS and category not in expected_risks:
            raise ReplayValidationError(
                f"{location} must expect its permanent-manual category"
            )
        if category == "prompt_injection" and not is_injection:
            raise ReplayValidationError(
                f"{location} must be marked as prompt injection"
            )
        if category != "prompt_injection" and is_injection:
            raise ReplayValidationError(
                f"{location} has an inconsistent injection marker"
            )
        if category in RISK_CONTROL_CATEGORIES and expected_risks:
            raise ReplayValidationError(f"{location} control case must expect no risks")
        result.append(
            {
                "id": case_id,
                "category": category,
                "message_text": message_text,
                "expected_risks": expected_risks,
                "is_prompt_injection": is_injection,
            }
        )
    return result


def _validate_gate_inputs(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReplayValidationError(f"{location} must be an object")
    _require_exact_keys(
        value,
        {"allowlisted", "cost_allowed", "frequency_allowed", "emotion"},
        location,
    )
    emotion = value["emotion"]
    if emotion is not None and not isinstance(emotion, Mapping):
        raise ReplayValidationError(f"{location}.emotion must be an object or null")
    return {
        "allowlisted": _require_bool(value["allowlisted"], f"{location}.allowlisted"),
        "cost_allowed": _require_bool(
            value["cost_allowed"], f"{location}.cost_allowed"
        ),
        "frequency_allowed": _require_bool(
            value["frequency_allowed"], f"{location}.frequency_allowed"
        ),
        "emotion": emotion,
    }


def _validate_expected(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReplayValidationError(f"{location} must be an object")
    _require_exact_keys(
        value,
        {"action", "autopilot_candidate", "manual_required", "detected_risks"},
        location,
    )
    action = _require_text(value["action"], f"{location}.action")
    if action not in GATE_ACTIONS:
        raise ReplayValidationError(f"unsupported expected gate action: {action}")
    raw_risks = value["detected_risks"]
    if not isinstance(raw_risks, list) or any(
        not isinstance(item, str) or item not in PERMANENT_MANUAL_RISKS
        for item in raw_risks
    ):
        raise ReplayValidationError(
            f"{location}.detected_risks must contain permanent-manual risks"
        )
    detected_risks = tuple(raw_risks)
    if detected_risks != tuple(sorted(set(detected_risks))):
        raise ReplayValidationError(
            f"{location}.detected_risks must be sorted and unique"
        )
    return {
        "action": action,
        "autopilot_candidate": _require_bool(
            value["autopilot_candidate"], f"{location}.autopilot_candidate"
        ),
        "manual_required": _require_bool(
            value["manual_required"], f"{location}.manual_required"
        ),
        "detected_risks": detected_risks,
    }


def _validate_scenarios(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    _require_exact_keys(
        document, {"schema", "description", "focus_mode", "scenarios"}, "replay fixture"
    )
    if document["schema"] != SHADOW_REPLAY_SCHEMA:
        raise ReplayValidationError(
            f"replay fixture schema must be {SHADOW_REPLAY_SCHEMA}"
        )
    _require_text(document["description"], "replay fixture description")
    if document["focus_mode"] != "shadow":
        raise ReplayValidationError("replay fixture focus_mode must be shadow")
    raw_scenarios = document["scenarios"]
    if not isinstance(raw_scenarios, list):
        raise ReplayValidationError("replay fixture scenarios must be an array")

    result: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for index, raw_scenario in enumerate(raw_scenarios):
        location = f"replay fixture scenarios[{index}]"
        if not isinstance(raw_scenario, Mapping):
            raise ReplayValidationError(f"{location} must be an object")
        _require_exact_keys(
            raw_scenario,
            {
                "id",
                "mode",
                "message_text",
                "decision",
                "gate",
                "expected",
                "is_prompt_injection",
            },
            location,
        )
        scenario_id = _require_text(raw_scenario["id"], f"{location}.id")
        if scenario_id in identifiers:
            raise ReplayValidationError(f"duplicate replay scenario id: {scenario_id}")
        identifiers.add(scenario_id)
        mode = _require_text(raw_scenario["mode"], f"{location}.mode")
        if mode not in GATE_MODES:
            raise ReplayValidationError(f"unsupported replay mode: {mode}")
        message_text = _require_text(
            raw_scenario["message_text"], f"{location}.message_text"
        )
        if not isinstance(raw_scenario["decision"], Mapping):
            raise ReplayValidationError(f"{location}.decision must be an object")
        try:
            decision = ReplyDecision.from_dict(raw_scenario["decision"])
        except (TypeError, ValueError) as exc:
            raise ReplayValidationError(
                f"{location}.decision is not a valid ReplyDecision"
            ) from exc
        result.append(
            {
                "id": scenario_id,
                "mode": mode,
                "message_text": message_text,
                "decision": decision,
                "gate": _validate_gate_inputs(raw_scenario["gate"], f"{location}.gate"),
                "expected": _validate_expected(
                    raw_scenario["expected"], f"{location}.expected"
                ),
                "is_prompt_injection": _require_bool(
                    raw_scenario["is_prompt_injection"],
                    f"{location}.is_prompt_injection",
                ),
            }
        )
    return result


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 1.0


def run_shadow_replay(
    replay_fixture: Mapping[str, Any] | str | Path,
    risk_cases_fixture: Mapping[str, Any] | str | Path,
) -> dict[str, Any]:
    """Replay structured decisions and return deterministic JSON-compatible metrics.

    This execution path reads local JSON, constructs ``ReplyDecision`` instances,
    and calls only ``detect_sensitive_risks`` and ``evaluate_gate``. It has no
    sender, network, subprocess, credential, or model adapter capability.
    """
    replay_document = load_fixture(replay_fixture)
    risk_document = load_fixture(risk_cases_fixture)
    forbidden_fields = _count_forbidden_context_fields(replay_document)
    forbidden_fields += _count_forbidden_context_fields(risk_document)
    if forbidden_fields:
        raise ReplayValidationError(
            "fixtures must not contain contact, recipient, conversation, or thread fields"
        )

    risk_cases = _validate_risk_cases(risk_document)
    scenarios = _validate_scenarios(replay_document)

    expected_labels = 0
    recalled_labels = 0
    false_positive_labels = 0
    risk_exact_matches = 0
    risk_category_counts: Counter[str] = Counter()
    for case in risk_cases:
        actual = set(detect_sensitive_risks(case["message_text"]))
        expected = set(case["expected_risks"])
        expected_labels += len(expected)
        recalled_labels += len(actual & expected)
        false_positive_labels += len(actual - expected)
        risk_exact_matches += int(actual == expected)
        risk_category_counts[case["category"]] += 1

    mode_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    scenario_results: list[dict[str, Any]] = []
    expectation_matches = 0
    injection_escalations = 0
    for scenario in scenarios:
        result = evaluate_gate(
            scenario["decision"],
            message_text=scenario["message_text"],
            mode=scenario["mode"],
            **scenario["gate"],
        )
        expected = scenario["expected"]
        expectation_met = (
            result.action == expected["action"]
            and result.autopilot_candidate == expected["autopilot_candidate"]
            and result.manual_required == expected["manual_required"]
            and result.detected_risks == expected["detected_risks"]
        )
        expectation_matches += int(expectation_met)
        mode_counts[result.mode] += 1
        action_counts[result.action] += 1

        injection_escalated = False
        if scenario["is_prompt_injection"]:
            baseline = evaluate_gate(
                scenario["decision"],
                message_text="",
                mode=scenario["mode"],
                **scenario["gate"],
            )
            injection_escalated = result.mode != scenario["mode"] or (
                result.autopilot_candidate and not baseline.autopilot_candidate
            )
            injection_escalations += int(injection_escalated)

        scenario_results.append(
            {
                "id": scenario["id"],
                "mode": result.mode,
                "action": result.action,
                "autopilot_candidate": result.autopilot_candidate,
                "manual_required": result.manual_required,
                "detected_risks": list(result.detected_risks),
                "send_attempted": False,
                "injection_escalated": injection_escalated,
                "expectation_met": expectation_met,
            }
        )

    shadow_results = [item for item in scenario_results if item["mode"] == "shadow"]
    shadow_autopilot_count = sum(
        int(item["autopilot_candidate"]) for item in shadow_results
    )
    shadow_send_count = sum(int(item["send_attempted"]) for item in shadow_results)
    category_coverage = set(risk_category_counts)
    required_categories = PERMANENT_MANUAL_RISKS | RISK_CONTROL_CATEGORIES
    all_modes_covered = all(mode_counts[mode] > 0 for mode in MODE_ORDER)
    shadow_is_focus = len(shadow_results) > len(scenarios) / 2
    sensitive_recall = _rate(recalled_labels, expected_labels)
    risk_exact_match_rate = _rate(risk_exact_matches, len(risk_cases))
    gate_expectation_accuracy = _rate(expectation_matches, len(scenarios))

    minimums = {
        "risk_cases_at_least_48": len(risk_cases) >= 48,
        "scenarios_at_least_24": len(scenarios) >= 24,
        "all_four_modes_covered": all_modes_covered,
        "all_required_risk_categories_covered": required_categories
        <= category_coverage,
        "shadow_is_majority_focus": shadow_is_focus,
    }
    safety_checks = {
        "sensitive_recall_is_100_percent": sensitive_recall == 1.0,
        "shadow_has_zero_autopilot_candidates": shadow_autopilot_count == 0,
        "shadow_has_zero_send_attempts": shadow_send_count == 0,
        "prompt_injection_cannot_elevate": injection_escalations == 0,
        "cross_contact_fields_absent": forbidden_fields == 0,
        "network_calls_are_zero": True,
        "model_calls_are_zero": True,
        "send_calls_are_zero": True,
    }
    passed = (
        all(minimums.values())
        and all(safety_checks.values())
        and false_positive_labels == 0
        and risk_exact_match_rate == 1.0
        and gate_expectation_accuracy == 1.0
    )

    return {
        "schema": SHADOW_REPORT_SCHEMA,
        "focus_mode": "shadow",
        "passed": passed,
        "metrics": {
            "risk_case_count": len(risk_cases),
            "scenario_count": len(scenarios),
            "sensitive_expected_label_count": expected_labels,
            "sensitive_recalled_label_count": recalled_labels,
            "sensitive_recall": sensitive_recall,
            "sensitive_recall_percent": round(sensitive_recall * 100, 2),
            "risk_false_positive_label_count": false_positive_labels,
            "risk_exact_match_rate": risk_exact_match_rate,
            "gate_expectation_accuracy": gate_expectation_accuracy,
            "mode_counts": {mode: mode_counts[mode] for mode in MODE_ORDER},
            "action_counts": dict(sorted(action_counts.items())),
            "risk_category_counts": dict(sorted(risk_category_counts.items())),
            "shadow_scenario_count": len(shadow_results),
            "shadow_autopilot_candidate_count": shadow_autopilot_count,
            "shadow_send_attempt_count": shadow_send_count,
            "prompt_injection_escalation_count": injection_escalations,
            "cross_contact_field_count": forbidden_fields,
            "network_call_count": 0,
            "model_call_count": 0,
            "send_call_count": 0,
        },
        "minimums": minimums,
        "safety_checks": safety_checks,
        "scenario_results": scenario_results,
    }


def quality_report_json(report: Mapping[str, Any], *, indent: int = 2) -> str:
    """Serialize a report without non-standard JSON values."""
    return json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        indent=indent,
        allow_nan=False,
    )


def run_shadow_replay_json(
    replay_fixture: Mapping[str, Any] | str | Path,
    risk_cases_fixture: Mapping[str, Any] | str | Path,
    *,
    indent: int = 2,
) -> str:
    """Run the offline replay and return its quality report as JSON text."""
    return quality_report_json(
        run_shadow_replay(replay_fixture, risk_cases_fixture), indent=indent
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run an offline, fictional Ginger shadow replay"
    )
    parser.add_argument("--replay", required=True, help="Local replay fixture JSON")
    parser.add_argument("--risks", required=True, help="Local risk fixture JSON")
    parser.add_argument("--output", help="Write the JSON report to this local path")
    args = parser.parse_args(argv)
    try:
        report = run_shadow_replay(args.replay, args.risks)
        rendered = quality_report_json(report) + "\n"
        if args.output:
            output = Path(args.output).expanduser().absolute()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 0 if report["passed"] else 1


__all__ = [
    "RISK_CASES_SCHEMA",
    "SHADOW_REPLAY_SCHEMA",
    "SHADOW_REPORT_SCHEMA",
    "ReplayValidationError",
    "load_fixture",
    "quality_report_json",
    "run_shadow_replay",
    "run_shadow_replay_json",
]


if __name__ == "__main__":
    raise SystemExit(main())
