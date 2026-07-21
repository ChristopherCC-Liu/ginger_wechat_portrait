import json
import io
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from personal_agent.config import AgentConfig, AgentPaths, load_config
from personal_agent import cli
from personal_agent.sender import (
    CanaryGuard,
    CanaryRequired,
    ComputerUseSender,
    DryRunSender,
    MacOSAccessibilitySender,
    SendRequest,
    UIDriftDetected,
    UIStateUncertain,
)
from personal_agent.service import pause, resume, set_kill_switch


CONTACT_KEY = "contact_0123456789abcdef"


class _Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Secrets:
    def __init__(self, values):
        self.values = values

    def get_secret(self, name):
        if name not in self.values:
            raise KeyError(name)
        return self.values[name]

    def delete_secret(self, name):
        self.values.pop(name, None)


class AgentConfigTests(unittest.TestCase):
    def test_default_is_shadow_with_real_send_disabled(self):
        config = AgentConfig.from_mapping({"schema_version": 2})
        self.assertEqual(config.mode, "shadow")
        self.assertTrue(config.sender.typing_only)
        self.assertFalse(config.sender.real_send_enabled)
        self.assertTrue(config.learning.enabled)
        self.assertEqual(config.learning.refresh_interval_seconds, 86_400)
        self.assertEqual(config.learning.minimum_corrections, 3)
        self.assertTrue(config.learning.auto_activate_safe)

    def test_learning_interval_and_sample_floor_are_validated(self):
        with self.assertRaisesRegex(ValueError, "refresh_interval_seconds"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "learning": {"refresh_interval_seconds": 299},
                }
            )
        with self.assertRaisesRegex(ValueError, "minimum_corrections"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "learning": {"minimum_corrections": 0},
                }
            )

    def test_boolean_and_numeric_config_types_are_strict(self):
        with self.assertRaisesRegex(ValueError, "sender.real_send_enabled"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "sender": {"real_send_enabled": "false"},
                }
            )
        with self.assertRaisesRegex(ValueError, "learning.enabled"):
            AgentConfig.from_mapping({"schema_version": 2, "learning": {"enabled": 1}})
        with self.assertRaisesRegex(ValueError, "daily_usd_limit"):
            AgentConfig.from_mapping(
                {"schema_version": 2, "cost": {"daily_usd_limit": True}}
            )
        with self.assertRaisesRegex(ValueError, "poll_interval_seconds"):
            AgentConfig.from_mapping(
                {"schema_version": 2, "poll_interval_seconds": 30.5}
            )
        with self.assertRaisesRegex(ValueError, "daily_call_limit must be <= 1000"):
            AgentConfig.from_mapping(
                {"schema_version": 2, "cost": {"daily_call_limit": 1001}}
            )

    def test_keychain_reference_names_are_not_treated_as_secrets(self):
        config = AgentConfig.from_mapping(
            {
                "schema_version": 2,
                "identity_key_ref": "identity-key",
                "reader": {"keychain_db_key_prefix": "wechat-db-key"},
                "model": {"api_key_ref": "openai-api-key"},
            }
        )
        self.assertEqual(config.model.api_key_ref, "openai-api-key")

    def test_keychain_reference_names_are_bounded_and_cannot_inject_namespaces(self):
        with self.assertRaisesRegex(ValueError, "sender.canary_ref"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "sender": {"canary_ref": "canary:forged-attempt"},
                }
            )
        with self.assertRaisesRegex(ValueError, "reader.self_id_ref"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "reader": {"self_id_ref": "self\nforged"},
                }
            )

    def test_raw_secret_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Raw secret field"):
            AgentConfig.from_mapping(
                {"schema_version": 2, "model": {"api_key": "not-allowed"}}
            )

    def test_secret_like_values_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Possible raw credential"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "model": {"model": "sk-this_should_never_be_in_config"},
                }
            )

    def test_real_send_needs_autopilot_allowlist_and_no_typing_only(self):
        with self.assertRaisesRegex(ValueError, "only valid in autopilot"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "sender": {"real_send_enabled": True, "typing_only": False},
                }
            )
        with self.assertRaisesRegex(ValueError, "non-empty hashed allowlist"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "mode": "autopilot",
                    "sender": {"real_send_enabled": True, "typing_only": False},
                }
            )
        with self.assertRaisesRegex(ValueError, "Accessibility"):
            AgentConfig.from_mapping(
                {
                    "schema_version": 2,
                    "mode": "autopilot",
                    "allowlist": [CONTACT_KEY],
                    "sender": {
                        "backend": "computer_use",
                        "real_send_enabled": True,
                        "typing_only": False,
                    },
                }
            )

    def test_load_config_requires_mode_0600(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.toml"
            path.write_text("schema_version = 2\n", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                load_config(path)
            path.chmod(0o600)
            self.assertEqual(load_config(path).mode, "shadow")

    def test_cli_doctor_returns_nonzero_when_required_checks_fail(self):
        with mock.patch.object(cli, "_runtime_config", return_value=mock.Mock()):
            with mock.patch.object(
                cli,
                "doctor",
                return_value={"schema": "ginger_agent_doctor_v2", "ready": False},
            ):
                with mock.patch("sys.stdout", new=io.StringIO()):
                    self.assertEqual(cli.main(["doctor"]), 1)


class SenderTests(unittest.TestCase):
    def _request(self, action="dry_run"):
        return SendRequest(
            attempt_id="attempt-1",
            contact_key=CONTACT_KEY,
            contact_label="测试联系人甲",
            body="虚构回复正文",
            search_token=(
                "fixture-unique-search-token-a" if action != "dry_run" else None
            ),
            action=action,
        )

    def test_send_request_rejects_contact_control_characters(self):
        with self.assertRaisesRegex(ValueError, "control"):
            SendRequest("a", CONTACT_KEY, "测试\n联系人", "body", action="typing_only")

    def test_dry_run_performs_no_verification_or_click(self):
        result = DryRunSender().execute(self._request())
        self.assertFalse(result.clicked)
        self.assertFalse(result.recipient_verified)

    def test_canary_is_required_for_click(self):
        runner = mock.Mock(side_effect=AssertionError("runner must not be called"))
        sender = MacOSAccessibilitySender(
            canary=CanaryGuard(_Secrets({}), "real-send-canary"), runner=runner
        )
        with mock.patch("personal_agent.sender.platform.system", return_value="Darwin"):
            with self.assertRaises(CanaryRequired):
                sender.execute(self._request("click_send"))

    def test_canary_is_bound_to_attempt_and_consumed_before_click(self):
        request = self._request("click_send")
        account = "real-send-canary:attempt-1"
        payload = {
            "schema": "ginger_one_time_canary_v1",
            "attempt_id": request.attempt_id,
            "contact_key": request.contact_key,
            "body_sha256": request.body_sha256,
            "expires_at_epoch": time.time() + 120,
        }
        secrets = _Secrets({account: json.dumps(payload).encode()})
        runner = mock.Mock(side_effect=AssertionError("stop after canary"))
        sender = MacOSAccessibilitySender(
            canary=CanaryGuard(secrets, "real-send-canary"), runner=runner
        )
        with mock.patch("personal_agent.sender.platform.system", return_value="Darwin"):
            with self.assertRaises(AssertionError):
                sender.execute(request)
        self.assertNotIn(account, secrets.values)

    def test_typing_only_keeps_body_out_of_osascript_argv_and_script(self):
        calls = []

        def runner(arguments, **kwargs):
            calls.append((arguments, kwargs.get("input")))
            if arguments == ["/usr/bin/pbpaste"]:
                return _Result(stdout=b"previous clipboard")
            if arguments == ["/usr/bin/pbcopy"]:
                return _Result()
            if arguments == ["/usr/bin/osascript", "-"]:
                return _Result(stdout=b"GINGER_TYPING_ONLY_OK\n")
            raise AssertionError(arguments)

        sender = MacOSAccessibilitySender(runner=runner)
        with mock.patch("personal_agent.sender.platform.system", return_value="Darwin"):
            result = sender.execute(self._request("typing_only"))
        self.assertFalse(result.clicked)
        osascript_call = next(call for call in calls if "osascript" in call[0][0])
        self.assertNotIn("虚构回复正文", " ".join(osascript_call[0]))
        self.assertNotIn("虚构回复正文", osascript_call[1].decode("utf-8"))
        script = osascript_call[1].decode("utf-8")
        self.assertIn('if existingEditorValue is not ""', script)
        self.assertIn("if searchMatchingLabels is not 1", script)
        self.assertIn("if editorValue is not messageBody", script)
        self.assertNotIn("ends with messageBody", script)

    def test_accessibility_mismatch_fails_closed(self):
        def runner(arguments, **kwargs):
            if arguments == ["/usr/bin/pbpaste"]:
                return _Result()
            if arguments == ["/usr/bin/pbcopy"]:
                return _Result()
            return _Result(returncode=1, stderr=b"GINGER_RECIPIENT_MISMATCH")

        sender = MacOSAccessibilitySender(runner=runner)
        with mock.patch("personal_agent.sender.platform.system", return_value="Darwin"):
            with self.assertRaises(UIDriftDetected):
                sender.execute(self._request("typing_only"))

    def test_body_mismatch_is_uncertain_and_must_not_be_retried(self):
        def runner(arguments, **kwargs):
            if arguments == ["/usr/bin/pbpaste"]:
                return _Result()
            if arguments == ["/usr/bin/pbcopy"]:
                return _Result()
            return _Result(returncode=1, stderr=b"GINGER_BODY_MISMATCH")

        sender = MacOSAccessibilitySender(runner=runner)
        with mock.patch("personal_agent.sender.platform.system", return_value="Darwin"):
            with self.assertRaises(UIStateUncertain):
                sender.execute(self._request("typing_only"))

    def test_nonempty_composer_is_uncertain_and_must_not_be_retried(self):
        def runner(arguments, **kwargs):
            if arguments == ["/usr/bin/pbpaste"]:
                return _Result()
            if arguments == ["/usr/bin/pbcopy"]:
                return _Result()
            return _Result(returncode=1, stderr=b"GINGER_COMPOSER_NOT_EMPTY")

        sender = MacOSAccessibilitySender(runner=runner)
        with mock.patch("personal_agent.sender.platform.system", return_value="Darwin"):
            with self.assertRaises(UIStateUncertain):
                sender.execute(self._request("typing_only"))

    def test_computer_use_helper_requires_secure_permissions_and_exact_result(self):
        with tempfile.TemporaryDirectory() as temp:
            helper = Path(temp) / "helper"
            helper.write_text("#!/bin/sh\n", encoding="utf-8")
            helper.chmod(0o700)

            def runner(arguments, **kwargs):
                request = self._request("typing_only")
                payload = (
                    '{"attempt_id":"attempt-1",'
                    f'"contact_key":"{CONTACT_KEY}",'
                    f'"body_sha256":"{request.body_sha256}",'
                    '"recipient_verified":true,"body_verified":true,'
                    '"clicked":false}'
                )
                return _Result(stdout=payload.encode("utf-8"))

            result = ComputerUseSender(helper, runner=runner).execute(
                self._request("typing_only")
            )
            self.assertTrue(result.recipient_verified)
            self.assertFalse(result.clicked)
            helper.chmod(0o722)
            with self.assertRaisesRegex(ValueError, "writable"):
                ComputerUseSender(helper, runner=runner)

    def test_computer_use_never_executes_click_send(self):
        with tempfile.TemporaryDirectory() as temp:
            helper = Path(temp) / "helper"
            helper.write_text("#!/bin/sh\n", encoding="utf-8")
            helper.chmod(0o700)
            sender = ComputerUseSender(helper)
            with self.assertRaisesRegex(CanaryRequired, "forbidden"):
                sender.execute(self._request("click_send"))


class ServiceControlTests(unittest.TestCase):
    def test_pause_resume_and_kill_switch_are_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            paths = AgentPaths(Path(temp))
            self.assertTrue(pause(paths)["paused"])
            self.assertFalse(resume(paths)["paused"])
            state = set_kill_switch(paths, True)
            self.assertTrue(state["kill_switch"])
            with self.assertRaisesRegex(RuntimeError, "Kill switch"):
                resume(paths)
            self.assertFalse(set_kill_switch(paths, False)["kill_switch"])
            self.assertFalse(resume(paths)["paused"])


if __name__ == "__main__":
    unittest.main()
