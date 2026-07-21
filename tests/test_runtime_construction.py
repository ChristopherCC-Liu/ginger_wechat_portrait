from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from personal_agent.config import AgentConfig
from personal_agent.crypto_store import MemorySecretStore
from personal_agent.ledger import EncryptedLedger
from personal_agent.runtime import (
    BOOTSTRAP_RECORD_ID,
    RuntimeConfigurationError,
    build_reader,
    build_runtime,
)


STATE_KEY = b"s" * 32
IDENTITY_KEY = b"i" * 32
CONTACT_KEY = "contact_" + "a" * 32


class RuntimeConstructionTests(unittest.TestCase):
    def _config(
        self,
        root: Path,
        *,
        real_send: bool = False,
        timezone: str = "UTC",
    ) -> AgentConfig:
        return AgentConfig.from_mapping(
            {
                "schema_version": 2,
                "mode": "autopilot" if real_send else "shadow",
                "timezone": timezone,
                "state_root": str(root / "state"),
                "allowlist": [CONTACT_KEY] if real_send else [],
                "reader": {"db_dir": str(root / "db")},
                "model": {
                    "provider": "local",
                    "model": "fixture-model",
                    "base_url": "http://127.0.0.1:11434/v1",
                },
                "sender": {
                    "real_send_enabled": real_send,
                    "typing_only": not real_send,
                },
            }
        )

    def _secrets(self, *, self_id: bytes | None = None) -> MemorySecretStore:
        values = {"state-key": STATE_KEY, "identity-key": IDENTITY_KEY}
        if self_id is not None:
            values["wechat-self-id"] = self_id
        return MemorySecretStore(values)

    def test_existing_bootstrap_cutoff_is_passed_to_new_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "db").mkdir()
            config = self._config(root)
            with EncryptedLedger(config.paths.ledger, STATE_KEY) as ledger:
                ledger.append_runtime_record(
                    BOOTSTRAP_RECORD_ID,
                    "runtime_meta",
                    "global",
                    "bootstrap",
                    {"completed_at_epoch": 123_456},
                )

            reader = mock.Mock()
            with mock.patch(
                "personal_agent.runtime.WeChatReader",
                return_value=reader,
            ) as constructor:
                _, ledger = build_runtime(config, secrets=self._secrets())
                ledger.close()

            kwargs = constructor.call_args.kwargs
            self.assertIsNone(kwargs["initial_after_epoch"])
            self.assertEqual(kwargs["bootstrap_after_epoch"], 123_456)

    def test_real_send_requires_direction_safe_self_id(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "db").mkdir()
            config = self._config(root, real_send=True)
            with self.assertRaisesRegex(
                RuntimeConfigurationError,
                "requires reader.self_id_ref",
            ):
                build_reader(
                    config,
                    mock.Mock(),
                    self._secrets(),
                    IDENTITY_KEY,
                    first_run=True,
                )

    def test_build_failure_closes_only_an_internally_created_ledger(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "db").mkdir()
            config = self._config(root)
            owned = mock.Mock()
            owned.get_runtime_record.return_value = None
            with mock.patch(
                "personal_agent.runtime.EncryptedLedger",
                return_value=owned,
            ):
                with mock.patch(
                    "personal_agent.runtime.build_reader",
                    side_effect=OSError("synthetic construction failure"),
                ):
                    with self.assertRaises(OSError):
                        build_runtime(config, secrets=self._secrets())
            owned.close.assert_called_once_with()

            provided = mock.Mock()
            provided.get_runtime_record.return_value = None
            invalid_timezone = self._config(root, timezone="Invalid/FixtureZone")
            with self.assertRaises(ValueError):
                build_runtime(
                    invalid_timezone,
                    secrets=self._secrets(),
                    ledger=provided,
                    reader=mock.Mock(),
                )
            provided.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
