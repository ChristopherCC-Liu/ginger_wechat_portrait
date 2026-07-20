from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from personal_agent.config import AgentConfig
from personal_agent.crypto_store import MemorySecretStore, SecretNotFoundError
from personal_agent.distillation import (
    RELATIONSHIP,
    USER_CONFIRMED,
    DistillationService,
)
from personal_agent.ledger import EncryptedLedger
from personal_agent.operations import arm_send_canary
from personal_agent.runtime import DRAFT_ACTION_NAMESPACE, DRAFT_NAMESPACE
from personal_agent.runtime_state import LedgerDistillationRepository
from personal_agent.sender import CanaryGuard, SendRequest, send_attempt_id


CONTACT_KEY = "contact_" + "a" * 32
BODY = "收到"
EVENT_ID = "evt_fixture_canary"
DRAFT_ID = "draft_fixture_canary"


class CanaryArmingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "db").mkdir()
        self.now = int(time.time())
        self.config = AgentConfig.from_mapping(
            {
                "schema_version": 2,
                "mode": "autopilot",
                "state_root": str(self.root / "state"),
                "allowlist": [CONTACT_KEY],
                "reader": {"db_dir": str(self.root / "db")},
                "model": {
                    "provider": "local",
                    "model": "fixture-model",
                    "base_url": "http://127.0.0.1:11434/v1",
                },
                "sender": {
                    "typing_only": False,
                    "real_send_enabled": True,
                },
            }
        )
        self.ledger = EncryptedLedger(self.root / "ledger.sqlite3", b"s" * 32)
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        identity = service.create_version(
            RELATIONSHIP,
            {
                "display_name": "虚构联系人甲",
                "ui_search_token": "fixture-unique-token-a",
            },
            contact_key=CONTACT_KEY,
            confidence=1,
            correction_type=USER_CONFIRMED,
            activate=True,
        )
        self.ledger.append_runtime_record(
            DRAFT_ID,
            DRAFT_NAMESPACE,
            CONTACT_KEY,
            "draft",
            {
                "body": BODY,
                "contact_key": CONTACT_KEY,
                "contact_label": "虚构联系人甲",
                "contact_search_token": "fixture-unique-token-a",
                "context_hash": "c" * 64,
                "decision": {
                    "intent": "acknowledge",
                    "stance": BODY,
                    "facts": [],
                    "commitments": [],
                    "risk": "low",
                    "confidence": 0.99,
                    "reply_required": True,
                    "context_sufficient": True,
                    "reasons": ["synthetic_fixture"],
                },
                "event_id": EVENT_ID,
                "gate": {
                    "action": "autopilot_candidate",
                    "detected_risks": [],
                    "mode": "autopilot",
                    "reasons": ["synthetic_fixture"],
                },
                "not_before_epoch": self.now,
                "status": "autopilot_candidate",
                "ui_identity_verified": True,
                "ui_identity_version_id": identity.version_id,
            },
            occurred_at=self.now,
        )

    def tearDown(self) -> None:
        self.ledger.close()
        self.temp.cleanup()

    def test_explicit_arm_creates_one_consumable_draft_bound_canary(self):
        secrets = MemorySecretStore()
        result = arm_send_canary(
            self.config,
            self.ledger,
            DRAFT_ID,
            confirmation="SEND_ONCE",
            expires_seconds=120,
            secrets=secrets,
            now_epoch=self.now,
        )
        expected_attempt = send_attempt_id(DRAFT_ID, EVENT_ID, CONTACT_KEY, BODY)
        self.assertEqual(result["attempt_id"], expected_attempt)
        self.assertFalse(result["send_executed"])

        request = SendRequest(
            attempt_id=expected_attempt,
            contact_key=CONTACT_KEY,
            contact_label="虚构联系人甲",
            search_token="fixture-unique-token-a",
            body=BODY,
            action="click_send",
        )
        account = f"{self.config.sender.canary_ref}:{expected_attempt}"
        with mock.patch("personal_agent.sender.time.time", return_value=self.now):
            CanaryGuard(secrets, self.config.sender.canary_ref).consume(request)
        with self.assertRaises(SecretNotFoundError):
            secrets.get_secret(account)

        records = self.ledger.list_runtime_records(
            DRAFT_ACTION_NAMESPACE,
            scope=DRAFT_ID,
            kind="real_send_canary_armed",
        )
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0].payload["send_executed"])

    def test_wrong_confirmation_future_draft_and_shadow_mode_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "SEND_ONCE"):
            arm_send_canary(
                self.config,
                self.ledger,
                DRAFT_ID,
                confirmation="yes",
                now_epoch=self.now,
                secrets=MemorySecretStore(),
            )

        future = self.ledger.get_runtime_record(DRAFT_ID)
        assert future is not None
        self.ledger.append_runtime_record(
            "draft_fixture_future",
            DRAFT_NAMESPACE,
            CONTACT_KEY,
            "draft",
            {**future.payload, "not_before_epoch": self.now + 60},
        )
        with self.assertRaisesRegex(ValueError, "not due"):
            arm_send_canary(
                self.config,
                self.ledger,
                "draft_fixture_future",
                confirmation="SEND_ONCE",
                now_epoch=self.now,
                secrets=MemorySecretStore(),
            )

        shadow = AgentConfig.from_mapping(
            {
                "schema_version": 2,
                "state_root": str(self.root / "shadow"),
                "reader": {"db_dir": str(self.root / "db")},
            }
        )
        with self.assertRaisesRegex(ValueError, "enabled autopilot"):
            arm_send_canary(
                shadow,
                self.ledger,
                DRAFT_ID,
                confirmation="SEND_ONCE",
                now_epoch=self.now,
                secrets=MemorySecretStore(),
            )


if __name__ == "__main__":
    unittest.main()
