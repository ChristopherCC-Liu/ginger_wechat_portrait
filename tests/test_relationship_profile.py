from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from personal_agent.distillation import (
    RELATIONSHIP,
    USER_CONFIRMED,
    DistillationService,
)
from personal_agent.learning import refresh_distillation
from personal_agent.ledger import Cursor, EncryptedLedger, LedgerEvent
from personal_agent.runtime_state import LedgerDistillationRepository


CONTACT_A = "contact_" + "a" * 32
CONTACT_B = "contact_" + "b" * 32
CONTACT_C = "contact_" + "c" * 32
SHARD = "message/message_0.db"
TABLE = "Msg_" + "0" * 32
BASE = 1_800_000_000


class RelationshipProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp.name) / "ledger.sqlite3"
        self.ledger = EncryptedLedger(self.database_path, b"r" * 32)

    def tearDown(self) -> None:
        self.ledger.close()
        self.temp.cleanup()

    @staticmethod
    def _event(
        event_id: str,
        contact_key: str,
        direction: str,
        create_time: int,
        local_id: int,
        body: str,
        *,
        display_name: str,
    ) -> LedgerEvent:
        return LedgerEvent(
            event_id=event_id,
            contact_key=contact_key,
            direction=direction,
            local_type=1,
            create_time=create_time,
            local_id=local_id,
            body=body,
            contact_display_name=display_name,
            shard=SHARD,
            table_name=TABLE,
        )

    def _ingest(self, events: list[LedgerEvent]) -> None:
        cursor_event = max(
            events,
            key=lambda event: (event.create_time, event.local_id),
        )
        self.ledger.ingest_events(
            events,
            shard=SHARD,
            table_name=TABLE,
            cursor=Cursor(cursor_event.create_time, cursor_event.local_id),
        )

    def _initial_events(self) -> list[LedgerEvent]:
        return [
            self._event(
                "evt_a_in_1",
                CONTACT_A,
                "inbound",
                BASE,
                1,
                "今天还好吗",
                display_name="UNCONFIRMED_A_DISPLAY",
            ),
            self._event(
                "evt_a_out_1",
                CONTACT_A,
                "outbound",
                BASE + 60,
                2,
                "阿澄，谢谢你，今天辛苦了，我们晚一点再把这件事情仔细聊完😊",
                display_name="UNCONFIRMED_A_DISPLAY",
            ),
            self._event(
                "evt_b_in_1",
                CONTACT_B,
                "inbound",
                BASE + 90,
                3,
                "请确认",
                display_name="UNCONFIRMED_B_DISPLAY",
            ),
            self._event(
                "evt_b_out_1",
                CONTACT_B,
                "outbound",
                BASE + 690,
                4,
                "老周，收到👍",
                display_name="UNCONFIRMED_B_DISPLAY",
            ),
            self._event(
                "evt_a_out_2",
                CONTACT_A,
                "outbound",
                BASE + 7 * 60 * 60,
                5,
                "阿澄，早安，记得吃早餐，今天出门也要注意安全😊",
                display_name="UNCONFIRMED_A_DISPLAY",
            ),
            self._event(
                "evt_a_in_2",
                CONTACT_A,
                "inbound",
                BASE + 7 * 60 * 60 + 120,
                6,
                "好呀",
                display_name="UNCONFIRMED_A_DISPLAY",
            ),
            self._event(
                "evt_b_out_2",
                CONTACT_B,
                "outbound",
                BASE + 7 * 60 * 60 + 30,
                7,
                "老周，收到👍",
                display_name="UNCONFIRMED_B_DISPLAY",
            ),
            self._event(
                "evt_a_in_3",
                CONTACT_A,
                "inbound",
                BASE + 14 * 60 * 60 + 180,
                8,
                "晚上再聊",
                display_name="UNCONFIRMED_A_DISPLAY",
            ),
            self._event(
                "evt_a_out_3",
                CONTACT_A,
                "outbound",
                BASE + 14 * 60 * 60 + 480,
                9,
                "阿澄，晚安，今天谢谢你耐心听我说这些，回去路上注意安全😊",
                display_name="UNCONFIRMED_A_DISPLAY",
            ),
            self._event(
                "evt_b_out_3",
                CONTACT_B,
                "outbound",
                BASE + 14 * 60 * 60 + 30,
                10,
                "老周，收到👍",
                display_name="UNCONFIRMED_B_DISPLAY",
            ),
        ]

    def _confirm_protected_a(self) -> str:
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        version = service.create_version(
            RELATIONSHIP,
            {
                "taboo": ["A_ONLY_CONFIRMED_TABOO"],
                "boundaries": {"share_private_data": False},
                "display_name": "A_CONFIRMED_DISPLAY",
                "ui_search_token": "A_CONFIRMED_SEARCH_TOKEN",
                "user_note": "keep this confirmed base",
            },
            confidence=1.0,
            contact_key=CONTACT_A,
            correction_type=USER_CONFIRMED,
            protected_fields=("taboo",),
            activate=True,
        )
        return version.version_id

    def test_profiles_are_contact_isolated_quantified_and_protected(self):
        confirmed_id = self._confirm_protected_a()
        self._ingest(self._initial_events())

        with (
            mock.patch(
                "personal_agent.models.create_model_adapter",
                side_effect=AssertionError("model access is forbidden"),
            ),
            mock.patch(
                "personal_agent.sender.DryRunSender.execute",
                side_effect=AssertionError("sender access is forbidden"),
            ),
        ):
            result = refresh_distillation(
                self.ledger,
                timezone_name="Asia/Shanghai",
                force=True,
                now_epoch=1_900_000_000,
            )

        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(result["send_actions"], 0)
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        version_a = service.active(RELATIONSHIP, CONTACT_A)
        version_b = service.active(RELATIONSHIP, CONTACT_B)
        self.assertIsNotNone(version_a)
        self.assertIsNotNone(version_b)
        assert version_a is not None and version_b is not None
        self.assertEqual(version_a.parent_id, confirmed_id)

        payload_a = version_a.to_dict()["payload"]
        payload_b = version_b.to_dict()["payload"]
        profile_a = payload_a["relationship_profile"]
        profile_b = payload_b["relationship_profile"]

        self.assertEqual(payload_a["preferred_address"], "阿澄")
        self.assertEqual(payload_b["preferred_address"], "老周")
        self.assertEqual(payload_a["preferred_emoji"], ["😊"])
        self.assertEqual(payload_b["preferred_emoji"], ["👍"])
        self.assertGreater(
            profile_a["reply_length"]["average_chars"],
            profile_b["reply_length"]["average_chars"],
        )
        self.assertEqual(payload_a["temperature"], "warm")
        self.assertEqual(payload_b["temperature"], "neutral")
        self.assertEqual(payload_a["initiative_level"], "low")
        self.assertEqual(payload_b["initiative_level"], "high")
        self.assertEqual(payload_a["reply_delay_seconds"], 180)
        self.assertEqual(payload_b["reply_delay_seconds"], 600)
        self.assertTrue(
            all(event_id.startswith("evt_a_") for event_id in version_a.evidence_ids)
        )
        self.assertTrue(
            all(event_id.startswith("evt_b_") for event_id in version_b.evidence_ids)
        )

        self.assertEqual(payload_a["taboo"], ["A_ONLY_CONFIRMED_TABOO"])
        self.assertEqual(payload_a["boundaries"], {"share_private_data": False})
        self.assertEqual(payload_a["display_name"], "A_CONFIRMED_DISPLAY")
        self.assertEqual(payload_a["ui_search_token"], "A_CONFIRMED_SEARCH_TOKEN")
        self.assertIn("taboo", version_a.protected_fields)
        serialized_a = json.dumps(payload_a, ensure_ascii=False)
        serialized_b = json.dumps(payload_b, ensure_ascii=False)
        self.assertNotIn("老周", serialized_a)
        self.assertNotIn("👍", serialized_a)
        self.assertNotIn("阿澄", serialized_b)
        self.assertNotIn("😊", serialized_b)
        self.assertNotIn("A_ONLY_CONFIRMED_TABOO", serialized_b)
        self.assertNotIn("UNCONFIRMED_A_DISPLAY", serialized_a)
        self.assertNotIn("UNCONFIRMED_B_DISPLAY", serialized_b)
        self.assertNotIn("阿澄".encode("utf-8"), self.database_path.read_bytes())

    def test_same_evidence_is_idempotent_and_new_version_rolls_back(self):
        self._confirm_protected_a()
        self._ingest(self._initial_events())
        refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            force=True,
            now_epoch=1_900_000_100,
        )
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        first = service.active(RELATIONSHIP, CONTACT_A)
        stable_b = service.active(RELATIONSHIP, CONTACT_B)
        self.assertIsNotNone(first)
        self.assertIsNotNone(stable_b)
        assert first is not None and stable_b is not None
        version_count = len(service.repository.list_versions(RELATIONSHIP, CONTACT_A))

        repeated = refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            force=True,
            now_epoch=1_900_000_101,
        )
        self.assertEqual(repeated["versions_created"], 0)
        self.assertEqual(
            len(service.repository.list_versions(RELATIONSHIP, CONTACT_A)),
            version_count,
        )

        self._ingest(
            [
                self._event(
                    "evt_a_in_4",
                    CONTACT_A,
                    "inbound",
                    BASE + 22 * 60 * 60,
                    100,
                    "到家了吗",
                    display_name="UNCONFIRMED_A_DISPLAY",
                ),
                self._event(
                    "evt_a_out_4",
                    CONTACT_A,
                    "outbound",
                    BASE + 22 * 60 * 60 + 120,
                    101,
                    "阿澄，谢谢关心，我已经安全到家了😊",
                    display_name="UNCONFIRMED_A_DISPLAY",
                ),
            ]
        )
        refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            force=True,
            now_epoch=1_900_000_102,
        )
        second = service.active(RELATIONSHIP, CONTACT_A)
        self.assertIsNotNone(second)
        assert second is not None
        self.assertEqual(second.parent_id, first.version_id)
        self.assertNotEqual(second.payload_hash, first.payload_hash)
        self.assertEqual(
            service.active(RELATIONSHIP, CONTACT_B).version_id,
            stable_b.version_id,
        )

        second_payload = second.to_dict()["payload"]
        rolled_back = service.rollback(
            RELATIONSHIP,
            first.version_id,
            contact_key=CONTACT_A,
        )
        self.assertEqual(rolled_back.version_id, first.version_id)
        self.assertEqual(
            service.repository.get(second.version_id).to_dict()["payload"],
            second_payload,
        )
        with self.assertRaises(TypeError):
            first.payload["warmth_score"] = 0

        after_rollback = refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            force=True,
            now_epoch=1_900_000_103,
        )
        self.assertEqual(after_rollback["versions_created"], 0)
        self.assertEqual(
            service.active(RELATIONSHIP, CONTACT_A).version_id,
            first.version_id,
        )

    def test_insufficient_samples_do_not_create_relationship_version(self):
        self._ingest(
            [
                self._event(
                    "evt_c_in_1",
                    CONTACT_C,
                    "inbound",
                    BASE,
                    1,
                    "在吗",
                    display_name="UNCONFIRMED_C_DISPLAY",
                ),
                self._event(
                    "evt_c_out_1",
                    CONTACT_C,
                    "outbound",
                    BASE + 20,
                    2,
                    "在",
                    display_name="UNCONFIRMED_C_DISPLAY",
                ),
            ]
        )

        result = refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            force=True,
            now_epoch=1_900_000_200,
        )

        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(result["send_actions"], 0)
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        self.assertIsNone(service.active(RELATIONSHIP, CONTACT_C))


if __name__ == "__main__":
    unittest.main()
