from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from personal_agent.corrections import (
    make_distillation_candidate,
    propose_distillation_candidates,
    record_correction,
)
from personal_agent.distillation import (
    DECISION_PREFERENCES,
    EMOTION_CYCLE,
    LANGUAGE_STYLE,
    RELATIONSHIP,
    STABLE_FACTS,
    USER_CONFIRMED,
    DistillationService,
)
from personal_agent.learning import (
    LEARNING_CANDIDATE_NAMESPACE,
    refresh_distillation,
)
from personal_agent.ledger import Cursor, EncryptedLedger, LedgerEvent
from personal_agent.runtime_state import LedgerDistillationRepository


CONTACT_A = "contact_" + "a" * 32
CONTACT_B = "contact_" + "b" * 32


class PeriodicLearningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = EncryptedLedger(
            Path(self.temp.name) / "ledger.sqlite3",
            b"l" * 32,
        )

    def tearDown(self) -> None:
        self.ledger.close()
        self.temp.cleanup()

    def _append_correction_candidates(
        self,
        contact_key: str,
        index: int,
        final_reply: str,
    ) -> None:
        correction = record_correction(
            contact_key=contact_key,
            model_draft="fixture draft",
            user_edit=final_reply,
            final_reply=final_reply,
            created_at=datetime(2026, 1, index + 1, tzinfo=timezone.utc),
            id_factory=lambda: f"corr_{contact_key[-1]}_{index}",
        )
        for candidate in propose_distillation_candidates(correction):
            self.ledger.append_runtime_record(
                candidate.candidate_id,
                LEARNING_CANDIDATE_NAMESPACE,
                candidate.contact_key or "global",
                "candidate",
                candidate.to_dict(),
                occurred_at=1_800_000_000 + index,
            )

    def _ingest_outbound_emotion_fixture(self) -> None:
        events = []
        base = 1_767_225_600
        for index in range(8):
            events.append(
                LedgerEvent(
                    event_id=f"evt_out_{index}",
                    contact_key=CONTACT_A,
                    direction="outbound",
                    local_type=1,
                    create_time=base + index * 60,
                    local_id=index + 1,
                    body="谢谢，今天很开心😊",
                    shard="message/message_0.db",
                    table_name="Msg_" + "0" * 32,
                )
            )
        self.ledger.ingest_events(
            events,
            shard="message/message_0.db",
            table_name="Msg_" + "0" * 32,
            cursor=Cursor(events[-1].create_time, events[-1].local_id),
        )

    def test_periodic_refresh_is_local_versioned_and_contact_isolated(self):
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        stable = service.create_version(
            STABLE_FACTS,
            {"fixture_name": "confirmed"},
            confidence=1.0,
            correction_type=USER_CONFIRMED,
            activate=True,
        )
        for index in range(3):
            self._append_correction_candidates(CONTACT_A, index, "收到😊")
            self._append_correction_candidates(
                CONTACT_B,
                index + 3,
                "这是一条比较详细的虚构最终回复，不使用表情。",
            )
        self._ingest_outbound_emotion_fixture()

        result = refresh_distillation(
            self.ledger,
            timezone_name="Asia/Shanghai",
            minimum_corrections=3,
            now_epoch=1_800_100_000,
        )

        self.assertTrue(result["due"])
        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(result["send_actions"], 0)
        self.assertGreaterEqual(result["versions_created"], 5)

        reopened = DistillationService(LedgerDistillationRepository(self.ledger))
        self.assertEqual(reopened.active(STABLE_FACTS).version_id, stable.version_id)
        self.assertIsNotNone(reopened.active(EMOTION_CYCLE))
        self.assertIsNotNone(reopened.active(LANGUAGE_STYLE))
        relation_a = reopened.active(RELATIONSHIP, CONTACT_A)
        relation_b = reopened.active(RELATIONSHIP, CONTACT_B)
        self.assertIsNotNone(relation_a)
        self.assertIsNotNone(relation_b)
        assert relation_a is not None and relation_b is not None
        self.assertEqual(
            relation_a.payload["correction_learning"]["sample_count"],
            3,
        )
        self.assertEqual(
            relation_b.payload["correction_learning"]["sample_count"],
            3,
        )
        self.assertNotEqual(relation_a.payload_hash, relation_b.payload_hash)

        repeated = refresh_distillation(
            self.ledger,
            timezone_name="Asia/Shanghai",
            minimum_corrections=3,
            now_epoch=1_800_100_100,
        )
        self.assertFalse(repeated["due"])
        self.assertEqual(repeated["versions_created"], 0)

    def test_boundary_candidate_is_never_materialized_automatically(self):
        correction = record_correction(
            contact_key=CONTACT_A,
            model_draft="fixture",
            user_edit="fixture edit",
            final_reply="fixture final",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            id_factory=lambda: "corr_boundary",
        )
        candidate = make_distillation_candidate(
            correction,
            domain=RELATIONSHIP,
            payload={"boundaries": {"share_private_data": False}},
            confidence=0.9,
        )
        self.assertTrue(candidate.requires_user_confirmation)
        self.ledger.append_runtime_record(
            candidate.candidate_id,
            LEARNING_CANDIDATE_NAMESPACE,
            CONTACT_A,
            "candidate",
            candidate.to_dict(),
        )

        result = refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            minimum_corrections=1,
            force=True,
            now_epoch=1_800_200_000,
        )
        self.assertEqual(result["versions_created"], 0)
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        self.assertIsNone(service.active(RELATIONSHIP, CONTACT_A))

    def test_global_decision_learning_contains_no_contact_wording(self):
        private_phrase = "仅属于虚构联系人甲的特殊说法"
        for index in range(3):
            self._append_correction_candidates(CONTACT_A, index, private_phrase)

        refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            minimum_corrections=3,
            force=True,
            now_epoch=1_800_300_000,
        )

        service = DistillationService(LedgerDistillationRepository(self.ledger))
        global_preferences = service.active(DECISION_PREFERENCES)
        relationship = service.active(RELATIONSHIP, CONTACT_A)
        self.assertIsNotNone(global_preferences)
        self.assertIsNotNone(relationship)
        assert global_preferences is not None and relationship is not None
        self.assertNotIn(
            private_phrase,
            json.dumps(global_preferences.to_dict(), ensure_ascii=False),
        )
        self.assertIn(
            private_phrase,
            json.dumps(relationship.to_dict(), ensure_ascii=False),
        )
        self.assertIsNone(service.active(RELATIONSHIP, CONTACT_B))

    def test_interrupted_materialization_is_idempotent_on_retry(self):
        for index in range(3):
            self._append_correction_candidates(CONTACT_A, index, "收到")

        original_append = self.ledger.append_runtime_record
        failed_once = False

        def flaky_append(record_id, *args, **kwargs):
            nonlocal failed_once
            if record_id.startswith("materialized:") and not failed_once:
                failed_once = True
                raise RuntimeError("synthetic materialization interruption")
            return original_append(record_id, *args, **kwargs)

        with mock.patch.object(
            self.ledger, "append_runtime_record", side_effect=flaky_append
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic"):
                refresh_distillation(
                    self.ledger,
                    timezone_name="UTC",
                    minimum_corrections=3,
                    force=True,
                    now_epoch=1_800_400_000,
                )

        refresh_distillation(
            self.ledger,
            timezone_name="UTC",
            minimum_corrections=3,
            force=True,
            now_epoch=1_800_400_100,
        )
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        style = service.active(LANGUAGE_STYLE)
        self.assertIsNotNone(style)
        assert style is not None
        self.assertEqual(style.payload["correction_learning"]["sample_count"], 3)


if __name__ == "__main__":
    unittest.main()
