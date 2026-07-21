from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from personal_agent.config import AgentConfig
from personal_agent.costs import BudgetExceededError, DailyLimits, ModelPricing
from personal_agent.crypto_store import MemorySecretStore
from personal_agent.decision import ReplyDecision
from personal_agent.distillation import (
    LANGUAGE_STYLE,
    RELATIONSHIP,
    USER_CONFIRMED,
    DistillationService,
)
from personal_agent.ledger import Cursor, EncryptedLedger, LedgerEvent
from personal_agent.operations import (
    approve_draft,
    arm_send_canary,
    typing_validate_draft,
)
from personal_agent.runtime import (
    BOOTSTRAP_RECORD_ID,
    DRAFT_NAMESPACE,
    AgentRuntime,
)
from personal_agent.runtime_state import (
    LedgerDistillationRepository,
    PersistentDailyCostLedger,
)
from personal_agent.sender import CanaryGuard, SendResult
from personal_agent.wechat_reader import PollResult, ReadbackBaseline


CONTACT_A = "contact_" + "a" * 32
CONTACT_B = "contact_" + "b" * 32


def _decision(confidence: float = 0.95) -> ReplyDecision:
    return ReplyDecision(
        intent="answer_question",
        stance="可以",
        facts=(),
        commitments=(),
        risk="low",
        confidence=confidence,
        reply_required=True,
        context_sufficient=True,
        reasons=("fixture",),
    )


class _Model:
    def __init__(self, decision: ReplyDecision | None = None) -> None:
        self.decision = decision or _decision()
        self.calls: list[tuple[str, dict]] = []

    def generate_reply_decision(self, text, *, context=None):
        self.calls.append((text, dict(context or {})))
        return self.decision


class _Reader:
    def __init__(
        self,
        *,
        readback: bool = True,
        readback_error: Exception | None = None,
    ) -> None:
        self.poll_calls = 0
        self.readback = readback
        self.readback_error = readback_error
        self.readback_calls = 0
        self.baseline_calls = 0

    def poll(self) -> PollResult:
        self.poll_calls += 1
        return PollResult(discovered_databases=2)

    def readback_baseline(self, contact_key, *, after_epoch=0):
        self.baseline_calls += 1
        return ReadbackBaseline(
            outbound_event_ids=frozenset({"evt_pre_click"}),
            high_watermark=(after_epoch, 1, "evt_pre_click"),
        )

    def readback_confirm(self, contact_key, body, after_epoch, *, baseline=None):
        self.readback_calls += 1
        if baseline is None:
            raise AssertionError("runtime must provide the pre-click readback baseline")
        if self.readback_error is not None:
            raise self.readback_error
        return self.readback


class _Sender:
    def __init__(self, *, clicked: bool = False) -> None:
        self.clicked = clicked
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        return SendResult(
            attempt_id=request.attempt_id,
            backend="fixture",
            action=request.action,
            recipient_verified=True,
            body_verified=True,
            clicked=self.clicked,
            detail="fixture",
        )


class RuntimePipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ledger = EncryptedLedger(self.root / "ledger.sqlite3", b"s" * 32)

    def tearDown(self) -> None:
        self.ledger.close()
        self.temp.cleanup()

    def _config(
        self,
        *,
        mode: str = "shadow",
        real_send: bool = False,
        allowlist: tuple[str, ...] = (),
    ) -> AgentConfig:
        return AgentConfig.from_mapping(
            {
                "schema_version": 2,
                "mode": mode,
                "state_root": str(self.root / "state"),
                "allowlist": list(allowlist),
                "reader": {"db_dir": str(self.root)},
                "model": {
                    "provider": "local",
                    "model": "fixture-model",
                    "base_url": "http://127.0.0.1:11434/v1",
                },
                "cost": {
                    "daily_call_limit": 5,
                    "daily_usd_limit": 1,
                    "per_contact_hourly_limit": 2,
                },
                "sender": {
                    "typing_only": not real_send,
                    "real_send_enabled": real_send,
                },
            }
        )

    def _costs(self, max_calls: int = 5) -> PersistentDailyCostLedger:
        return PersistentDailyCostLedger(
            self.ledger,
            timezone_name="UTC",
            limits=DailyLimits(max_calls=max_calls, max_cost=Decimal("1")),
            pricing={
                ("local", "fixture-model"): ModelPricing(
                    input_per_million=Decimal("1"),
                    output_per_million=Decimal("1"),
                )
            },
        )

    def _runtime(
        self,
        config: AgentConfig,
        model: _Model,
        reader: _Reader,
        sender: _Sender,
        *,
        now=lambda: 2_000_000_000,
        send_preflight=None,
    ) -> AgentRuntime:
        return AgentRuntime(
            config,
            self.ledger,
            reader,  # type: ignore[arg-type]
            self._costs(),
            model_factory=lambda: model,
            sender_factory=lambda: sender,
            send_preflight=send_preflight,
            now=now,
        )

    def _event(
        self,
        local_id: int,
        body: str,
        *,
        contact: str = CONTACT_A,
        direction: str = "inbound",
        display_name: str | None = "虚构联系人甲",
        create_time: int | None = None,
    ) -> LedgerEvent:
        return LedgerEvent(
            event_id=f"evt_{contact[-1]}_{local_id}",
            contact_key=contact,
            direction=direction,
            local_type=1,
            create_time=(
                1_900_000_000 + local_id if create_time is None else create_time
            ),
            local_id=local_id,
            body=body,
            contact_display_name=display_name,
            shard="message/message_0.db",
            table_name="Msg_" + "0" * 32,
        )

    def _ingest(self, *events: LedgerEvent) -> None:
        latest = max((event.create_time, event.local_id) for event in events)
        self.ledger.ingest_events(
            events,
            shard="message/message_0.db",
            table_name="Msg_" + "0" * 32,
            cursor=Cursor(*latest),
        )

    def _bootstrapped(self) -> None:
        self.ledger.append_runtime_record(
            BOOTSTRAP_RECORD_ID,
            "runtime_meta",
            "global",
            "bootstrap",
            {"fixture": True},
        )

    def _enroll_ui_identity(self, contact: str = CONTACT_A) -> str:
        version = DistillationService(
            LedgerDistillationRepository(self.ledger)
        ).create_version(
            RELATIONSHIP,
            {
                "display_name": "虚构联系人甲",
                "ui_search_token": "fixture-unique-search-token-a",
            },
            contact_key=contact,
            confidence=1,
            correction_type=USER_CONFIRMED,
            activate=True,
        )
        return version.version_id

    def _set_relationship_delay(self, seconds: int) -> None:
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        active = service.active(RELATIONSHIP, CONTACT_A)
        assert active is not None
        payload = dict(active.to_dict()["payload"])
        payload["reply_delay_seconds"] = seconds
        service.create_version(
            RELATIONSHIP,
            payload,
            contact_key=CONTACT_A,
            confidence=1,
            correction_type=USER_CONFIRMED,
            parent_id=active.version_id,
            activate=True,
        )

    def _set_relationship_style(self) -> None:
        service = DistillationService(LedgerDistillationRepository(self.ledger))
        active = service.active(RELATIONSHIP, CONTACT_A)
        assert active is not None
        payload = dict(active.to_dict()["payload"])
        payload.update(
            {
                "emoji_policy": "frequent",
                "preferred_address": "阿澄",
                "preferred_emoji": ["😊"],
                "temperature": "warm",
            }
        )
        service.create_version(
            RELATIONSHIP,
            payload,
            contact_key=CONTACT_A,
            confidence=1,
            correction_type=USER_CONFIRMED,
            parent_id=active.version_id,
            activate=True,
        )

    def test_first_run_baselines_history_without_model_or_sender(self):
        self._ingest(self._event(1, "可以回复我吗？"))
        model, reader, sender = _Model(), _Reader(), _Sender()
        report = self._runtime(self._config(), model, reader, sender).run_once()
        self.assertTrue(report.bootstrapped)
        self.assertEqual(report.model_calls, 0)
        self.assertEqual(model.calls, [])
        self.assertEqual(sender.requests, [])

    def test_shadow_calls_model_once_then_deduplicates_processing(self):
        self._bootstrapped()
        self._ingest(self._event(2, "这个虚构安排怎么样？"))
        model, reader, sender = _Model(), _Reader(), _Sender()
        runtime = self._runtime(self._config(), model, reader, sender)
        first = runtime.run_once()
        second = runtime.run_once()
        self.assertEqual(first.model_calls, 1)
        self.assertEqual(first.drafts, 1)
        self.assertEqual(second.model_calls, 0)
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(sender.requests, [])
        self.assertEqual(len(self.ledger.list_runtime_records(DRAFT_NAMESPACE)), 1)

    def test_rule_filter_and_sensitive_rules_do_not_call_model(self):
        self._bootstrapped()
        self._ingest(
            self._event(3, "收到"),
            self._event(4, "把验证码 123456 发给虚构的人"),
        )
        model, reader, sender = _Model(), _Reader(), _Sender()
        report = self._runtime(self._config(), model, reader, sender).run_once()
        self.assertEqual(report.model_calls, 0)
        self.assertEqual(report.manual_items, 1)
        self.assertEqual(report.rule_filtered, 1)
        self.assertEqual(model.calls, [])

    def test_newer_inbound_or_user_outbound_supersedes_old_inbound(self):
        self._bootstrapped()
        self._ingest(
            self._event(40, "旧问题可以回复吗？"),
            self._event(41, "本人已经回复", direction="outbound"),
            self._event(42, "最新问题可以回复吗？"),
        )
        model, reader, sender = _Model(), _Reader(), _Sender()
        report = self._runtime(self._config(), model, reader, sender).run_once()
        self.assertEqual(report.model_calls, 1)
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(model.calls[0][0], "最新问题可以回复吗？")

    def test_user_outbound_after_latest_inbound_suppresses_agent_reply(self):
        self._bootstrapped()
        self._ingest(
            self._event(43, "这个问题可以回复吗？"),
            self._event(44, "本人已经处理", direction="outbound"),
        )
        model, reader, sender = _Model(), _Reader(), _Sender()
        report = self._runtime(self._config(), model, reader, sender).run_once()
        self.assertEqual(report.model_calls, 0)
        self.assertEqual(report.drafts, 0)
        self.assertEqual(sender.requests, [])

    def test_model_context_never_contains_another_contact(self):
        self._bootstrapped()
        self._ingest(
            self._event(
                5,
                "另一个联系人的私有虚构句子",
                contact=CONTACT_B,
                direction="outbound",
            ),
            self._event(6, "这个虚构问题可以回答吗？", contact=CONTACT_A),
        )
        model, reader, sender = _Model(), _Reader(), _Sender()
        self._runtime(self._config(), model, reader, sender).run_once()
        context = model.calls[0][1]
        self.assertEqual(context["contact_key"], CONTACT_A)
        self.assertNotIn(
            "另一个联系人的私有虚构句子",
            str(context),
        )

    def test_structured_decision_is_rendered_with_only_current_contact_style(self):
        self._bootstrapped()
        self._enroll_ui_identity()
        self._set_relationship_style()
        self._ingest(self._event(49, "这个虚构问题可以回答吗？"))
        model, reader, sender = _Model(_decision(0.95)), _Reader(), _Sender()

        report = self._runtime(self._config(), model, reader, sender).run_once()

        self.assertEqual(report.drafts, 1)
        draft = self.ledger.list_runtime_records(DRAFT_NAMESPACE, kind="draft")[-1]
        self.assertEqual(draft.payload["body"], "阿澄，可以😊")
        self.assertNotIn("另一个联系人", str(draft.payload))

    def test_autopilot_logic_with_real_send_disabled_never_loads_sender(self):
        self._bootstrapped()
        self._ingest(self._event(7, "这个低风险虚构问题可以回答吗？"))
        model, reader, sender = (
            _Model(_decision(0.99)),
            _Reader(),
            _Sender(clicked=True),
        )
        report = self._runtime(
            self._config(mode="autopilot", allowlist=(CONTACT_A,)),
            model,
            reader,
            sender,
        ).run_once()
        self.assertEqual(report.drafts, 1)
        self.assertEqual(report.send_attempts, 0)
        self.assertEqual(sender.requests, [])

    def test_model_stance_cannot_bypass_rendered_body_safety(self):
        self._bootstrapped()
        self._ingest(self._event(45, "这个虚构问题可以回答吗？"))
        unsafe = ReplyDecision(
            intent="answer_question",
            stance="我确认替你签署合同并披露隐私资料",
            facts=(),
            commitments=(),
            risk="low",
            confidence=0.99,
            reply_required=True,
            context_sufficient=True,
            reasons=("synthetic_adversarial_stance",),
        )
        model, reader, sender = _Model(unsafe), _Reader(), _Sender(clicked=True)
        report = self._runtime(
            self._config(
                mode="autopilot",
                real_send=True,
                allowlist=(CONTACT_A,),
            ),
            model,
            reader,
            sender,
        ).run_once()
        self.assertEqual(report.send_attempts, 0)
        self.assertEqual(sender.requests, [])

    def test_non_canned_invented_stance_is_draft_only_in_autopilot(self):
        self._bootstrapped()
        self._ingest(self._event(46, "这个虚构问题可以回答吗？"))
        invented = ReplyDecision(
            intent="answer_question",
            stance="虚构航班已改到明天上午九点",
            facts=(),
            commitments=(),
            risk="low",
            confidence=0.99,
            reply_required=True,
            context_sufficient=True,
            reasons=("synthetic_invented_stance",),
        )
        model, reader, sender = _Model(invented), _Reader(), _Sender(clicked=True)
        report = self._runtime(
            self._config(
                mode="autopilot",
                real_send=True,
                allowlist=(CONTACT_A,),
            ),
            model,
            reader,
            sender,
        ).run_once()
        self.assertEqual(report.drafts, 1)
        self.assertEqual(report.send_attempts, 0)
        self.assertEqual(sender.requests, [])

    def test_synthetic_click_requires_readback_and_is_never_retried(self):
        self._bootstrapped()
        self._enroll_ui_identity()
        self._ingest(self._event(8, "这个低风险虚构问题可以回答吗？"))
        model = _Model(_decision(0.99))
        reader = _Reader(readback=False)
        sender = _Sender(clicked=True)
        report = self._runtime(
            self._config(
                mode="autopilot",
                real_send=True,
                allowlist=(CONTACT_A,),
            ),
            model,
            reader,
            sender,
        ).run_once()
        self.assertEqual(report.send_attempts, 1)
        self.assertEqual(report.sends_confirmed, 0)
        self.assertEqual(reader.baseline_calls, 1)
        self.assertEqual(reader.readback_calls, 1)
        self.assertEqual(len(sender.requests), 1)

    def test_real_send_waits_for_explicit_draft_bound_canary(self):
        self._bootstrapped()
        self._enroll_ui_identity()
        now = int(datetime.now(timezone.utc).timestamp())
        self._ingest(
            self._event(
                48,
                "这个低风险虚构问题可以回答吗？",
                create_time=now,
            )
        )
        config = self._config(
            mode="autopilot",
            real_send=True,
            allowlist=(CONTACT_A,),
        )
        model = _Model(_decision(0.99))
        reader = _Reader(readback=True)
        sender = _Sender(clicked=True)
        secrets = MemorySecretStore()
        preflight = CanaryGuard(
            secrets,
            config.sender.canary_ref,
        ).is_authorized
        runtime = self._runtime(
            config,
            model,
            reader,
            sender,
            now=lambda: now,
            send_preflight=preflight,
        )

        first = runtime.run_once()
        self.assertEqual(first.send_attempts, 0)
        self.assertEqual(sender.requests, [])
        draft = self.ledger.list_runtime_records(DRAFT_NAMESPACE, kind="draft")[-1]
        arm_send_canary(
            config,
            self.ledger,
            draft.record_id,
            confirmation="SEND_ONCE",
            expires_seconds=120,
            secrets=secrets,
            now_epoch=now,
        )

        second = runtime.run_once()
        self.assertEqual(second.model_calls, 0)
        self.assertEqual(second.send_attempts, 1)
        self.assertEqual(second.sends_confirmed, 1)
        self.assertEqual(len(sender.requests), 1)

    def test_relationship_delay_is_persistent_and_revalidated_without_new_model_call(
        self,
    ):
        self._bootstrapped()
        self._enroll_ui_identity()
        self._set_relationship_delay(60)
        clock = [2_000_000_000]
        self._ingest(
            self._event(
                47,
                "这个低风险虚构问题可以回答吗？",
                create_time=clock[0],
            )
        )
        model = _Model(_decision(0.99))
        reader = _Reader(readback=True)
        sender = _Sender(clicked=True)
        runtime = self._runtime(
            self._config(
                mode="autopilot",
                real_send=True,
                allowlist=(CONTACT_A,),
            ),
            model,
            reader,
            sender,
            now=lambda: clock[0],
        )

        first = runtime.run_once()
        self.assertEqual(first.drafts, 1)
        self.assertEqual(first.send_attempts, 0)
        self.assertEqual(sender.requests, [])

        clock[0] += 61
        second = runtime.run_once()
        self.assertEqual(second.model_calls, 0)
        self.assertEqual(second.send_attempts, 1)
        self.assertEqual(second.sends_confirmed, 1)
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(len(sender.requests), 1)

        self.assertEqual(runtime.run_once().send_attempts, 0)
        self.assertEqual(len(sender.requests), 1)
        self.assertEqual(
            self._runtime(
                self._config(
                    mode="autopilot",
                    real_send=True,
                    allowlist=(CONTACT_A,),
                ),
                model,
                reader,
                sender,
            )
            .run_once()
            .send_attempts,
            0,
        )
        self.assertEqual(len(sender.requests), 1)

    def test_readback_error_is_terminal_and_never_retried(self):
        self._bootstrapped()
        self._enroll_ui_identity()
        self._ingest(self._event(9, "这个低风险虚构问题可以回答吗？"))
        model = _Model(_decision(0.99))
        reader = _Reader(readback_error=OSError("synthetic readback failure"))
        sender = _Sender(clicked=True)
        runtime = self._runtime(
            self._config(
                mode="autopilot",
                real_send=True,
                allowlist=(CONTACT_A,),
            ),
            model,
            reader,
            sender,
        )

        first = runtime.run_once()
        self.assertEqual(first.send_attempts, 1)
        self.assertEqual(first.sends_confirmed, 0)
        attempt = self.ledger.get_send_attempt(sender.requests[0].attempt_id)
        self.assertIsNotNone(attempt)
        assert attempt is not None
        self.assertEqual(attempt.status, "failed")

        self.assertEqual(
            runtime.run_once().send_attempts,
            0,
        )
        self.assertEqual(reader.readback_calls, 1)
        self.assertEqual(len(sender.requests), 1)


class PersistenceAndApprovalTests(unittest.TestCase):
    def test_runtime_records_distillation_and_cost_survive_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.sqlite3"
            key = b"p" * 32
            with EncryptedLedger(path, key) as ledger:
                service = DistillationService(LedgerDistillationRepository(ledger))
                first = service.create_version(
                    LANGUAGE_STYLE,
                    {"length": "short"},
                    confidence=0.8,
                    activate=True,
                )
                second = service.create_version(
                    LANGUAGE_STYLE,
                    {"length": "normal"},
                    confidence=0.9,
                    activate=True,
                )
                service.rollback(LANGUAGE_STYLE, first.version_id)
                costs = PersistentDailyCostLedger(
                    ledger,
                    timezone_name="UTC",
                    limits=DailyLimits(max_calls=1, max_cost=Decimal("1")),
                    pricing={
                        ("local", "fixture"): ModelPricing(Decimal("1"), Decimal("1"))
                    },
                    clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
                )
                reservation = costs.reserve("local", "fixture", 10, 10)
                costs.refund(reservation.reservation_id)
                self.assertEqual(costs.snapshot().calls, 1)
                with self.assertRaises(BudgetExceededError):
                    costs.reserve("local", "fixture", 1, 1)
                self.assertNotEqual(first.version_id, second.version_id)
            with EncryptedLedger(path, key) as restarted:
                service = DistillationService(LedgerDistillationRepository(restarted))
                self.assertEqual(
                    service.active(LANGUAGE_STYLE).version_id,
                    first.version_id,
                )
                self.assertTrue(restarted.verify_audit_chain())
                self.assertNotIn(b'"length":"short"', path.read_bytes())

    def test_relationship_versions_are_isolated_after_restart(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.sqlite3"
            with EncryptedLedger(path, b"r" * 32) as ledger:
                service = DistillationService(LedgerDistillationRepository(ledger))
                service.create_version(
                    RELATIONSHIP,
                    {"display_name": "虚构甲", "boundary": "不谈虚构事项"},
                    contact_key=CONTACT_A,
                    confidence=1,
                    correction_type=USER_CONFIRMED,
                    activate=True,
                )
                self.assertIsNone(service.active(RELATIONSHIP, CONTACT_B))

    def test_typing_validation_consumes_short_lived_approval_without_click(self):
        with tempfile.TemporaryDirectory() as temp:
            config = AgentConfig.from_mapping(
                {"schema_version": 2, "state_root": temp, "mode": "approve"}
            )
            with EncryptedLedger(Path(temp) / "ledger.sqlite3", b"t" * 32) as ledger:
                identity = DistillationService(
                    LedgerDistillationRepository(ledger)
                ).create_version(
                    RELATIONSHIP,
                    {
                        "display_name": "虚构联系人甲",
                        "ui_search_token": "fixture-unique-search-token-a",
                    },
                    contact_key=CONTACT_A,
                    confidence=1,
                    correction_type=USER_CONFIRMED,
                    activate=True,
                )
                ledger.append_runtime_record(
                    "draft_fixture",
                    DRAFT_NAMESPACE,
                    CONTACT_A,
                    "draft",
                    {
                        "body": "虚构草稿",
                        "contact_label": "虚构联系人甲",
                        "contact_search_token": "fixture-unique-search-token-a",
                        "context_hash": "abc",
                        "event_id": "evt_fixture",
                        "status": "approval_required",
                        "gate": {
                            "action": "approval_required",
                            "mode": "approve",
                        },
                        "ui_identity_verified": True,
                        "ui_identity_version_id": identity.version_id,
                    },
                )
                approve_draft(config, ledger, "draft_fixture")
                sender = _Sender(clicked=False)
                result = typing_validate_draft(
                    config,
                    ledger,
                    "draft_fixture",
                    sender=sender,
                )
                self.assertFalse(result["clicked"])
                self.assertFalse(result["real_send"])
                with self.assertRaisesRegex(ValueError, "already consumed"):
                    typing_validate_draft(
                        config,
                        ledger,
                        "draft_fixture",
                        sender=sender,
                    )

    def test_shadow_and_draft_only_cannot_reach_typing_sender(self):
        with tempfile.TemporaryDirectory() as temp:
            config = AgentConfig.from_mapping({"schema_version": 2, "state_root": temp})
            with EncryptedLedger(Path(temp) / "ledger.sqlite3", b"u" * 32) as ledger:
                ledger.append_runtime_record(
                    "draft_shadow_fixture",
                    DRAFT_NAMESPACE,
                    CONTACT_A,
                    "draft",
                    {
                        "body": "虚构 Shadow 草稿",
                        "contact_label": "虚构联系人甲",
                        "context_hash": "abc",
                        "event_id": "evt_shadow_fixture",
                        "status": "draft_only",
                        "gate": {"action": "draft_only", "mode": "shadow"},
                    },
                )
                with self.assertRaisesRegex(ValueError, "approve mode"):
                    approve_draft(config, ledger, "draft_shadow_fixture")
                with self.assertRaisesRegex(ValueError, "approve mode"):
                    typing_validate_draft(
                        config,
                        ledger,
                        "draft_shadow_fixture",
                        sender=_Sender(clicked=False),
                    )


if __name__ == "__main__":
    unittest.main()
