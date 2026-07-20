from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from personal_agent.builder import build_bundle
from personal_agent.cli import main as cli_main
from personal_agent.emotion_cycle import calculate_emotion_cycle
from personal_agent.ingest import normalize_exports
from personal_agent.policy import review_draft, stage_draft, triage_pending_inbound
from personal_agent.schema import MessageEvent


TIMEZONE = ZoneInfo("Asia/Shanghai")


def _write_export(path: Path, messages, declared_count=None) -> None:
    payload = {
        "format": "wechat_chat_export_v1",
        "contact_wxid": "wxid_private_contact",
        "contact_name": "测试联系人",
        "self_wxid": "wxid_private_self",
        "message_count": len(messages) if declared_count is None else declared_count,
        "source_databases": ["message_0.db"],
        "messages": messages,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _event(
    event_id: str,
    occurred: datetime,
    direction: str,
    text: str,
    message_type: str = "1",
) -> MessageEvent:
    return MessageEvent(
        event_id=event_id,
        occurred_at=occurred.isoformat(timespec="seconds"),
        epoch_seconds=int(occurred.timestamp()),
        epoch_microseconds=int(occurred.timestamp() * 1_000_000),
        contact_key="contact_test",
        contact_label="测试联系人",
        direction=direction,
        message_type=message_type,
        text=text,
        source_id="sha256:test",
        source_sequence=int(event_id.rsplit("_", 1)[-1]),
    )


class PersonalAgentIngestTests(unittest.TestCase):
    def test_normalize_export_removes_wxids_and_preserves_directions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "export.json"
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "datetime": base.strftime("%Y-%m-%d %H:%M:%S"),
                        "sender": "我",
                        "is_sender": 1,
                        "type": 1,
                        "content": "早上好请加wxid_hidden1234谢谢",
                    },
                    {
                        "timestamp": int((base + timedelta(minutes=1)).timestamp()),
                        "datetime": (base + timedelta(minutes=1)).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "sender": "测试联系人",
                        "is_sender": 0,
                        "type": 1,
                        "content": "早",
                    },
                ],
            )

            events, sources = normalize_exports([path], b"x" * 32)

            self.assertEqual(
                [event.direction for event in events], ["outbound", "inbound"]
            )
            self.assertEqual(sources[0].message_count, 2)
            serialized = json.dumps(
                [event.to_dict() for event in events] + [sources[0].to_dict()],
                ensure_ascii=False,
            )
            self.assertNotIn("wxid_private_contact", serialized)
            self.assertNotIn("wxid_private_self", serialized)
            self.assertNotIn("wxid_hidden1234", serialized)
            self.assertIn("[redacted_wxid]", events[0].text)
            self.assertTrue(events[0].contact_key.startswith("contact_"))

    def test_overlapping_append_only_exports_deduplicate_stably(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first.json"
            second = root / "second.json"
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            shared = {
                "timestamp": int(base.timestamp()),
                "is_sender": 1,
                "type": 1,
                "content": "同一条消息",
            }
            _write_export(first, [shared])
            _write_export(
                second,
                [
                    shared,
                    {
                        "timestamp": int((base + timedelta(minutes=1)).timestamp()),
                        "is_sender": 0,
                        "type": 1,
                        "content": "新增消息",
                    },
                ],
            )

            first_events, _ = normalize_exports([first], b"x" * 32)
            merged_events, sources = normalize_exports([first, second], b"x" * 32)

            self.assertEqual(len(merged_events), 2)
            self.assertEqual(first_events[0].event_id, merged_events[0].event_id)
            self.assertEqual([source.message_count for source in sources], [1, 2])

    def test_same_second_message_order_is_preserved_for_triage(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        replied = [
            _event("evt_1", base, "inbound", "在吗？"),
            _event("evt_2", base, "outbound", "在"),
        ]
        awaiting_reply = [
            _event("evt_1", base, "outbound", "在"),
            _event("evt_2", base, "inbound", "方便吗？"),
        ]

        self.assertEqual(triage_pending_inbound(replied), [])
        self.assertEqual(len(triage_pending_inbound(awaiting_reply)), 1)

    def test_z_datetime_and_invalid_sender_handling(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "export.json"
            _write_export(
                path,
                [
                    {
                        "datetime": "2026-01-01T01:00:00Z",
                        "is_sender": 1,
                        "type": 1,
                        "content": "有效",
                    },
                    {
                        "datetime": "2026-01-01T01:01:00Z",
                        "is_sender": 2,
                        "type": 1,
                        "content": "方向不明",
                    },
                ],
            )

            events, sources = normalize_exports([path], b"x" * 32)

            self.assertEqual(len(events), 1)
            self.assertIn("+08:00", events[0].occurred_at)
            self.assertTrue(
                any(
                    "unsupported is_sender" in warning
                    for warning in sources[0].warnings
                )
            )

    def test_normalize_export_rejects_unknown_format(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text('{"format":"unknown","messages":[]}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Unsupported export format"):
                normalize_exports([path], b"x" * 32)

    def test_normalize_legacy_full_export(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "legacy_chat_full.json"
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            path.write_text(
                json.dumps(
                    [
                        {
                            "create_time": int(base.timestamp()),
                            "sender": "历史联系人",
                            "is_sender": 0,
                            "local_type": 1,
                            "content": "旧格式消息",
                        }
                    ],
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            events, sources = normalize_exports([path], b"x" * 32)

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].contact_label, "历史联系人")
            self.assertEqual(events[0].message_type, "1")
            self.assertEqual(sources[0].format, "ginger_chat_full_v0")
            self.assertTrue(sources[0].warnings)


class EmotionCycleTests(unittest.TestCase):
    def test_cycle_uses_only_outbound_text_and_exposes_confidence(self):
        base = datetime(2026, 1, 1, 1, 0, tzinfo=TIMEZONE)
        events = [
            _event("evt_1", base, "outbound", "今天很开心，谢谢你！"),
            _event("evt_2", base + timedelta(hours=1), "inbound", "我非常难过焦虑"),
            _event("evt_3", base + timedelta(hours=9), "outbound", "可能晚点再说"),
            _event("evt_4", base + timedelta(hours=10), "outbound", "图片", "3"),
        ]

        result = calculate_emotion_cycle(events)

        self.assertEqual(result["summary"]["outbound_text_messages"], 2)
        self.assertEqual(result["daily"][0]["message_count"], 2)
        self.assertGreater(result["daily"][0]["metrics"]["valence"], 0)
        self.assertGreater(result["daily"][0]["metrics"]["late_night_share"], 0)
        self.assertEqual(result["daily"][0]["confidence_label"], "low")
        self.assertIn("No clinical", " ".join(result["methodology"]["limitations"]))

    def test_low_sample_day_is_never_anomaly_scored(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        events = []
        event_number = 1
        for day in range(7):
            for message in range(5):
                events.append(
                    _event(
                        f"evt_{event_number}",
                        base + timedelta(days=day, minutes=message),
                        "outbound",
                        "今天状态平稳，按计划处理事情。",
                    )
                )
                event_number += 1
        events.append(
            _event(
                f"evt_{event_number}",
                base + timedelta(days=7),
                "outbound",
                "崩溃！",
            )
        )

        result = calculate_emotion_cycle(events)
        latest = result["daily"][-1]

        self.assertFalse(latest["valid_for_trend"])
        self.assertTrue(all(value is None for value in latest["baseline_z"].values()))
        self.assertEqual(latest["anomaly_flags"], [])

    def test_low_confidence_day_is_not_valid_despite_volume_thresholds(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        events = [
            _event(
                f"evt_{index + 1}",
                base + timedelta(minutes=index),
                "outbound",
                "这是普通内容没有词典信号",
            )
            for index in range(5)
        ]

        latest = calculate_emotion_cycle(events)["daily"][0]

        self.assertGreaterEqual(latest["character_count"], 40)
        self.assertLess(latest["confidence"], 0.45)
        self.assertFalse(latest["valid_for_trend"])


class ApprovalPolicyTests(unittest.TestCase):
    def test_sensitive_pending_message_never_enables_send(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        events = [
            _event("evt_1", base, "outbound", "收到"),
            _event(
                "evt_2",
                base + timedelta(minutes=1),
                "inbound",
                "请马上转账给我，可以吗？",
            ),
        ]

        queue = triage_pending_inbound(events)
        draft = stage_draft(
            queue[0], "我先核对信息，稍后手动回复。", now="2026-01-01T01:02:00+00:00"
        )
        reviewed = review_draft(
            draft,
            "approve",
            actor="user",
            now="2026-01-01T01:03:00+00:00",
        )

        self.assertEqual(queue[0]["tier"], "sensitive")
        self.assertIn("money", queue[0]["sensitive_categories"])
        self.assertFalse(queue[0]["send_allowed"])
        self.assertEqual(draft["status"], "pending_approval")
        self.assertEqual(reviewed["status"], "approved_for_manual_copy")
        self.assertFalse(reviewed["send_allowed"])
        self.assertIsNone(reviewed["transport_action"])

    def test_common_word_possibility_does_not_trigger_intimacy_rule(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        queue = triage_pending_inbound(
            [_event("evt_1", base, "inbound", "这个方案有可能性，你觉得呢？")]
        )

        self.assertEqual(queue[0]["tier"], "action_required")
        self.assertNotIn("conflict_or_intimacy", queue[0]["sensitive_categories"])

    def test_draft_nonce_prevents_same_second_id_collision(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        queue_item = triage_pending_inbound(
            [_event("evt_1", base, "inbound", "请回复")]
        )[0]

        first = stage_draft(queue_item, "同一草稿", now="2026-01-01T01:00:00+00:00")
        second = stage_draft(queue_item, "同一草稿", now="2026-01-01T01:00:00+00:00")

        self.assertNotEqual(first["draft_id"], second["draft_id"])

    def test_review_rejects_tampered_draft_text(self):
        base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
        queue_item = triage_pending_inbound(
            [_event("evt_1", base, "inbound", "请回复")]
        )[0]
        draft = stage_draft(
            queue_item,
            "原始草稿",
            now="2026-01-01T01:00:00+00:00",
        )
        draft["text"] = "被修改的草稿"

        with self.assertRaisesRegex(ValueError, "content hash"):
            review_draft(
                draft,
                "approve",
                now="2026-01-01T01:01:00+00:00",
            )


class BundleBuilderTests(unittest.TestCase):
    def test_build_bundle_is_private_and_loads_only_descriptive_yourself_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_path = root / "export.json"
            state_dir = root / "state"
            skill_dir = root / "my-self"
            skill_dir.mkdir()
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                export_path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "is_sender": 1,
                        "type": 1,
                        "content": "今天很开心",
                    },
                    {
                        "timestamp": int((base + timedelta(minutes=1)).timestamp()),
                        "is_sender": 0,
                        "type": 1,
                        "content": "可以帮我确认一下吗？",
                    },
                ],
            )
            (skill_dir / "meta.json").write_text(
                json.dumps({"name": "Steve", "version": "v1"}), encoding="utf-8"
            )
            (skill_dir / "self.md").write_text(
                "重视事实和可验证证据。", encoding="utf-8"
            )
            (skill_dir / "persona.md").write_text(
                "表达直接，先给结论。", encoding="utf-8"
            )
            (skill_dir / "SKILL.md").write_text(
                "你是 Steve，不是 AI。", encoding="utf-8"
            )

            manifest = build_bundle([export_path], state_dir, yourself_skill=skill_dir)

            self.assertEqual(manifest["schema"], "ginger_personal_agent_bundle_v1")
            self.assertFalse(manifest["transport_send_allowed"])
            self.assertFalse(manifest["privacy"]["message_text_retained_locally"])
            self.assertEqual(
                (state_dir / ".ginger-personal-agent-state")
                .read_text(encoding="ascii")
                .strip(),
                "ginger_personal_agent_bundle_v1",
            )
            self.assertEqual(
                (state_dir / ".gitignore").read_text(encoding="utf-8"),
                "*\n!.gitignore\n",
            )
            self.assertEqual(state_dir.stat().st_mode & 0o777, 0o700)
            for path in state_dir.iterdir():
                if path.is_file():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600, path.name)
            style_context = (state_dir / "style_context.md").read_text(encoding="utf-8")
            self.assertIn("descriptive reference data", style_context)
            self.assertIn("重视事实", style_context)
            self.assertNotIn("不是 AI", style_context)
            event_text = (state_dir / "events.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("wxid_private_contact", event_text)
            self.assertNotIn("今天很开心", event_text)
            self.assertIn('"text": null', event_text)
            dashboard = (state_dir / "emotion_dashboard.html").read_text(
                encoding="utf-8"
            )
            self.assertIn("Ginger Personal Agent", dashboard)
            self.assertIn("外发能力：关闭", dashboard)
            self.assertNotIn("今天很开心", dashboard)
            self.assertNotIn("<script", dashboard)

    def test_plaintext_retention_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_path = root / "export.json"
            state_dir = root / "state"
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                export_path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "is_sender": 1,
                        "type": 1,
                        "content": "保留正文",
                    }
                ],
            )

            manifest = build_bundle(
                [export_path],
                state_dir,
                retain_message_text=True,
            )

            self.assertTrue(manifest["privacy"]["message_text_retained_locally"])
            self.assertIn(
                "保留正文",
                (state_dir / "events.jsonl").read_text(encoding="utf-8"),
            )

    def test_existing_unmanaged_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_path = root / "export.json"
            state_dir = root / "existing"
            state_dir.mkdir()
            (state_dir / "unrelated.txt").write_text(
                "do not overwrite", encoding="utf-8"
            )
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                export_path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "is_sender": 1,
                        "type": 1,
                        "content": "消息",
                    }
                ],
            )

            with self.assertRaisesRegex(ValueError, "unknown files"):
                build_bundle([export_path], state_dir)

            self.assertEqual(
                (state_dir / "unrelated.txt").read_text(encoding="utf-8"),
                "do not overwrite",
            )

    def test_symbolic_link_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_path = root / "export.json"
            real_dir = root / "real"
            link_dir = root / "state-link"
            real_dir.mkdir()
            link_dir.symlink_to(real_dir, target_is_directory=True)
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                export_path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "is_sender": 1,
                        "type": 1,
                        "content": "消息",
                    }
                ],
            )

            with self.assertRaisesRegex(ValueError, "symbolic-link state directory"):
                build_bundle([export_path], link_dir)

    def test_rebuild_preserves_review_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_path = root / "export.json"
            state_dir = root / "state"
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                export_path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "is_sender": 0,
                        "type": 1,
                        "content": "请回复",
                    }
                ],
            )
            build_bundle([export_path], state_dir)
            preserved = [{"draft_id": "draft_preserved", "status": "rejected"}]
            (state_dir / "drafts.json").write_text(
                json.dumps(preserved, ensure_ascii=False), encoding="utf-8"
            )

            build_bundle([export_path], state_dir)

            self.assertEqual(
                json.loads((state_dir / "drafts.json").read_text(encoding="utf-8")),
                preserved,
            )
            self.assertEqual((state_dir / "drafts.json").stat().st_mode & 0o777, 0o600)


class PersonalAgentCliTests(unittest.TestCase):
    def test_draft_reject_flow_has_stable_audit_name_and_no_send(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            export_path = root / "export.json"
            state_dir = root / "state"
            draft_path = root / "draft.txt"
            base = datetime(2026, 1, 1, 9, 0, tzinfo=TIMEZONE)
            _write_export(
                export_path,
                [
                    {
                        "timestamp": int(base.timestamp()),
                        "is_sender": 0,
                        "type": 1,
                        "content": "请回复",
                    }
                ],
            )
            draft_path.write_text("稍后回复。", encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "build",
                            "--export",
                            str(export_path),
                            "--output",
                            str(state_dir),
                        ]
                    ),
                    0,
                )
            queue_id = json.loads(
                (state_dir / "triage_queue.json").read_text(encoding="utf-8")
            )[0]["queue_id"]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "draft",
                            "--state",
                            str(state_dir),
                            "--queue-id",
                            queue_id,
                            "--text-file",
                            str(draft_path),
                        ]
                    ),
                    0,
                )
            draft_id = json.loads(
                (state_dir / "drafts.json").read_text(encoding="utf-8")
            )[0]["draft_id"]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    cli_main(
                        [
                            "review",
                            "--state",
                            str(state_dir),
                            "--draft-id",
                            draft_id,
                            "--decision",
                            "reject",
                        ]
                    ),
                    0,
                )

            reviewed = json.loads(
                (state_dir / "drafts.json").read_text(encoding="utf-8")
            )[0]
            audit_rows = [
                json.loads(line)
                for line in (state_dir / "audit.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(reviewed["status"], "rejected")
            self.assertFalse(reviewed["send_allowed"])
            self.assertEqual(audit_rows[-1]["action"], "draft_rejected")


if __name__ == "__main__":
    unittest.main()
