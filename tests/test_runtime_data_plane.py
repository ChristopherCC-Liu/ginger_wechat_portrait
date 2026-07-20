from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from personal_agent.crypto_store import (
    AESGCMEnvelope,
    InvalidEnvelopeError,
    MacOSKeychain,
    MemorySecretStore,
    SecretStoreError,
)
from personal_agent.ledger import (
    Cursor,
    DuplicateSendError,
    IdempotencyConflictError,
    InvalidSendTransitionError,
    Ledger,
    LedgerEvent,
)
from personal_agent.wechat_reader import (
    SQLCipherCLIQuery,
    WeChatReader,
    ZSTD_UNAVAILABLE_MARKER,
    validate_message_table,
)


MASTER_KEY = b"k" * 32
IDENTITY_SECRET = b"i" * 32


def _message_table(username: str) -> str:
    digest = hashlib.md5(
        username.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return f"Msg_{digest}"


def _create_message_database(
    path: Path,
    *,
    contact_username: str,
    self_username: str,
    rows: list[tuple[int, int, int, str, bytes, int]],
    include_invalid_table: bool = False,
) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    table = _message_table(contact_username)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE Name2Id(user_name TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO Name2Id(user_name) VALUES (?)",
            [(contact_username,), (self_username,)],
        )
        connection.execute(
            f'CREATE TABLE "{table}"('
            "local_id INTEGER NOT NULL, "
            "local_type INTEGER NOT NULL, "
            "create_time INTEGER NOT NULL, "
            "real_sender_id INTEGER, "
            "message_content BLOB, "
            "WCDB_CT_message_content INTEGER NOT NULL DEFAULT 0)"
        )
        for local_id, local_type, create_time, sender, content, compression in rows:
            sender_id = 1 if sender == "contact" else 2
            connection.execute(
                f'INSERT INTO "{table}"('
                "local_id, local_type, create_time, real_sender_id, "
                "message_content, WCDB_CT_message_content"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    local_id,
                    local_type,
                    create_time,
                    sender_id,
                    content,
                    compression,
                ),
            )
        if include_invalid_table:
            connection.execute(
                'CREATE TABLE "Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;DROP"(x INTEGER)'
            )
        connection.commit()
    return table


def _append_message(
    path: Path,
    table: str,
    *,
    local_id: int,
    create_time: int,
    sender_id: int,
    body: bytes,
) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            f'INSERT INTO "{table}"('
            "local_id, local_type, create_time, real_sender_id, "
            "message_content, WCDB_CT_message_content"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (local_id, 1, create_time, sender_id, body, 0),
        )
        connection.commit()


class CryptoStoreTests(unittest.TestCase):
    def test_versioned_aes_gcm_envelope_authenticates_and_hides_plaintext(self):
        plaintext = "私密正文-for-envelope".encode()
        codec = AESGCMEnvelope(MASTER_KEY)

        envelope = codec.encrypt(plaintext, aad=b"row:event-1")

        self.assertNotIn(plaintext, envelope)
        self.assertEqual(json.loads(envelope)["v"], 1)
        self.assertEqual(codec.decrypt(envelope, aad=b"row:event-1"), plaintext)
        with self.assertRaises(InvalidEnvelopeError):
            codec.decrypt(envelope, aad=b"row:event-2")
        with self.assertRaises(ValueError):
            AESGCMEnvelope(b"short")

        tampered = bytearray(envelope)
        tampered[-3] = ord("A") if tampered[-3] != ord("A") else ord("B")
        with self.assertRaises(InvalidEnvelopeError):
            codec.decrypt(bytes(tampered), aad=b"row:event-1")

    def test_memory_store_and_keychain_keep_secret_out_of_argv(self):
        secret = b"binary-secret\x00value"
        memory = MemorySecretStore()
        memory.set_secret("ledger", secret)
        self.assertEqual(memory.get_secret("ledger"), secret)

        calls: list[tuple[list[str], bytes | None]] = []
        stored = b""

        def fake_runner(argv, **kwargs):
            nonlocal stored
            stdin = kwargs.get("input")
            calls.append((list(argv), stdin))
            if argv[1] == "add-generic-password":
                stored = stdin
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return subprocess.CompletedProcess(argv, 0, stored, b"")

        keychain = MacOSKeychain("test.personal-agent", runner=fake_runner)
        keychain.set_secret("ledger", secret)
        self.assertEqual(keychain.get_secret("ledger"), secret)

        write_argv, write_stdin = calls[0]
        self.assertEqual(write_argv[0], "/usr/bin/security")
        self.assertEqual(write_argv[-1], "-w")
        self.assertNotIn(secret, "\x00".join(write_argv).encode())
        self.assertIsNotNone(write_stdin)
        self.assertNotEqual(write_stdin, b"")
        self.assertEqual(calls[1][0][1], "find-generic-password")
        self.assertEqual(calls[1][0][-1], "-w")

    def test_keychain_failure_does_not_echo_process_output(self):
        secret = b"must-not-escape"

        def failed_runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, secret, secret)

        keychain = MacOSKeychain("test.personal-agent", runner=failed_runner)
        with self.assertRaises(SecretStoreError) as captured:
            keychain.set_secret(secret)
        self.assertNotIn(secret.decode(), str(captured.exception))


class LedgerTests(unittest.TestCase):
    def _event(self, event_id: str, body: str = "私密消息") -> LedgerEvent:
        return LedgerEvent(
            event_id=event_id,
            contact_key="contact_test",
            direction="inbound",
            local_type=1,
            create_time=1_000,
            local_id=1,
            body=body,
            contact_display_name="联系人显示名",
            shard="message/message_0.db",
            table_name="Msg_" + "a" * 32,
            payload={"draft_context": "草稿上下文"},
        )

    def test_atomic_ingest_dedup_cursor_restart_and_encrypted_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ledger.db"
            ledger = Ledger(path, MASTER_KEY)
            event = self._event("evt_one")

            self.assertEqual(
                ledger.ingest_events(
                    [event],
                    shard=event.shard,
                    table_name=event.table_name,
                    cursor=(event.create_time, event.local_id),
                ),
                1,
            )
            self.assertEqual(
                ledger.ingest_events(
                    [event],
                    shard=event.shard,
                    table_name=event.table_name,
                    cursor=(event.create_time, event.local_id),
                ),
                0,
            )
            self.assertEqual(
                ledger.get_cursor(event.shard, event.table_name),
                Cursor(1_000, 1),
            )
            self.assertEqual(list(ledger.iter_recent_events())[0].body, "私密消息")
            self.assertTrue(ledger.verify_audit_chain())
            ledger.close()

            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            file_bytes = path.read_bytes()
            for plaintext in ("私密消息", "联系人显示名", "草稿上下文"):
                self.assertNotIn(plaintext.encode(), file_bytes)

            restarted = Ledger(path, MASTER_KEY)
            self.assertEqual(
                restarted.get_cursor(event.shard, event.table_name),
                Cursor(1_000, 1),
            )
            self.assertEqual(list(restarted.iter_recent_events())[0].body, "私密消息")
            restarted.close()

    def test_send_reservation_is_idempotent_and_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ledger.db"
            with Ledger(path, MASTER_KEY) as ledger:
                first = ledger.reserve_send(
                    "send-1",
                    "contact_test",
                    "精确草稿正文",
                    payload={"draft": "敏感草稿"},
                    now_epoch=1_000,
                )
                same = ledger.reserve_send(
                    "send-1",
                    "contact_test",
                    "精确草稿正文",
                    payload={"draft": "敏感草稿"},
                    now_epoch=1_001,
                )
                self.assertTrue(first.created)
                self.assertFalse(same.created)
                with self.assertRaises(IdempotencyConflictError):
                    ledger.reserve_send(
                        "send-1",
                        "contact_test",
                        "已被替换的正文",
                        now_epoch=1_001,
                    )
                with self.assertRaises(DuplicateSendError):
                    ledger.reserve_send(
                        "send-2",
                        "contact_test",
                        "精确草稿正文",
                        payload={"draft": "敏感草稿"},
                        now_epoch=1_002,
                    )
                self.assertEqual(
                    ledger.transition_send("send-1", "sent").status, "sent"
                )
                self.assertEqual(
                    ledger.transition_send("send-1", "readback_confirmed").status,
                    "readback_confirmed",
                )
                self.assertTrue(ledger.verify_audit_chain())

            file_bytes = path.read_bytes()
            self.assertNotIn("精确草稿正文".encode(), file_bytes)
            self.assertNotIn("敏感草稿".encode(), file_bytes)

    def test_failed_send_is_terminal_and_still_blocks_duplicate_body(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ledger.db"
            with Ledger(path, MASTER_KEY) as ledger:
                ledger.reserve_send(
                    "send-failed",
                    "contact_test",
                    "无法确认是否已经发送的正文",
                    now_epoch=1_000,
                )
                ledger.transition_send("send-failed", "sending", now_epoch=1_001)
                ledger.transition_send(
                    "send-failed",
                    "failed",
                    payload={"retry_allowed": False},
                    now_epoch=1_002,
                )

                with self.assertRaises(InvalidSendTransitionError):
                    ledger.transition_send(
                        "send-failed",
                        "reserved",
                        now_epoch=1_003,
                    )
                with self.assertRaises(DuplicateSendError):
                    ledger.reserve_send(
                        "send-retry",
                        "contact_test",
                        "无法确认是否已经发送的正文",
                        now_epoch=1_004,
                    )

    def test_audit_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ledger.db"
            with Ledger(path, MASTER_KEY) as ledger:
                event = self._event("evt_audit")
                ledger.ingest_events(
                    [event],
                    shard=event.shard,
                    table_name=event.table_name,
                    cursor=(1_000, 1),
                )
                self.assertTrue(ledger.verify_audit_chain())

            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "UPDATE audit_chain SET entry_hash = ? WHERE sequence = ?",
                    (b"x" * 32, 1),
                )
                connection.commit()

            with Ledger(path, MASTER_KEY) as ledger:
                self.assertFalse(ledger.verify_audit_chain())


class WeChatReaderTests(unittest.TestCase):
    def test_multishard_overlap_dedup_restart_collision_and_readback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            message_dir = root / "message"
            first_db = message_dir / "message_0.db"
            second_db = message_dir / "message_1.db"
            contact_username = "wxid_raw_alice"
            self_username = "wxid_raw_self"
            first_table = _create_message_database(
                first_db,
                contact_username=contact_username,
                self_username=self_username,
                rows=[
                    (1, 1, 100, "contact", "第一条".encode(), 0),
                    (2, 1, 101, "self", "已发送".encode(), 0),
                    (3, 1, 101, "contact", "同秒后一条".encode(), 0),
                ],
                include_invalid_table=True,
            )
            _create_message_database(
                second_db,
                contact_username=contact_username,
                self_username=self_username,
                rows=[
                    (1, 1, 99, "contact", "local-id 冲突".encode(), 0),
                    (2, 1, 101, "self", "已发送".encode(), 0),
                    (4, 1, 102, "contact", "第二分片新增".encode(), 0),
                ],
            )
            ledger_path = Path(temp_dir) / "private" / "ledger.db"
            ledger = Ledger(ledger_path, MASTER_KEY)
            reader = WeChatReader(
                root,
                ledger,
                IDENTITY_SECRET,
                self_username=self_username,
                display_name_provider=lambda _: "Alice",
                overlap_seconds=5,
                batch_size=2,
            )

            first_poll = reader.poll()
            self.assertEqual(first_poll.discovered_databases, 2)
            self.assertEqual(first_poll.scanned_tables, 2)
            self.assertEqual(first_poll.scanned_rows, 6)
            self.assertEqual(first_poll.inserted_events, 5)
            events = list(ledger.iter_recent_events(limit=20))
            self.assertEqual(len(events), 5)
            self.assertEqual(
                [event.local_id for event in events if event.create_time == 101],
                [2, 3],
            )
            local_one_ids = {event.event_id for event in events if event.local_id == 1}
            self.assertEqual(len(local_one_ids), 2)
            self.assertEqual(reader.poll().inserted_events, 0)

            _append_message(
                first_db,
                first_table,
                local_id=5,
                create_time=100,
                sender_id=1,
                body="回看窗口回填".encode(),
            )
            backfill = reader.poll()
            self.assertEqual(backfill.inserted_events, 1)
            self.assertEqual(
                ledger.get_cursor("message/message_0.db", first_table),
                Cursor(101, 3),
            )
            ledger.close()

            ledger = Ledger(ledger_path, MASTER_KEY)
            restarted_reader = WeChatReader(
                root,
                ledger,
                IDENTITY_SECRET,
                self_username=self_username,
                overlap_seconds=5,
                batch_size=2,
            )
            self.assertEqual(restarted_reader.poll().inserted_events, 0)
            contact_key = next(iter(ledger.iter_recent_events())).contact_key

            _append_message(
                first_db,
                first_table,
                local_id=6,
                create_time=103,
                sender_id=2,
                body="readback exact".encode(),
            )
            self.assertTrue(
                restarted_reader.readback_confirm(
                    contact_key,
                    "readback exact",
                    after_epoch=103,
                )
            )
            self.assertFalse(
                restarted_reader.readback_confirm(
                    contact_key,
                    "readback exact ",
                    after_epoch=103,
                )
            )
            self.assertFalse(
                restarted_reader.readback_confirm(
                    contact_key,
                    "readback exact",
                    after_epoch=104,
                )
            )
            ledger.close()

            ledger_bytes = ledger_path.read_bytes()
            for plaintext in (
                contact_username,
                self_username,
                "Alice",
                "第一条",
                "readback exact",
            ):
                self.assertNotIn(plaintext.encode(), ledger_bytes)

    def test_zstd_type_four_without_dependency_is_marked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            _create_message_database(
                root / "message" / "message_0.db",
                contact_username="wxid_zstd_contact",
                self_username="wxid_zstd_self",
                rows=[
                    (
                        1,
                        1,
                        200,
                        "contact",
                        b"\x28\xb5\x2f\xfdnot-plaintext",
                        4,
                    )
                ],
            )
            with Ledger(Path(temp_dir) / "ledger.db", MASTER_KEY) as ledger:
                result = WeChatReader(
                    root,
                    ledger,
                    IDENTITY_SECRET,
                    self_username="wxid_zstd_self",
                    zstd_decompressor=False,
                ).poll()
                event = list(ledger.iter_recent_events())[0]
                self.assertEqual(event.body, ZSTD_UNAVAILABLE_MARKER)
                self.assertEqual(
                    event.payload["content_state"], "zstd_decoder_unavailable"
                )
                self.assertTrue(
                    any("zstd decoder unavailable" in x for x in result.warnings)
                )

    def test_table_name_injection_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_message_table(
                "Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; DROP TABLE events"
            )
        self.assertEqual(
            validate_message_table("Msg_" + "a" * 32),
            "Msg_" + "a" * 32,
        )

    def test_sqlcipher_key_is_only_sent_on_stdin(self):
        key = b"q" * 32
        captured: dict[str, object] = {}

        def fake_runner(argv, **kwargs):
            captured["argv"] = list(argv)
            captured["input"] = kwargs["input"]
            captured["timeout"] = kwargs["timeout"]
            return subprocess.CompletedProcess(argv, 0, b"[]", b"")

        backend = SQLCipherCLIQuery(
            lambda _: key,
            executable="/mock/sqlcipher",
            runner=fake_runner,
        )
        result = backend.query(Path("/fixture/message_0.db"), "SELECT 1 AS value")

        self.assertEqual(result, [])
        argv = os.fsencode("\x00".join(captured["argv"]))
        stdin = captured["input"]
        self.assertNotIn(key.hex().encode(), argv)
        self.assertIn(key.hex().encode(), stdin)
        self.assertIn(b"PRAGMA query_only = ON", stdin)
        self.assertIn("-readonly", captured["argv"])


if __name__ == "__main__":
    unittest.main()
