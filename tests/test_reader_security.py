from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from personal_agent import wechat_reader as reader_module
from personal_agent.ledger import Cursor, LedgerEvent
from personal_agent.wechat_reader import (
    CONTENT_TOO_LARGE_MARKER,
    PollResult,
    ReadbackBaseline,
    SQLCipherCLIQuery,
    WeChatReader,
    WeChatReaderError,
)


IDENTITY_SECRET = b"i" * 32


def _message_table(username: str) -> str:
    digest = hashlib.md5(
        username.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return f"Msg_{digest}"


def _event(
    event_id: str,
    *,
    body: str = "sent body",
    create_time: int = 100,
    local_id: int = 1,
) -> LedgerEvent:
    return LedgerEvent(
        event_id=event_id,
        contact_key="contact_test",
        direction="outbound",
        local_type=1,
        create_time=create_time,
        local_id=local_id,
        body=body,
        shard="message/message_0.db",
        table_name="Msg_" + "a" * 32,
    )


class _PermissiveLedger:
    def event_identity_status(self, event: LedgerEvent) -> str:
        return "absent"


class _BaselineLedger(_PermissiveLedger):
    def __init__(self) -> None:
        self.cursors: dict[tuple[str, str], Cursor] = {}

    def get_cursor(self, shard: str, table_name: str) -> Cursor | None:
        return self.cursors.get((shard, table_name))

    def ingest_events(
        self,
        events,
        *,
        shard: str,
        table_name: str,
        cursor: Cursor,
    ) -> int:
        materialized = list(events)
        previous = self.cursors.get((shard, table_name))
        self.cursors[(shard, table_name)] = (
            max(previous, cursor) if previous is not None else cursor
        )
        return len(materialized)


class _DiscoveryQuery:
    def __init__(self, usernames: list[str], tables: list[str]) -> None:
        self.usernames = usernames
        self.tables = tables
        self.after_times: list[tuple[str, int]] = []

    def query(self, database: Path, sql: str, parameters=None):
        if "FROM Name2Id" in sql:
            return [
                {"sender_id": index, "user_name": username}
                for index, username in enumerate(self.usernames, start=1)
            ]
        if "FROM sqlite_master" in sql:
            return [{"name": table} for table in self.tables]
        if sql.startswith("PRAGMA table_info"):
            return [
                {"name": name}
                for name in (
                    "create_time",
                    "local_id",
                    "local_type",
                    "message_content",
                    "real_sender_id",
                    "WCDB_CT_message_content",
                )
            ]
        if 'FROM "Msg_' in sql:
            table_name = sql.split('FROM "', 1)[1].split('"', 1)[0]
            self.after_times.append((table_name, int(parameters["after_time"])))
            return []
        raise AssertionError(f"unexpected query: {sql}")


class _ReadbackLedger(_PermissiveLedger):
    def __init__(self, events: list[LedgerEvent]) -> None:
        self.events = events

    def iter_recent_events(
        self,
        *,
        limit: int,
        contact_key: str,
        after_epoch: int,
        direction: str,
    ):
        selected = [
            event
            for event in self.events
            if event.contact_key == contact_key
            and event.create_time >= after_epoch
            and event.direction == direction
        ]
        yield from selected[-limit:]


class SQLCipherExecutableSecurityTests(unittest.TestCase):
    def _runner(self, argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, b"[]", b"")

    def _binary(self, root: Path, *, mode: int = 0o755) -> Path:
        binary = root / "bin" / "sqlcipher"
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        binary.chmod(mode)
        return binary

    def test_accepts_only_resolved_trusted_regular_executable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            trusted_root = Path(temp_dir).resolve()
            binary = self._binary(trusted_root)
            captured: dict[str, object] = {}

            def runner(argv, **kwargs):
                captured["argv"] = list(argv)
                return subprocess.CompletedProcess(argv, 0, b"[]", b"")

            with mock.patch.object(
                reader_module,
                "TRUSTED_SQLCIPHER_ROOTS",
                (trusted_root,),
            ):
                backend = SQLCipherCLIQuery(
                    lambda _: b"k" * 32,
                    executable=str(binary),
                    runner=runner,
                )
                self.assertEqual(
                    backend.query(Path("/fixture.db"), "SELECT 1"),
                    [],
                )

            self.assertEqual(captured["argv"][0], str(binary.resolve(strict=True)))

    def test_rejects_symlink_untrusted_writable_and_non_executable_paths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            trusted_root = Path(temp_dir).resolve()
            binary = self._binary(trusted_root)
            link_dir = trusted_root / "links"
            link_dir.mkdir()
            link = link_dir / "sqlcipher"
            link.symlink_to(binary)

            with mock.patch.object(
                reader_module,
                "TRUSTED_SQLCIPHER_ROOTS",
                (trusted_root,),
            ):
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    SQLCipherCLIQuery(
                        lambda _: b"k" * 32,
                        executable=str(link),
                        runner=self._runner,
                    )

                binary.chmod(0o777)
                with self.assertRaisesRegex(ValueError, "group or world writable"):
                    SQLCipherCLIQuery(
                        lambda _: b"k" * 32,
                        executable=str(binary),
                        runner=self._runner,
                    )

                binary.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "must be executable"):
                    SQLCipherCLIQuery(
                        lambda _: b"k" * 32,
                        executable=str(binary),
                        runner=self._runner,
                    )

                directory = trusted_root / "directory" / "sqlcipher"
                directory.mkdir(parents=True)
                with self.assertRaisesRegex(ValueError, "regular file"):
                    SQLCipherCLIQuery(
                        lambda _: b"k" * 32,
                        executable=str(directory),
                        runner=self._runner,
                    )

                owner = binary.stat().st_uid
                if owner != 0:
                    with (
                        mock.patch.object(
                            reader_module.os, "getuid", return_value=owner + 1
                        ),
                        self.assertRaisesRegex(ValueError, "untrusted owner"),
                    ):
                        binary.chmod(0o755)
                        SQLCipherCLIQuery(
                            lambda _: b"k" * 32,
                            executable=str(binary),
                            runner=self._runner,
                        )

            binary.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "outside trusted"):
                SQLCipherCLIQuery(
                    lambda _: b"k" * 32,
                    executable=str(binary),
                    runner=self._runner,
                )

    def test_real_runner_requires_existing_binary_and_caps_stdout(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            SQLCipherCLIQuery(
                lambda _: b"k" * 32,
                executable="/usr/local/definitely-missing/sqlcipher",
            )

        def oversized_runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, b"[]\n", b"")

        with mock.patch.object(reader_module, "MAX_SQLCIPHER_OUTPUT_BYTES", 2):
            backend = SQLCipherCLIQuery(
                lambda _: b"k" * 32,
                executable="/mock/sqlcipher",
                runner=oversized_runner,
            )
            with self.assertRaisesRegex(WeChatReaderError, "size limit"):
                backend.query(Path("/fixture.db"), "SELECT 1")


class DirectionAndContentSecurityTests(unittest.TestCase):
    def _reader(self, *, self_username: str | None = None, decompressor=False):
        return WeChatReader(
            "/unused",
            _PermissiveLedger(),
            IDENTITY_SECRET,
            self_username=self_username,
            zstd_decompressor=decompressor,
        )

    def test_direction_is_three_state_and_missing_self_id_never_guesses(self):
        reader = self._reader()
        self.assertEqual(reader._direction(1, "member", "room@chatroom"), "unknown")
        self.assertEqual(reader._direction(1, "contact", "contact"), "inbound")
        self.assertEqual(reader._direction(2, "some-self", "contact"), "unknown")
        self.assertEqual(reader._direction(None, None, "contact"), "unknown")

        identified = self._reader(self_username="self")
        self.assertEqual(identified._direction(2, "self", "contact"), "outbound")
        self.assertEqual(identified._direction(1, "contact", "contact"), "inbound")
        self.assertEqual(identified._direction(None, None, "contact"), "unknown")

    def test_oversized_hex_and_zstd_output_become_small_markers(self):
        reader = self._reader(decompressor=lambda _: b"x" * 9)
        base_row = {
            "local_id": 1,
            "local_type": 1,
            "create_time": 100,
            "real_sender_id": 1,
            "content_oversized": 0,
        }
        kwargs = {
            "shard": "message/message_0.db",
            "table_name": "Msg_" + "a" * 32,
            "contact_username": "contact",
            "contact_key": "contact_test",
            "display_name": None,
            "name_map": {1: "contact"},
            "page_identities": {},
        }

        with mock.patch.object(reader_module, "MAX_MESSAGE_HEX_CHARS", 8):
            event = reader._row_event(
                {**base_row, "message_content_hex": "00" * 5, "compression_type": 0},
                **kwargs,
            )
        self.assertIsNotNone(event)
        self.assertEqual(event.body, CONTENT_TOO_LARGE_MARKER)
        self.assertEqual(event.payload["content_state"], "hex_input_too_large")

        with mock.patch.object(reader_module, "MAX_ZSTD_OUTPUT_BYTES", 8):
            event = reader._row_event(
                {**base_row, "message_content_hex": "28b52ffd", "compression_type": 4},
                **{**kwargs, "page_identities": {}},
            )
        self.assertIsNotNone(event)
        self.assertEqual(event.body, CONTENT_TOO_LARGE_MARKER)
        self.assertEqual(event.payload["content_state"], "zstd_output_too_large")
        self.assertLess(len(event.body.encode("utf-8")), 100)

    def test_compressed_input_and_plaintext_body_have_independent_limits(self):
        decompressor_calls = 0

        def decompressor(raw: bytes) -> bytes:
            nonlocal decompressor_calls
            decompressor_calls += 1
            return raw

        reader = self._reader(decompressor=decompressor)
        base_row = {
            "local_id": 1,
            "local_type": 1,
            "create_time": 100,
            "real_sender_id": 1,
            "content_oversized": 0,
        }
        kwargs = {
            "shard": "message/message_0.db",
            "table_name": "Msg_" + "a" * 32,
            "contact_username": "contact",
            "contact_key": "contact_test",
            "display_name": None,
            "name_map": {1: "contact"},
            "page_identities": {},
        }

        with (
            mock.patch.object(reader_module, "MAX_MESSAGE_CONTENT_BYTES", 4),
            mock.patch.object(reader_module, "MAX_MESSAGE_HEX_CHARS", 100),
        ):
            compressed = reader._row_event(
                {
                    **base_row,
                    "message_content_hex": (reader_module.ZSTD_MAGIC + b"x").hex(),
                    "compression_type": 4,
                },
                **kwargs,
            )
        self.assertIsNotNone(compressed)
        self.assertEqual(
            compressed.payload["content_state"],
            "compressed_input_too_large",
        )
        self.assertEqual(decompressor_calls, 0)

        with mock.patch.object(reader_module, "MAX_BODY_BYTES", 8):
            plaintext = reader._row_event(
                {
                    **base_row,
                    "message_content_hex": (b"x" * 9).hex(),
                    "compression_type": 0,
                },
                **{**kwargs, "page_identities": {}},
            )
        self.assertIsNotNone(plaintext)
        self.assertEqual(plaintext.payload["content_state"], "body_too_large")
        self.assertEqual(plaintext.body, CONTENT_TOO_LARGE_MARKER)


class IncrementalAndReadbackSecurityTests(unittest.TestCase):
    def test_runtime_cutoff_applies_only_to_newly_discovered_tables(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "source"
            database = root / "message" / "message_0.db"
            database.parent.mkdir(parents=True)
            database.touch()
            first_username = "contact-one"
            second_username = "contact-two"
            first_table = _message_table(first_username)
            second_table = _message_table(second_username)
            query = _DiscoveryQuery(
                [first_username, second_username],
                [first_table],
            )
            ledger = _BaselineLedger()
            reader = WeChatReader(
                root,
                ledger,
                IDENTITY_SECRET,
                query=query,
                overlap_seconds=5,
                zstd_decompressor=False,
            )

            reader.poll(bootstrap_after_epoch=100)
            query.tables.append(second_table)
            reader.poll(bootstrap_after_epoch=200)

            last_after = dict(query.after_times[-2:])
            self.assertEqual(last_after[first_table], 95)
            self.assertEqual(last_after[second_table], 200)
            self.assertEqual(
                ledger.get_cursor("message/message_0.db", second_table),
                Cursor(200, 0),
            )

    def test_readback_requires_event_identity_strictly_after_click_baseline(self):
        old = _event("evt_old", create_time=100, local_id=1)
        ledger = _ReadbackLedger([old])
        reader = WeChatReader(
            "/unused",
            ledger,
            IDENTITY_SECRET,
            zstd_decompressor=False,
        )
        reader.poll = mock.Mock(return_value=PollResult())

        baseline = reader.readback_baseline("contact_test", after_epoch=100)
        self.assertEqual(
            baseline,
            ReadbackBaseline(
                outbound_event_ids=frozenset({"evt_old"}),
                high_watermark=(100, 1, "evt_old"),
            ),
        )
        self.assertFalse(
            reader.readback_confirm(
                "contact_test",
                "sent body",
                100,
                baseline=baseline,
            )
        )

        ledger.events.append(_event("evt_new", create_time=101, local_id=2))
        self.assertTrue(
            reader.readback_confirm(
                "contact_test",
                "sent body",
                100,
                baseline=baseline,
            )
        )
        self.assertFalse(
            reader.readback_confirm(
                "contact_test",
                "sent body",
                100,
                known_outbound_event_ids={"evt_old", "evt_new"},
                outbound_high_watermark=(101, 2),
            )
        )


if __name__ == "__main__":
    unittest.main()
