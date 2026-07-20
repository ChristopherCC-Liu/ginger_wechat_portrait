from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from personal_agent.ledger import (
    SCHEMA_VERSION,
    EncryptedLedger,
    LedgerError,
    LedgerEvent,
)


MASTER_KEY = b"k" * 32


class _TransactionAbort(BaseException):
    pass


class _CommitFailure(RuntimeError):
    pass


class _RollbackFailure(RuntimeError):
    pass


class _ConnectionProxy:
    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        fail_commit: bool = False,
        fail_rollback: bool = False,
    ) -> None:
        self.connection = connection
        self.fail_commit = fail_commit
        self.fail_rollback = fail_rollback
        self.rollback_attempted = False

    def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
        statement = sql.strip().upper()
        if statement == "COMMIT" and self.fail_commit:
            raise _CommitFailure("commit failed")
        if statement == "ROLLBACK":
            self.rollback_attempted = True
            if self.fail_rollback:
                raise _RollbackFailure("rollback failed")
        return self.connection.execute(sql, parameters)


class LedgerIntegrityTests(unittest.TestCase):
    @staticmethod
    def _event() -> LedgerEvent:
        return LedgerEvent(
            event_id="event-1",
            contact_key="contact-a",
            direction="inbound",
            local_type=1,
            create_time=1_000,
            local_id=7,
            body="private body",
            contact_display_name="Contact A",
            shard="message/message_0.db",
            table_name="Msg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            payload={"source": "fixture"},
        )

    @staticmethod
    def _tamper(path: Path, sql: str, parameters: tuple[object, ...]) -> None:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(sql, parameters)
            connection.commit()

    def test_event_row_tampering_is_rejected_on_readback(self) -> None:
        mutations = {
            "event_id": "event-tampered",
            "contact_key": "contact-b",
            "direction": "outbound",
            "shard": "message/message_9.db",
            "table_name": "Msg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "create_time": 2_000,
            "local_id": 8,
            "local_type": "49",
            "body_hmac": b"b" * 32,
            "canonical_hmac": b"c" * 32,
            "integrity_hmac": b"i" * 32,
            "payload_envelope": b"tampered-envelope",
            "ingested_at": 9_999,
        }
        for column, value in mutations.items():
            with self.subTest(column=column), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "ledger.sqlite3"
                with EncryptedLedger(path, MASTER_KEY) as ledger:
                    event = self._event()
                    ledger.ingest_events([event])
                    self._tamper(
                        path,
                        f"UPDATE events SET {column} = ? WHERE event_id = ?",
                        (value, event.event_id),
                    )
                    with self.assertRaises(LedgerError):
                        tuple(ledger.iter_recent_events())

    def test_runtime_record_metadata_and_ciphertext_tampering_is_rejected(
        self,
    ) -> None:
        mutations = {
            "record_id": "record-tampered",
            "namespace": "other-namespace",
            "scope": "contact-b",
            "kind": "other-kind",
            "occurred_at": 2_000,
            "canonical_hmac": b"c" * 32,
            "payload_envelope": b"tampered-envelope",
        }
        for column, value in mutations.items():
            with self.subTest(column=column), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "ledger.sqlite3"
                with EncryptedLedger(path, MASTER_KEY) as ledger:
                    ledger.append_runtime_record(
                        "record-1",
                        "state",
                        "contact-a",
                        "profile",
                        {"value": "private"},
                        occurred_at=1_000,
                    )
                    self._tamper(
                        path,
                        f"UPDATE runtime_records SET {column} = ? WHERE record_id = ?",
                        (value, "record-1"),
                    )
                    lookup_id = (
                        "record-tampered" if column == "record_id" else "record-1"
                    )
                    with self.assertRaises(LedgerError):
                        ledger.get_runtime_record(lookup_id)

    def test_cross_scope_runtime_active_pointer_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.sqlite3"
            with EncryptedLedger(path, MASTER_KEY) as ledger:
                ledger.append_runtime_record(
                    "record-a",
                    "state",
                    "contact-a",
                    "profile",
                    {"value": "a"},
                    occurred_at=1_000,
                    activate=True,
                )
                ledger.append_runtime_record(
                    "record-b",
                    "state",
                    "contact-b",
                    "profile",
                    {"value": "b"},
                    occurred_at=1_001,
                )
                self._tamper(
                    path,
                    "UPDATE runtime_active SET record_id = ? "
                    "WHERE namespace = ? AND scope = ?",
                    ("record-b", "state", "contact-a"),
                )
                with self.assertRaises(LedgerError):
                    ledger.get_active_runtime_record("state", "contact-a")

    def test_transaction_rolls_back_base_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with EncryptedLedger(Path(temp) / "ledger.sqlite3", MASTER_KEY) as ledger:
                with self.assertRaises(_TransactionAbort):
                    with ledger._transaction() as connection:
                        connection.execute(
                            "INSERT INTO ledger_meta(key, value) VALUES (?, ?)",
                            ("base-exception", b"value"),
                        )
                        raise _TransactionAbort("abort")

                self.assertFalse(ledger._connection.in_transaction)
                row = ledger._connection.execute(
                    "SELECT value FROM ledger_meta WHERE key = ?",
                    ("base-exception",),
                ).fetchone()
                self.assertIsNone(row)

    def test_transaction_rolls_back_commit_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with EncryptedLedger(Path(temp) / "ledger.sqlite3", MASTER_KEY) as ledger:
                connection = ledger._connection
                proxy = _ConnectionProxy(connection, fail_commit=True)
                ledger._connection = proxy  # type: ignore[assignment]
                try:
                    with self.assertRaisesRegex(_CommitFailure, "commit failed"):
                        with ledger._transaction() as transaction:
                            transaction.execute(
                                "INSERT INTO ledger_meta(key, value) VALUES (?, ?)",
                                ("commit-failure", b"value"),
                            )
                finally:
                    ledger._connection = connection

                self.assertTrue(proxy.rollback_attempted)
                self.assertFalse(connection.in_transaction)
                row = connection.execute(
                    "SELECT value FROM ledger_meta WHERE key = ?",
                    ("commit-failure",),
                ).fetchone()
                self.assertIsNone(row)

    def test_transaction_does_not_mask_original_when_rollback_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with EncryptedLedger(Path(temp) / "ledger.sqlite3", MASTER_KEY) as ledger:
                connection = ledger._connection
                proxy = _ConnectionProxy(connection, fail_rollback=True)
                ledger._connection = proxy  # type: ignore[assignment]
                try:
                    with self.assertRaisesRegex(_TransactionAbort, "original abort"):
                        with ledger._transaction():
                            raise _TransactionAbort("original abort")
                finally:
                    ledger._connection = connection
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")

                self.assertTrue(proxy.rollback_attempted)

    def test_populated_v2_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "legacy.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_version (
                        version INTEGER PRIMARY KEY,
                        applied_at INTEGER NOT NULL
                    );
                    INSERT INTO schema_version(version, applied_at) VALUES (2, 1);
                    CREATE TABLE events (
                        event_id TEXT PRIMARY KEY,
                        shard TEXT NOT NULL,
                        table_name TEXT NOT NULL,
                        create_time INTEGER NOT NULL,
                        local_id INTEGER NOT NULL,
                        contact_key TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        local_type TEXT NOT NULL,
                        body_hmac BLOB NOT NULL,
                        canonical_hmac BLOB NOT NULL,
                        payload_envelope BLOB NOT NULL,
                        ingested_at INTEGER NOT NULL
                    );
                    """
                )
                connection.execute(
                    "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "legacy-event",
                        "legacy-shard",
                        "legacy-table",
                        1,
                        1,
                        "legacy-contact",
                        "inbound",
                        "1",
                        b"b" * 32,
                        b"c" * 32,
                        b"legacy-envelope",
                        1,
                    ),
                )
                connection.commit()

            with self.assertRaisesRegex(LedgerError, "migration refused"):
                EncryptedLedger(path, MASTER_KEY)

    def test_empty_v2_schema_migrates_to_current_integrity_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "legacy-empty.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_version (
                        version INTEGER PRIMARY KEY,
                        applied_at INTEGER NOT NULL
                    );
                    INSERT INTO schema_version(version, applied_at) VALUES (2, 1);
                    CREATE TABLE events (
                        event_id TEXT PRIMARY KEY,
                        shard TEXT NOT NULL,
                        table_name TEXT NOT NULL,
                        create_time INTEGER NOT NULL,
                        local_id INTEGER NOT NULL,
                        contact_key TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        local_type TEXT NOT NULL,
                        body_hmac BLOB NOT NULL,
                        canonical_hmac BLOB NOT NULL,
                        payload_envelope BLOB NOT NULL,
                        ingested_at INTEGER NOT NULL
                    );
                    """
                )

            with EncryptedLedger(path, MASTER_KEY) as ledger:
                self.assertEqual(ledger.schema_version, SCHEMA_VERSION)
                event = self._event()
                self.assertEqual(ledger.ingest_events([event]), 1)
                self.assertEqual(tuple(ledger.iter_recent_events()), (event,))


if __name__ == "__main__":
    unittest.main()
