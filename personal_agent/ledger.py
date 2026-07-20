"""Encrypted, transactional SQLite ledger for Personal Agent v2."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final, NamedTuple, TypeAlias, cast

from .crypto_store import AESGCMEnvelope, InvalidEnvelopeError, require_aes256_key


SCHEMA_VERSION: Final = 3
BUSY_TIMEOUT_MS: Final = 5_000
PRIVATE_FILE_MODE: Final = 0o600
PRIVATE_DIRECTORY_MODE: Final = 0o700
MAX_EVENT_BATCH: Final = 100_000
MAX_RECENT_LIMIT: Final = 10_000
DEFAULT_SEND_DEDUPE_SECONDS: Final = 300
_ZERO_HASH: Final = b"\x00" * hashlib.sha256().digest_size

JSONValue: TypeAlias = (
    None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]
)
EventInput: TypeAlias = "LedgerEvent | Mapping[str, Any]"


class LedgerError(RuntimeError):
    """Base ledger error."""


class LedgerKeyError(LedgerError):
    """Raised when a database is opened with the wrong master key."""


class EventCollisionError(LedgerError):
    """Raised when one event id names different canonical event content."""

    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        super().__init__(f"event id collision: {event_id}")


class IdempotencyConflictError(LedgerError):
    """Raised when an idempotency key is reused for a different request."""


class DuplicateSendError(LedgerError):
    """Raised for an equivalent active send inside the dedupe window."""


class InvalidSendTransitionError(LedgerError):
    """Raised when a send state transition is not allowed."""


class Cursor(NamedTuple):
    create_time: int
    local_id: int


@dataclass(frozen=True)
class LedgerEvent:
    event_id: str
    contact_key: str
    direction: str
    local_type: int | str
    create_time: int
    local_id: int
    body: str
    contact_display_name: str | None = None
    shard: str = ""
    table_name: str = ""
    payload: Mapping[str, JSONValue] = field(default_factory=dict)


@dataclass(frozen=True)
class SendReservation:
    idempotency_key: str
    contact_key: str
    body: str
    status: str
    payload: Mapping[str, JSONValue]
    reserved_at: int
    updated_at: int
    created: bool


@dataclass(frozen=True)
class RuntimeRecord:
    """One immutable encrypted runtime object.

    Namespaces, scopes, and identifiers must contain pseudonymous metadata only;
    the payload is the only field that may contain private message-derived data.
    """

    record_id: str
    namespace: str
    scope: str
    kind: str
    occurred_at: int
    payload: Mapping[str, JSONValue]
    created: bool = False


_SEND_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "reserved": frozenset({"sending", "sent", "failed", "cancelled"}),
    "sending": frozenset({"sent", "failed", "cancelled"}),
    "sent": frozenset({"readback_confirmed", "failed"}),
    "failed": frozenset({"cancelled"}),
    "readback_confirmed": frozenset(),
    "cancelled": frozenset(),
}


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("payload must be finite JSON data") from exc


def _decode_json(value: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerError("encrypted ledger payload is invalid") from exc
    if not isinstance(decoded, dict):
        raise LedgerError("encrypted ledger payload is invalid")
    return cast(dict[str, Any], decoded)


def _derive_key(root: bytes, label: bytes) -> bytes:
    return hmac.new(root, b"ginger-ledger-kdf-v1\x00" + label, hashlib.sha256).digest()


def _hmac_parts(key: bytes, domain: bytes, *parts: bytes) -> bytes:
    digest = hmac.new(key, domain + b"\x00", hashlib.sha256)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _required_string(value: object, field_name: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _integer(value: object, field_name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    try:
        normalized = int(cast(Any, value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if normalized < minimum:
        raise ValueError(f"{field_name} must be at least {minimum}")
    return normalized


def _normalize_cursor(value: Cursor | tuple[int, int]) -> Cursor:
    if not isinstance(value, tuple) or len(value) != 2:
        raise ValueError("cursor must be a (create_time, local_id) pair")
    return Cursor(
        _integer(value[0], "cursor create_time"),
        _integer(value[1], "cursor local_id"),
    )


def _prepare_database_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("ledger parent must not be a symbolic link")
    try:
        path.parent.chmod(PRIVATE_DIRECTORY_MODE)
    except OSError:
        pass

    if path.is_symlink():
        raise ValueError("ledger path must not be a symbolic link")
    if path.exists():
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("ledger path must be a regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("ledger file must be owned by the current user")
        path.chmod(PRIVATE_FILE_MODE)
        return

    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
    finally:
        os.close(descriptor)


class EncryptedLedger:
    """SQLite ledger whose sensitive values are authenticated and encrypted."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        encryption_key: bytes,
        *,
        hmac_key: bytes | None = None,
        send_dedupe_seconds: int = DEFAULT_SEND_DEDUPE_SECONDS,
    ) -> None:
        self.path = Path(path).expanduser()
        master_key = require_aes256_key(encryption_key)
        hmac_root = master_key if hmac_key is None else bytes(hmac_key)
        if len(hmac_root) < 32:
            raise ValueError("ledger HMAC key must be at least 32 bytes")
        if not 0 <= send_dedupe_seconds <= 86_400:
            raise ValueError("send dedupe window must be between 0 and 86400 seconds")

        self._cipher = AESGCMEnvelope(master_key)
        self._body_hmac_key = _derive_key(hmac_root, b"event-body")
        self._canonical_hmac_key = _derive_key(hmac_root, b"event-canonical")
        self._runtime_hmac_key = _derive_key(hmac_root, b"runtime-record")
        self._audit_hmac_key = _derive_key(hmac_root, b"audit-chain")
        self._request_hmac_key = _derive_key(hmac_root, b"send-request")
        self._send_dedupe_seconds = int(send_dedupe_seconds)
        self._lock = threading.RLock()
        self._closed = False

        _prepare_database_file(self.path)
        self._connection = sqlite3.connect(
            self.path,
            timeout=BUSY_TIMEOUT_MS / 1_000,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure_connection()
            self._initialize_schema()
            self.path.chmod(PRIVATE_FILE_MODE)
        except Exception:
            self._connection.close()
            raise

    def _configure_connection(self) -> None:
        journal_mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if not journal_mode or str(journal_mode[0]).lower() != "wal":
            raise LedgerError("could not enable SQLite WAL mode")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA synchronous = FULL")
        foreign_keys = self._connection.execute("PRAGMA foreign_keys").fetchone()
        busy_timeout = self._connection.execute("PRAGMA busy_timeout").fetchone()
        if not foreign_keys or foreign_keys[0] != 1:
            raise LedgerError("could not enable SQLite foreign keys")
        if not busy_timeout or busy_timeout[0] != BUSY_TIMEOUT_MS:
            raise LedgerError("could not configure SQLite busy timeout")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise LedgerError("ledger is closed")
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                try:
                    self._connection.execute("ROLLBACK")
                except BaseException:
                    pass
                raise
            else:
                try:
                    self._connection.execute("COMMIT")
                except BaseException:
                    try:
                        self._connection.execute("ROLLBACK")
                    except BaseException:
                        pass
                    raise

    def _initialize_schema(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    shard TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    create_time INTEGER NOT NULL CHECK (create_time >= 0),
                    local_id INTEGER NOT NULL CHECK (local_id >= 0),
                    contact_key TEXT NOT NULL,
                    direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
                    local_type TEXT NOT NULL,
                    body_hmac BLOB NOT NULL CHECK (length(body_hmac) = 32),
                    canonical_hmac BLOB NOT NULL CHECK (length(canonical_hmac) = 32),
                    integrity_hmac BLOB NOT NULL CHECK (length(integrity_hmac) = 32),
                    payload_envelope BLOB NOT NULL,
                    ingested_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS events_recent_idx
                    ON events(create_time DESC, local_id DESC);
                CREATE INDEX IF NOT EXISTS events_contact_recent_idx
                    ON events(contact_key, create_time DESC, local_id DESC);

                CREATE TABLE IF NOT EXISTS cursors (
                    shard TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    create_time INTEGER NOT NULL CHECK (create_time >= 0),
                    local_id INTEGER NOT NULL CHECK (local_id >= 0),
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (shard, table_name)
                );

                CREATE TABLE IF NOT EXISTS send_attempts (
                    idempotency_key TEXT PRIMARY KEY,
                    contact_key TEXT NOT NULL,
                    body_hmac BLOB NOT NULL CHECK (length(body_hmac) = 32),
                    request_hmac BLOB NOT NULL CHECK (length(request_hmac) = 32),
                    status TEXT NOT NULL,
                    payload_envelope BLOB NOT NULL,
                    reserved_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS send_attempts_dedupe_idx
                    ON send_attempts(contact_key, body_hmac, reserved_at DESC);

                CREATE TABLE IF NOT EXISTS audit_chain (
                    sequence INTEGER PRIMARY KEY,
                    occurred_at INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    payload_envelope BLOB NOT NULL,
                    prev_hash BLOB NOT NULL CHECK (length(prev_hash) = 32),
                    entry_hash BLOB NOT NULL CHECK (length(entry_hash) = 32)
                );

                CREATE TABLE IF NOT EXISTS ledger_meta (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runtime_records (
                    record_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
                    canonical_hmac BLOB NOT NULL CHECK (length(canonical_hmac) = 32),
                    payload_envelope BLOB NOT NULL
                );

                CREATE INDEX IF NOT EXISTS runtime_records_scope_idx
                    ON runtime_records(namespace, scope, occurred_at, record_id);
                CREATE INDEX IF NOT EXISTS runtime_records_kind_idx
                    ON runtime_records(namespace, kind, occurred_at, record_id);

                CREATE TABLE IF NOT EXISTS runtime_active (
                    namespace TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (namespace, scope),
                    FOREIGN KEY (record_id) REFERENCES runtime_records(record_id)
                );
                """
            )
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT version FROM schema_version ORDER BY version"
            ).fetchall()
            versions = [int(row[0]) for row in rows]
            if any(version > SCHEMA_VERSION for version in versions):
                raise LedgerError("ledger schema is newer than this runtime")

            expected_key_check = _hmac_parts(
                self._audit_hmac_key,
                b"ledger-key-check-v1",
                b"personal-agent-v2",
            )
            key_check = connection.execute(
                "SELECT value FROM ledger_meta WHERE key = ?",
                ("key_check",),
            ).fetchone()
            if key_check is not None and not hmac.compare_digest(
                bytes(key_check[0]), expected_key_check
            ):
                raise LedgerKeyError("ledger key verification failed")

            if SCHEMA_VERSION not in versions:
                protected_rows = connection.execute(
                    "SELECT (SELECT COUNT(*) FROM events) + "
                    "(SELECT COUNT(*) FROM runtime_records) + "
                    "(SELECT COUNT(*) FROM runtime_active)"
                ).fetchone()
                if protected_rows is None or int(protected_rows[0]) != 0:
                    raise LedgerError(
                        "ledger integrity migration refused: cannot safely upgrade "
                        "legacy protected records"
                    )
                event_columns = {
                    str(row[1])
                    for row in connection.execute("PRAGMA table_info(events)")
                }
                if "integrity_hmac" not in event_columns:
                    connection.execute(
                        "ALTER TABLE events ADD COLUMN integrity_hmac BLOB "
                        "NOT NULL CHECK (length(integrity_hmac) = 32)"
                    )
                connection.execute(
                    "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, int(time.time())),
                )

            event_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(events)")
            }
            if "integrity_hmac" not in event_columns:
                raise LedgerError("ledger integrity schema is incomplete")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            if key_check is None:
                connection.execute(
                    "INSERT INTO ledger_meta(key, value) VALUES (?, ?)",
                    ("key_check", expected_key_check),
                )

    @property
    def schema_version(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _event_from_input(
        self,
        value: EventInput,
        *,
        shard: str | None,
        table_name: str | None,
    ) -> LedgerEvent:
        if isinstance(value, LedgerEvent):
            event = value
        elif isinstance(value, Mapping):
            body = value.get("body", value.get("text"))
            local_type = value.get("local_type", value.get("message_type", "unknown"))
            event = LedgerEvent(
                event_id=cast(str, value.get("event_id")),
                contact_key=cast(str, value.get("contact_key")),
                direction=cast(str, value.get("direction")),
                local_type=cast(int | str, local_type),
                create_time=cast(
                    int, value.get("create_time", value.get("epoch_seconds"))
                ),
                local_id=cast(int, value.get("local_id", value.get("source_sequence"))),
                body=cast(str, body),
                contact_display_name=cast(
                    str | None,
                    value.get("contact_display_name", value.get("contact_label")),
                ),
                shard=cast(str, value.get("shard", "")),
                table_name=cast(str, value.get("table_name", "")),
                payload=cast(Mapping[str, JSONValue], value.get("payload", {})),
            )
        else:
            raise TypeError("events must be LedgerEvent objects or mappings")

        event_shard = shard if shard is not None else event.shard
        event_table = table_name if table_name is not None else event.table_name
        normalized_direction = _required_string(
            event.direction, "direction", maximum=16
        )
        if normalized_direction not in {"inbound", "outbound"}:
            raise ValueError("direction must be inbound or outbound")
        if not isinstance(event.body, str):
            raise ValueError("event body must be a string")
        if event.contact_display_name is not None and not isinstance(
            event.contact_display_name, str
        ):
            raise ValueError("contact display name must be a string or None")
        if not isinstance(event.payload, Mapping):
            raise ValueError("event payload must be a mapping")
        payload = cast(Mapping[str, JSONValue], dict(event.payload))
        _canonical_json(payload)

        return replace(
            event,
            event_id=_required_string(event.event_id, "event id"),
            contact_key=_required_string(event.contact_key, "contact key"),
            direction=normalized_direction,
            local_type=str(event.local_type),
            create_time=_integer(event.create_time, "create time"),
            local_id=_integer(event.local_id, "local id"),
            shard=_required_string(event_shard, "shard", maximum=1_024),
            table_name=_required_string(event_table, "table name"),
            payload=payload,
        )

    def _event_route(self, event: LedgerEvent) -> bytes:
        return _canonical_json(
            {
                "contact_key": event.contact_key,
                "create_time": event.create_time,
                "direction": event.direction,
                "event_id": event.event_id,
                "local_id": event.local_id,
                "local_type": str(event.local_type),
                "shard": event.shard,
                "table_name": event.table_name,
                "v": 2,
            }
        )

    def _event_canonical_hmac(self, event: LedgerEvent) -> bytes:
        canonical = _canonical_json(
            {
                "body": event.body,
                "contact_key": event.contact_key,
                "create_time": event.create_time,
                "direction": event.direction,
                "local_id": event.local_id,
                "local_type": str(event.local_type),
                "v": 1,
            }
        )
        return _hmac_parts(
            self._canonical_hmac_key,
            b"event-canonical-v1",
            canonical,
        )

    def _event_payload(self, event: LedgerEvent) -> bytes:
        return _canonical_json(
            {
                "body": event.body,
                "contact_display_name": event.contact_display_name,
                "payload": dict(event.payload),
                "v": 2,
            }
        )

    def _event_payload_aad(self, event: LedgerEvent) -> bytes:
        return b"events-v2\x00" + self._event_route(event)

    def _event_integrity_hmac(
        self,
        event: LedgerEvent,
        body_hmac: bytes,
        ingested_at: int,
    ) -> bytes:
        return _hmac_parts(
            self._canonical_hmac_key,
            b"event-row-v2",
            self._event_route(event),
            self._event_payload(event),
            body_hmac,
            str(ingested_at).encode("ascii"),
        )

    def _event_from_row(self, row: sqlite3.Row) -> LedgerEvent:
        try:
            event = LedgerEvent(
                event_id=_required_string(str(row["event_id"]), "event id"),
                contact_key=_required_string(str(row["contact_key"]), "contact key"),
                direction=_required_string(
                    str(row["direction"]), "direction", maximum=16
                ),
                local_type=self._restore_local_type(str(row["local_type"])),
                create_time=_integer(row["create_time"], "create time"),
                local_id=_integer(row["local_id"], "local id"),
                body="",
                shard=_required_string(str(row["shard"]), "shard", maximum=1_024),
                table_name=_required_string(str(row["table_name"]), "table name"),
            )
            if event.direction not in {"inbound", "outbound"}:
                raise ValueError("direction must be inbound or outbound")
            plaintext = self._cipher.decrypt(
                bytes(row["payload_envelope"]),
                aad=self._event_payload_aad(event),
            )
            decoded = _decode_json(plaintext)
            body = decoded.get("body")
            display_name = decoded.get("contact_display_name")
            payload = decoded.get("payload")
            if (
                decoded.get("v") != 2
                or not isinstance(body, str)
                or (display_name is not None and not isinstance(display_name, str))
                or not isinstance(payload, dict)
            ):
                raise LedgerError("event integrity verification failed")
            event = replace(
                event,
                body=body,
                contact_display_name=cast(str | None, display_name),
                payload=cast(Mapping[str, JSONValue], payload),
            )
            expected_body_hmac = _hmac_parts(
                self._body_hmac_key,
                b"event-body-v1",
                event.body.encode("utf-8"),
            )
            stored_body_hmac = bytes(row["body_hmac"])
            ingested_at = _integer(row["ingested_at"], "ingested at")
            expected_canonical_hmac = self._event_canonical_hmac(event)
            expected_integrity_hmac = self._event_integrity_hmac(
                event,
                expected_body_hmac,
                ingested_at,
            )
            if not hmac.compare_digest(stored_body_hmac, expected_body_hmac):
                raise LedgerError("event integrity verification failed")
            if not hmac.compare_digest(
                bytes(row["canonical_hmac"]), expected_canonical_hmac
            ):
                raise LedgerError("event integrity verification failed")
            if not hmac.compare_digest(
                bytes(row["integrity_hmac"]), expected_integrity_hmac
            ):
                raise LedgerError("event integrity verification failed")
            return event
        except (
            IndexError,
            InvalidEnvelopeError,
            KeyError,
            LedgerError,
            TypeError,
            ValueError,
        ) as exc:
            raise LedgerError("event integrity verification failed") from exc

    def event_identity_status(self, value: EventInput) -> str:
        """Return ``absent``, ``same``, or ``conflict`` for an event id."""
        event = self._event_from_input(value, shard=None, table_name=None)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
        if row is None:
            return "absent"
        stored_event = self._event_from_row(row)
        if hmac.compare_digest(
            self._event_canonical_hmac(stored_event),
            self._event_canonical_hmac(event),
        ):
            return "same"
        return "conflict"

    def ingest_events(
        self,
        events: Iterable[EventInput],
        *,
        shard: str | None = None,
        table_name: str | None = None,
        cursor: Cursor | tuple[int, int] | None = None,
    ) -> int:
        """Atomically insert events, deduplicate, and advance one table cursor."""
        raw_events = list(events)
        if len(raw_events) > MAX_EVENT_BATCH:
            raise ValueError(f"event batch exceeds {MAX_EVENT_BATCH} rows")
        normalized = [
            self._event_from_input(value, shard=shard, table_name=table_name)
            for value in raw_events
        ]

        if cursor is not None:
            new_cursor = _normalize_cursor(cursor)
            cursor_shard = _required_string(shard, "shard", maximum=1_024)
            cursor_table = _required_string(table_name, "table name")
        elif normalized:
            sources = {(event.shard, event.table_name) for event in normalized}
            if len(sources) != 1:
                raise ValueError(
                    "a batch without an explicit cursor must use one source"
                )
            cursor_shard, cursor_table = next(iter(sources))
            new_cursor = max(
                Cursor(event.create_time, event.local_id) for event in normalized
            )
        else:
            return 0

        if any(
            event.shard != cursor_shard or event.table_name != cursor_table
            for event in normalized
        ):
            raise ValueError("all batch events must match the cursor source")

        inserted = 0
        now = int(time.time())
        with self._transaction() as connection:
            previous_row = connection.execute(
                "SELECT create_time, local_id FROM cursors "
                "WHERE shard = ? AND table_name = ?",
                (cursor_shard, cursor_table),
            ).fetchone()
            previous = (
                Cursor(int(previous_row[0]), int(previous_row[1]))
                if previous_row is not None
                else None
            )

            for event in normalized:
                body_hmac = _hmac_parts(
                    self._body_hmac_key,
                    b"event-body-v1",
                    event.body.encode("utf-8"),
                )
                canonical_hmac = self._event_canonical_hmac(event)
                integrity_hmac = self._event_integrity_hmac(
                    event,
                    body_hmac,
                    now,
                )
                encrypted = self._cipher.encrypt(
                    self._event_payload(event),
                    aad=self._event_payload_aad(event),
                )
                result = connection.execute(
                    "INSERT OR IGNORE INTO events("
                    "event_id, shard, table_name, create_time, local_id, "
                    "contact_key, direction, local_type, body_hmac, "
                    "canonical_hmac, integrity_hmac, payload_envelope, ingested_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.event_id,
                        event.shard,
                        event.table_name,
                        event.create_time,
                        event.local_id,
                        event.contact_key,
                        event.direction,
                        str(event.local_type),
                        body_hmac,
                        canonical_hmac,
                        integrity_hmac,
                        encrypted,
                        now,
                    ),
                )
                if result.rowcount == 1:
                    inserted += 1
                    continue
                existing = connection.execute(
                    "SELECT * FROM events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()
                if existing is None:
                    raise EventCollisionError(event.event_id)
                stored_event = self._event_from_row(existing)
                if not hmac.compare_digest(
                    self._event_canonical_hmac(stored_event),
                    self._event_canonical_hmac(event),
                ):
                    raise EventCollisionError(event.event_id)

            committed_cursor = max(
                candidate
                for candidate in (previous, new_cursor)
                if candidate is not None
            )
            cursor_advanced = previous is None or committed_cursor > previous
            connection.execute(
                "INSERT INTO cursors("
                "shard, table_name, create_time, local_id, updated_at"
                ") VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(shard, table_name) DO UPDATE SET "
                "create_time = excluded.create_time, "
                "local_id = excluded.local_id, "
                "updated_at = excluded.updated_at",
                (
                    cursor_shard,
                    cursor_table,
                    committed_cursor.create_time,
                    committed_cursor.local_id,
                    now,
                ),
            )
            if inserted or cursor_advanced:
                self._append_audit(
                    connection,
                    action="ingest_events",
                    object_id="event_batch",
                    payload={
                        "cursor": list(committed_cursor),
                        "inserted": inserted,
                        "scanned": len(normalized),
                        "shard": cursor_shard,
                        "table_name": cursor_table,
                    },
                )
        return inserted

    def get_cursor(self, shard: str, table_name: str) -> Cursor | None:
        normalized_shard = _required_string(shard, "shard", maximum=1_024)
        normalized_table = _required_string(table_name, "table name")
        with self._lock:
            row = self._connection.execute(
                "SELECT create_time, local_id FROM cursors "
                "WHERE shard = ? AND table_name = ?",
                (normalized_shard, normalized_table),
            ).fetchone()
        if row is None:
            return None
        return Cursor(int(row[0]), int(row[1]))

    @staticmethod
    def _restore_local_type(value: str) -> int | str:
        try:
            return int(value)
        except ValueError:
            return value

    def iter_recent_events(
        self,
        *,
        limit: int = 100,
        contact_key: str | None = None,
        after_epoch: int | None = None,
        direction: str | None = None,
    ) -> Iterator[LedgerEvent]:
        """Yield the selected recent window in chronological order."""
        normalized_limit = _integer(limit, "limit", minimum=1)
        if normalized_limit > MAX_RECENT_LIMIT:
            raise ValueError(f"limit must not exceed {MAX_RECENT_LIMIT}")
        clauses: list[str] = []
        parameters: list[object] = []
        if contact_key is not None:
            clauses.append("contact_key = ?")
            parameters.append(_required_string(contact_key, "contact key"))
        if after_epoch is not None:
            clauses.append("create_time >= ?")
            parameters.append(_integer(after_epoch, "after epoch"))
        if direction is not None:
            if direction not in {"inbound", "outbound"}:
                raise ValueError("direction must be inbound or outbound")
            clauses.append("direction = ?")
            parameters.append(direction)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(normalized_limit)
        sql = (
            f"SELECT * FROM events{where} "
            "ORDER BY create_time DESC, local_id DESC, event_id DESC LIMIT ?"
        )
        with self._lock:
            rows = self._connection.execute(sql, tuple(parameters)).fetchall()

        restored = [self._event_from_row(row) for row in rows]
        yield from reversed(restored)

    def _send_payload_aad(self, idempotency_key: str) -> bytes:
        return f"send_attempts:{idempotency_key}".encode("utf-8")

    def _reservation_from_row(
        self,
        row: sqlite3.Row,
        *,
        created: bool,
    ) -> SendReservation:
        idempotency_key = str(row["idempotency_key"])
        plaintext = self._cipher.decrypt(
            bytes(row["payload_envelope"]),
            aad=self._send_payload_aad(idempotency_key),
        )
        stored = _decode_json(plaintext)
        payload = stored.get("payload", {})
        if not isinstance(payload, dict) or not isinstance(stored.get("body"), str):
            raise LedgerError("encrypted send payload is invalid")
        return SendReservation(
            idempotency_key=idempotency_key,
            contact_key=str(row["contact_key"]),
            body=str(stored["body"]),
            status=str(row["status"]),
            payload=cast(Mapping[str, JSONValue], payload),
            reserved_at=int(row["reserved_at"]),
            updated_at=int(row["updated_at"]),
            created=created,
        )

    def reserve_send(
        self,
        idempotency_key: str,
        contact_key: str,
        body: str,
        *,
        payload: Mapping[str, JSONValue] | None = None,
        now_epoch: int | None = None,
    ) -> SendReservation:
        normalized_key = _required_string(
            idempotency_key, "idempotency key", maximum=512
        )
        normalized_contact = _required_string(contact_key, "contact key")
        if not isinstance(body, str) or not body:
            raise ValueError("send body must be a non-empty string")
        normalized_payload = dict(payload or {})
        _canonical_json(normalized_payload)
        now = (
            int(time.time()) if now_epoch is None else _integer(now_epoch, "now epoch")
        )
        body_hmac = _hmac_parts(
            self._body_hmac_key,
            b"send-body-v1",
            body.encode("utf-8"),
        )
        request_hmac = _hmac_parts(
            self._request_hmac_key,
            b"send-request-v1",
            normalized_contact.encode("utf-8"),
            body.encode("utf-8"),
            _canonical_json(normalized_payload),
        )
        stored_payload = {
            "body": body,
            "payload": normalized_payload,
            "transitions": [],
            "v": 1,
        }
        encrypted = self._cipher.encrypt(
            _canonical_json(stored_payload),
            aad=self._send_payload_aad(normalized_key),
        )

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM send_attempts WHERE idempotency_key = ?",
                (normalized_key,),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(
                    bytes(existing["request_hmac"]), request_hmac
                ):
                    raise IdempotencyConflictError(
                        "idempotency key was already used for another send"
                    )
                return self._reservation_from_row(existing, created=False)

            if self._send_dedupe_seconds:
                duplicate = connection.execute(
                    "SELECT idempotency_key FROM send_attempts "
                    "WHERE contact_key = ? AND body_hmac = ? AND reserved_at >= ? "
                    "AND status != ? "
                    "ORDER BY reserved_at DESC LIMIT ?",
                    (
                        normalized_contact,
                        body_hmac,
                        max(0, now - self._send_dedupe_seconds),
                        "cancelled",
                        1,
                    ),
                ).fetchone()
                if duplicate is not None:
                    raise DuplicateSendError("equivalent send is already reserved")

            connection.execute(
                "INSERT INTO send_attempts("
                "idempotency_key, contact_key, body_hmac, request_hmac, status, "
                "payload_envelope, reserved_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    normalized_key,
                    normalized_contact,
                    body_hmac,
                    request_hmac,
                    "reserved",
                    encrypted,
                    now,
                    now,
                ),
            )
            self._append_audit(
                connection,
                action="reserve_send",
                object_id=normalized_key,
                payload={"contact_key": normalized_contact, "status": "reserved"},
            )
            row = connection.execute(
                "SELECT * FROM send_attempts WHERE idempotency_key = ?",
                (normalized_key,),
            ).fetchone()
            if row is None:  # pragma: no cover - protected by the transaction
                raise LedgerError("send reservation was not persisted")
            return self._reservation_from_row(row, created=True)

    def get_send_attempt(self, idempotency_key: str) -> SendReservation | None:
        normalized_key = _required_string(
            idempotency_key, "idempotency key", maximum=512
        )
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM send_attempts WHERE idempotency_key = ?",
                (normalized_key,),
            ).fetchone()
        if row is None:
            return None
        return self._reservation_from_row(row, created=False)

    def transition_send(
        self,
        idempotency_key: str,
        new_status: str,
        *,
        expected_status: str | None = None,
        payload: Mapping[str, JSONValue] | None = None,
        now_epoch: int | None = None,
    ) -> SendReservation:
        normalized_key = _required_string(
            idempotency_key, "idempotency key", maximum=512
        )
        normalized_status = _required_string(new_status, "send status", maximum=32)
        if normalized_status not in _SEND_TRANSITIONS:
            raise ValueError("unknown send status")
        if expected_status is not None and expected_status not in _SEND_TRANSITIONS:
            raise ValueError("unknown expected send status")
        detail = dict(payload or {})
        _canonical_json(detail)
        now = (
            int(time.time()) if now_epoch is None else _integer(now_epoch, "now epoch")
        )

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM send_attempts WHERE idempotency_key = ?",
                (normalized_key,),
            ).fetchone()
            if row is None:
                raise LedgerError("send reservation was not found")
            current_status = str(row["status"])
            if expected_status is not None and current_status != expected_status:
                raise InvalidSendTransitionError("send status changed concurrently")
            if current_status == normalized_status:
                return self._reservation_from_row(row, created=False)
            if normalized_status not in _SEND_TRANSITIONS.get(
                current_status, frozenset()
            ):
                raise InvalidSendTransitionError(
                    f"send transition {current_status} -> {normalized_status} is not allowed"
                )

            stored = _decode_json(
                self._cipher.decrypt(
                    bytes(row["payload_envelope"]),
                    aad=self._send_payload_aad(normalized_key),
                )
            )
            transitions = stored.get("transitions", [])
            if not isinstance(transitions, list):
                raise LedgerError("encrypted send payload is invalid")
            transitions.append(
                {
                    "at": now,
                    "from": current_status,
                    "payload": detail,
                    "to": normalized_status,
                }
            )
            stored["transitions"] = transitions
            encrypted = self._cipher.encrypt(
                _canonical_json(stored),
                aad=self._send_payload_aad(normalized_key),
            )
            result = connection.execute(
                "UPDATE send_attempts SET status = ?, payload_envelope = ?, "
                "updated_at = ? WHERE idempotency_key = ? AND status = ?",
                (
                    normalized_status,
                    encrypted,
                    now,
                    normalized_key,
                    current_status,
                ),
            )
            if result.rowcount != 1:
                raise InvalidSendTransitionError("send status changed concurrently")
            self._append_audit(
                connection,
                action="transition_send",
                object_id=normalized_key,
                payload={
                    "from": current_status,
                    "payload": detail,
                    "to": normalized_status,
                },
            )
            updated = connection.execute(
                "SELECT * FROM send_attempts WHERE idempotency_key = ?",
                (normalized_key,),
            ).fetchone()
            if updated is None:  # pragma: no cover - protected by the transaction
                raise LedgerError("send reservation disappeared")
            return self._reservation_from_row(updated, created=False)

    @staticmethod
    def _runtime_route(
        record_id: str,
        namespace: str,
        scope: str,
        kind: str,
        occurred_at: int,
    ) -> bytes:
        return _canonical_json(
            {
                "kind": kind,
                "namespace": namespace,
                "occurred_at": occurred_at,
                "record_id": record_id,
                "scope": scope,
                "v": 2,
            }
        )

    def _runtime_payload_aad(
        self,
        record_id: str,
        namespace: str,
        scope: str,
        kind: str,
        occurred_at: int,
    ) -> bytes:
        return b"runtime-records-v2\x00" + self._runtime_route(
            record_id,
            namespace,
            scope,
            kind,
            occurred_at,
        )

    def _runtime_canonical_hmac(
        self,
        record_id: str,
        namespace: str,
        scope: str,
        kind: str,
        occurred_at: int,
        payload: Mapping[str, JSONValue],
    ) -> bytes:
        return _hmac_parts(
            self._runtime_hmac_key,
            b"runtime-record-v2",
            self._runtime_route(
                record_id,
                namespace,
                scope,
                kind,
                occurred_at,
            ),
            _canonical_json({"payload": dict(payload), "v": 2}),
        )

    def _runtime_record_from_row(
        self,
        row: sqlite3.Row,
        *,
        created: bool,
    ) -> RuntimeRecord:
        try:
            record_id = _required_string(
                str(row["record_id"]), "record id", maximum=512
            )
            namespace = _required_string(
                str(row["namespace"]), "record namespace", maximum=64
            )
            scope = _required_string(str(row["scope"]), "record scope", maximum=512)
            kind = _required_string(str(row["kind"]), "record kind", maximum=64)
            occurred_at = _integer(row["occurred_at"], "occurred at")
            decoded = _decode_json(
                self._cipher.decrypt(
                    bytes(row["payload_envelope"]),
                    aad=self._runtime_payload_aad(
                        record_id,
                        namespace,
                        scope,
                        kind,
                        occurred_at,
                    ),
                )
            )
            payload = decoded.get("payload")
            if decoded.get("v") != 2 or not isinstance(payload, dict):
                raise LedgerError("runtime record integrity verification failed")
            normalized_payload = cast(Mapping[str, JSONValue], payload)
            expected_hmac = self._runtime_canonical_hmac(
                record_id,
                namespace,
                scope,
                kind,
                occurred_at,
                normalized_payload,
            )
            if not hmac.compare_digest(bytes(row["canonical_hmac"]), expected_hmac):
                raise LedgerError("runtime record integrity verification failed")
            return RuntimeRecord(
                record_id=record_id,
                namespace=namespace,
                scope=scope,
                kind=kind,
                occurred_at=occurred_at,
                payload=normalized_payload,
                created=created,
            )
        except (
            IndexError,
            InvalidEnvelopeError,
            KeyError,
            LedgerError,
            TypeError,
            ValueError,
        ) as exc:
            raise LedgerError("runtime record integrity verification failed") from exc

    def append_runtime_record(
        self,
        record_id: str,
        namespace: str,
        scope: str,
        kind: str,
        payload: Mapping[str, JSONValue],
        *,
        occurred_at: int | None = None,
        activate: bool = False,
    ) -> RuntimeRecord:
        """Append an immutable encrypted record and optionally activate its scope."""
        normalized_id = _required_string(record_id, "record id", maximum=512)
        normalized_namespace = _required_string(
            namespace, "record namespace", maximum=64
        )
        normalized_scope = _required_string(scope, "record scope", maximum=512)
        normalized_kind = _required_string(kind, "record kind", maximum=64)
        if not isinstance(payload, Mapping):
            raise TypeError("runtime record payload must be a mapping")
        normalized_payload = cast(Mapping[str, JSONValue], dict(payload))
        _canonical_json(normalized_payload)
        timestamp = (
            int(time.time())
            if occurred_at is None
            else _integer(occurred_at, "occurred at")
        )
        canonical_hmac = self._runtime_canonical_hmac(
            normalized_id,
            normalized_namespace,
            normalized_scope,
            normalized_kind,
            timestamp,
            normalized_payload,
        )
        encrypted = self._cipher.encrypt(
            _canonical_json({"payload": normalized_payload, "v": 2}),
            aad=self._runtime_payload_aad(
                normalized_id,
                normalized_namespace,
                normalized_scope,
                normalized_kind,
                timestamp,
            ),
        )

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM runtime_records WHERE record_id = ?",
                (normalized_id,),
            ).fetchone()
            if existing is not None:
                record = self._runtime_record_from_row(existing, created=False)
                expected_existing_hmac = self._runtime_canonical_hmac(
                    normalized_id,
                    normalized_namespace,
                    normalized_scope,
                    normalized_kind,
                    record.occurred_at,
                    normalized_payload,
                )
                if not hmac.compare_digest(
                    bytes(existing["canonical_hmac"]), expected_existing_hmac
                ):
                    raise IdempotencyConflictError(
                        "runtime record id was already used for another payload"
                    )
                if activate:
                    self._set_active_runtime_record(
                        connection,
                        normalized_namespace,
                        normalized_scope,
                        normalized_id,
                        timestamp,
                    )
                return record

            connection.execute(
                "INSERT INTO runtime_records("
                "record_id, namespace, scope, kind, occurred_at, "
                "canonical_hmac, payload_envelope"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    normalized_id,
                    normalized_namespace,
                    normalized_scope,
                    normalized_kind,
                    timestamp,
                    canonical_hmac,
                    encrypted,
                ),
            )
            if activate:
                self._set_active_runtime_record(
                    connection,
                    normalized_namespace,
                    normalized_scope,
                    normalized_id,
                    timestamp,
                )
            self._append_audit(
                connection,
                action="append_runtime_record",
                object_id=normalized_id,
                payload={
                    "activated": activate,
                    "kind": normalized_kind,
                    "namespace": normalized_namespace,
                    "scope": normalized_scope,
                },
            )
            row = connection.execute(
                "SELECT * FROM runtime_records WHERE record_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:  # pragma: no cover - protected by the transaction
                raise LedgerError("runtime record was not persisted")
            return self._runtime_record_from_row(row, created=True)

    def get_runtime_record(self, record_id: str) -> RuntimeRecord | None:
        normalized_id = _required_string(record_id, "record id", maximum=512)
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM runtime_records WHERE record_id = ?",
                (normalized_id,),
            ).fetchone()
        if row is None:
            return None
        return self._runtime_record_from_row(row, created=False)

    def list_runtime_records(
        self,
        namespace: str,
        *,
        scope: str | None = None,
        kind: str | None = None,
        after_epoch: int | None = None,
        limit: int = 1_000,
    ) -> tuple[RuntimeRecord, ...]:
        normalized_namespace = _required_string(
            namespace, "record namespace", maximum=64
        )
        normalized_limit = _integer(limit, "limit", minimum=1)
        if normalized_limit > MAX_RECENT_LIMIT:
            raise ValueError(f"limit must not exceed {MAX_RECENT_LIMIT}")
        clauses = ["namespace = ?"]
        parameters: list[object] = [normalized_namespace]
        if scope is not None:
            clauses.append("scope = ?")
            parameters.append(_required_string(scope, "record scope", maximum=512))
        if kind is not None:
            clauses.append("kind = ?")
            parameters.append(_required_string(kind, "record kind", maximum=64))
        if after_epoch is not None:
            clauses.append("occurred_at >= ?")
            parameters.append(_integer(after_epoch, "after epoch"))
        parameters.append(normalized_limit)
        sql = (
            "SELECT * FROM runtime_records WHERE "
            + " AND ".join(clauses)
            + " ORDER BY occurred_at, record_id LIMIT ?"
        )
        with self._lock:
            rows = self._connection.execute(sql, tuple(parameters)).fetchall()
        return tuple(self._runtime_record_from_row(row, created=False) for row in rows)

    def _set_active_runtime_record(
        self,
        connection: sqlite3.Connection,
        namespace: str,
        scope: str,
        record_id: str,
        timestamp: int,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM runtime_records WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise LedgerError("active runtime record was not found")
        record = self._runtime_record_from_row(row, created=False)
        if record.namespace != namespace or record.scope != scope:
            raise IdempotencyConflictError(
                "active runtime record crosses a namespace or scope"
            )
        connection.execute(
            "INSERT INTO runtime_active(namespace, scope, record_id, updated_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(namespace, scope) DO UPDATE SET "
            "record_id = excluded.record_id, updated_at = excluded.updated_at",
            (namespace, scope, record_id, timestamp),
        )

    def set_active_runtime_record(
        self,
        namespace: str,
        scope: str,
        record_id: str,
        *,
        occurred_at: int | None = None,
    ) -> RuntimeRecord:
        normalized_namespace = _required_string(
            namespace, "record namespace", maximum=64
        )
        normalized_scope = _required_string(scope, "record scope", maximum=512)
        normalized_id = _required_string(record_id, "record id", maximum=512)
        timestamp = (
            int(time.time())
            if occurred_at is None
            else _integer(occurred_at, "occurred at")
        )
        with self._transaction() as connection:
            self._set_active_runtime_record(
                connection,
                normalized_namespace,
                normalized_scope,
                normalized_id,
                timestamp,
            )
            self._append_audit(
                connection,
                action="set_active_runtime_record",
                object_id=normalized_id,
                payload={
                    "namespace": normalized_namespace,
                    "scope": normalized_scope,
                },
            )
            row = connection.execute(
                "SELECT * FROM runtime_records WHERE record_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:  # pragma: no cover
                raise LedgerError("active runtime record disappeared")
            return self._runtime_record_from_row(row, created=False)

    def get_active_runtime_record(
        self,
        namespace: str,
        scope: str,
    ) -> RuntimeRecord | None:
        normalized_namespace = _required_string(
            namespace, "record namespace", maximum=64
        )
        normalized_scope = _required_string(scope, "record scope", maximum=512)
        with self._lock:
            row = self._connection.execute(
                "SELECT active.namespace AS active_namespace, "
                "active.scope AS active_scope, "
                "active.record_id AS active_record_id, "
                "records.record_id AS record_id, "
                "records.namespace AS namespace, records.scope AS scope, "
                "records.kind AS kind, records.occurred_at AS occurred_at, "
                "records.canonical_hmac AS canonical_hmac, "
                "records.payload_envelope AS payload_envelope "
                "FROM runtime_active AS active "
                "LEFT JOIN runtime_records AS records "
                "ON records.record_id = active.record_id "
                "WHERE active.namespace = ? AND active.scope = ?",
                (normalized_namespace, normalized_scope),
            ).fetchone()
        if row is None:
            return None
        if row["record_id"] is None:
            raise LedgerError("active runtime record integrity verification failed")
        record = self._runtime_record_from_row(row, created=False)
        if (
            str(row["active_namespace"]) != normalized_namespace
            or str(row["active_scope"]) != normalized_scope
            or str(row["active_record_id"]) != record.record_id
            or record.namespace != normalized_namespace
            or record.scope != normalized_scope
        ):
            raise LedgerError("active runtime record integrity verification failed")
        return record

    def _audit_entry_hash(
        self,
        sequence: int,
        occurred_at: int,
        action: str,
        object_id: str,
        payload_envelope: bytes,
        prev_hash: bytes,
    ) -> bytes:
        return _hmac_parts(
            self._audit_hmac_key,
            b"audit-entry-v1",
            str(sequence).encode("ascii"),
            str(occurred_at).encode("ascii"),
            action.encode("utf-8"),
            object_id.encode("utf-8"),
            payload_envelope,
            prev_hash,
        )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        object_id: str,
        payload: Mapping[str, JSONValue],
    ) -> None:
        head = connection.execute(
            "SELECT sequence, entry_hash FROM audit_chain "
            "ORDER BY sequence DESC LIMIT ?",
            (1,),
        ).fetchone()
        sequence = 1 if head is None else int(head["sequence"]) + 1
        prev_hash = _ZERO_HASH if head is None else bytes(head["entry_hash"])
        occurred_at = time.time_ns()
        normalized_action = _required_string(action, "audit action", maximum=128)
        normalized_object = _required_string(object_id, "audit object", maximum=512)
        aad = f"audit:{sequence}:{normalized_action}:{normalized_object}".encode(
            "utf-8"
        )
        encrypted = self._cipher.encrypt(
            _canonical_json({"payload": dict(payload), "v": 1}),
            aad=aad,
        )
        entry_hash = self._audit_entry_hash(
            sequence,
            occurred_at,
            normalized_action,
            normalized_object,
            encrypted,
            prev_hash,
        )
        connection.execute(
            "INSERT INTO audit_chain("
            "sequence, occurred_at, action, object_id, payload_envelope, "
            "prev_hash, entry_hash"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sequence,
                occurred_at,
                normalized_action,
                normalized_object,
                encrypted,
                prev_hash,
                entry_hash,
            ),
        )
        connection.execute(
            "INSERT INTO ledger_meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("audit_head_sequence", str(sequence).encode("ascii")),
        )
        connection.execute(
            "INSERT INTO ledger_meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("audit_head_hash", entry_hash),
        )

    def verify_audit_chain(self) -> bool:
        """Verify entry HMACs, links, sequence continuity, and the stored head."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT sequence, occurred_at, action, object_id, "
                "payload_envelope, prev_hash, entry_hash "
                "FROM audit_chain ORDER BY sequence"
            ).fetchall()
            head_rows = self._connection.execute(
                "SELECT key, value FROM ledger_meta WHERE key IN (?, ?)",
                ("audit_head_sequence", "audit_head_hash"),
            ).fetchall()
        metadata = {str(row["key"]): bytes(row["value"]) for row in head_rows}

        previous = _ZERO_HASH
        expected_sequence = 1
        for row in rows:
            sequence = int(row["sequence"])
            if sequence != expected_sequence:
                return False
            stored_prev = bytes(row["prev_hash"])
            if not hmac.compare_digest(stored_prev, previous):
                return False
            expected = self._audit_entry_hash(
                sequence,
                int(row["occurred_at"]),
                str(row["action"]),
                str(row["object_id"]),
                bytes(row["payload_envelope"]),
                stored_prev,
            )
            stored_hash = bytes(row["entry_hash"])
            if not hmac.compare_digest(stored_hash, expected):
                return False
            previous = stored_hash
            expected_sequence += 1

        if not rows:
            return not metadata
        try:
            stored_head_sequence = int(metadata["audit_head_sequence"].decode("ascii"))
            stored_head_hash = metadata["audit_head_hash"]
        except (KeyError, UnicodeDecodeError, ValueError):
            return False
        return stored_head_sequence == len(rows) and hmac.compare_digest(
            stored_head_hash, previous
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                self._connection.close()
                self._closed = True
                try:
                    self.path.chmod(PRIVATE_FILE_MODE)
                except OSError:
                    pass

    def __enter__(self) -> EncryptedLedger:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


Ledger = EncryptedLedger


__all__ = [
    "Cursor",
    "DuplicateSendError",
    "EncryptedLedger",
    "EventCollisionError",
    "IdempotencyConflictError",
    "InvalidSendTransitionError",
    "Ledger",
    "LedgerError",
    "LedgerEvent",
    "LedgerKeyError",
    "SCHEMA_VERSION",
    "RuntimeRecord",
    "SendReservation",
]
