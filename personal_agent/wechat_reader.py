"""Read-only incremental reader for macOS WeChat message databases.

This module has no model or network dependency. Raw WeChat usernames are used
only while a database is being scanned and are replaced with keyed identities
before events reach the ledger.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import stat
import subprocess
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final, Literal, Protocol, TypeAlias, cast

from .crypto_store import MAX_ENVELOPE_BYTES
from .ledger import Cursor, EncryptedLedger, LedgerEvent


MESSAGE_DATABASE_RE: Final = re.compile(r"^message_(\d+)\.db$")
MESSAGE_TABLE_RE: Final = re.compile(r"^Msg_[0-9a-f]{32}$")
PARAMETER_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
ZSTD_MAGIC: Final = b"\x28\xb5\x2f\xfd"
ZSTD_UNAVAILABLE_MARKER: Final = "[zstd-compressed:decoder-unavailable]"
ZSTD_FAILED_MARKER: Final = "[zstd-compressed:decode-failed]"
BINARY_CONTENT_MARKER: Final = "[binary-content:undecodable]"
CONTENT_TOO_LARGE_MARKER: Final = "[content-too-large:skipped]"
MAX_QUERY_ROWS: Final = 10_000
MAX_READBACK_EVENTS: Final = 10_000
# Leave room for worst-case JSON control escaping and Base64 envelope expansion.
MAX_BODY_BYTES: Final = min(4 * 1024 * 1024, MAX_ENVELOPE_BYTES // 16)
MAX_MESSAGE_CONTENT_BYTES: Final = MAX_BODY_BYTES
MAX_MESSAGE_HEX_CHARS: Final = MAX_MESSAGE_CONTENT_BYTES * 2
MAX_ZSTD_OUTPUT_BYTES: Final = MAX_BODY_BYTES
MAX_SQLCIPHER_OUTPUT_BYTES: Final = 64 * 1024 * 1024
MAX_DISPLAY_NAME_CHARS: Final = 4_096
MAX_QUERY_PAGE_ROWS: Final = max(
    1,
    MAX_SQLCIPHER_OUTPUT_BYTES // (MAX_MESSAGE_HEX_CHARS + 1_024),
)
TRUSTED_SQLCIPHER_ROOTS: Final = (
    Path("/opt/homebrew"),
    Path("/usr/local"),
    Path("/usr/bin"),
)

QueryParameter: TypeAlias = int | float | None
KeyProvider: TypeAlias = Callable[[Path], bytes | str]
DisplayNameProvider: TypeAlias = Callable[[str], str | None]
Decompressor: TypeAlias = Callable[[bytes], bytes]
RunResult: TypeAlias = subprocess.CompletedProcess[bytes]
Runner: TypeAlias = Callable[..., RunResult]
Direction: TypeAlias = Literal["inbound", "outbound", "unknown"]
ReadbackWatermark: TypeAlias = tuple[int, int] | tuple[int, int, str]


class WeChatReaderError(RuntimeError):
    """Raised when a message source cannot be read safely."""


class ReadOnlyQuery(Protocol):
    def query(
        self,
        database: Path,
        sql: str,
        parameters: Mapping[str, QueryParameter] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute one read-only statement and return named rows."""


def validate_message_table(table_name: str) -> str:
    if not isinstance(table_name, str) or not MESSAGE_TABLE_RE.fullmatch(table_name):
        raise ValueError("invalid WeChat message table name")
    return table_name


def _validate_read_query(sql: str) -> str:
    if not isinstance(sql, str) or not sql.strip() or len(sql) > 32_768:
        raise ValueError("read query is invalid")
    normalized = sql.strip()
    if "\x00" in normalized or ";" in normalized:
        raise ValueError("read query must contain one statement")
    if any(line.lstrip().startswith(".") for line in normalized.splitlines()):
        raise ValueError("read query contains a shell command")
    first_token = normalized.split(None, 1)[0].upper()
    if first_token not in {"SELECT", "WITH", "PRAGMA"}:
        raise ValueError("only read queries are allowed")
    return normalized


def _normalized_parameters(
    parameters: Mapping[str, QueryParameter] | None,
) -> dict[str, QueryParameter]:
    result: dict[str, QueryParameter] = {}
    for name, value in (parameters or {}).items():
        if not PARAMETER_RE.fullmatch(name):
            raise ValueError("query parameter name is invalid")
        if value is not None and isinstance(value, bool):
            raise ValueError("query parameters must be numeric or null")
        if value is not None and not isinstance(value, (int, float)):
            raise ValueError("query parameters must be numeric or null")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("query parameters must be finite")
        result[name] = value
    return result


def _optional_nonnegative_epoch(value: int | None, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _sqlite_uri(path: Path) -> str:
    return f"{path.resolve(strict=True).as_uri()}?mode=ro"


class PlaintextSQLiteQuery:
    """Read-only SQLite backend used for synthetic fixtures and decrypted DBs."""

    def __init__(self, *, timeout_seconds: float = 5.0) -> None:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("SQLite timeout must be between 0 and 60 seconds")
        self._timeout_seconds = float(timeout_seconds)

    def query(
        self,
        database: Path,
        sql: str,
        parameters: Mapping[str, QueryParameter] | None = None,
    ) -> list[dict[str, Any]]:
        statement = _validate_read_query(sql)
        bound = _normalized_parameters(parameters)
        deadline = time.monotonic() + self._timeout_seconds
        try:
            connection = sqlite3.connect(
                _sqlite_uri(database),
                uri=True,
                timeout=self._timeout_seconds,
                isolation_level=None,
            )
        except (OSError, sqlite3.Error) as exc:
            raise WeChatReaderError(
                "could not open the WeChat database read-only"
            ) from exc
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.set_progress_handler(
                lambda: 1 if time.monotonic() > deadline else 0,
                1_000,
            )
            rows = connection.execute(statement, bound).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise WeChatReaderError("read-only WeChat query failed") from exc
        finally:
            connection.close()


def _normalize_sqlcipher_key(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        key = bytes(value)
    elif isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
        key = bytes.fromhex(value)
    else:
        raise WeChatReaderError("SQLCipher key provider returned an invalid key")
    if len(key) != 32:
        raise WeChatReaderError("SQLCipher key provider returned an invalid key")
    return key


def _cli_parameter_literal(value: QueryParameter) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, int):
        return str(value)
    return repr(value)


def _resolve_sqlcipher_executable(executable: str | os.PathLike[str]) -> Path:
    candidate = Path(executable)
    if not candidate.is_absolute() or candidate.name != "sqlcipher":
        raise ValueError("SQLCipher executable must be an absolute sqlcipher path")
    if candidate.is_symlink():
        raise ValueError("SQLCipher executable must not be a symbolic link")

    resolved = candidate.resolve(strict=True)
    metadata = resolved.stat()
    if resolved.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("SQLCipher executable must be a regular file")
    if not metadata.st_mode & 0o111 or not os.access(resolved, os.X_OK):
        raise ValueError("SQLCipher executable must be executable")
    if metadata.st_uid not in {0, os.getuid()}:
        raise ValueError("SQLCipher executable has an untrusted owner")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("SQLCipher executable must not be group or world writable")
    if not any(
        resolved == trusted_root or trusted_root in resolved.parents
        for trusted_root in TRUSTED_SQLCIPHER_ROOTS
    ):
        raise ValueError("SQLCipher executable is outside trusted install roots")
    return resolved


class SQLCipherCLIQuery:
    """Read-only SQLCipher shell backend with an injected per-file key provider."""

    def __init__(
        self,
        key_provider: KeyProvider,
        *,
        executable: str = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher",
        timeout_seconds: float = 10.0,
        runner: Runner = subprocess.run,
    ) -> None:
        executable_path = Path(executable)
        if not executable_path.is_absolute() or executable_path.name != "sqlcipher":
            raise ValueError("SQLCipher executable must be an absolute sqlcipher path")
        if not 0 < timeout_seconds <= 120:
            raise ValueError("SQLCipher timeout must be between 0 and 120 seconds")
        try:
            trusted_executable = _resolve_sqlcipher_executable(executable_path)
            validate_executable = True
        except FileNotFoundError as exc:
            if runner is subprocess.run:
                raise ValueError("SQLCipher executable does not exist") from exc
            # An injected runner is executable code already and may model a binary
            # that intentionally does not exist in unit tests.
            trusted_executable = executable_path
            validate_executable = False
        self._key_provider = key_provider
        self._executable = trusted_executable
        self._validate_executable = validate_executable
        self._timeout_seconds = float(timeout_seconds)
        self._runner = runner

    def query(
        self,
        database: Path,
        sql: str,
        parameters: Mapping[str, QueryParameter] | None = None,
    ) -> list[dict[str, Any]]:
        statement = _validate_read_query(sql)
        bound = _normalized_parameters(parameters)
        executable = self._executable
        if self._validate_executable:
            try:
                executable = _resolve_sqlcipher_executable(executable)
            except (OSError, ValueError) as exc:
                raise WeChatReaderError(
                    "SQLCipher executable is no longer trusted"
                ) from exc
        try:
            key = _normalize_sqlcipher_key(self._key_provider(database))
        except WeChatReaderError:
            raise
        except Exception as exc:
            raise WeChatReaderError("SQLCipher key provider failed") from exc

        commands = [
            ".bail on",
            f".timeout {int(self._timeout_seconds * 1_000)}",
            f"PRAGMA key = \"x'{key.hex()}'\";",
            "PRAGMA cipher_page_size = 4096;",
            "PRAGMA query_only = ON;",
            ".mode json",
            ".parameter init",
        ]
        for name, value in sorted(bound.items()):
            commands.append(f".parameter set :{name} {_cli_parameter_literal(value)}")
        commands.append(statement + ";")
        stdin = ("\n".join(commands) + "\n").encode("utf-8")
        argv = [str(executable), "-readonly", "-batch", str(database)]
        try:
            result = self._runner(
                argv,
                input=stdin,
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise WeChatReaderError("SQLCipher read query timed out") from exc
        except OSError as exc:
            raise WeChatReaderError("SQLCipher read query failed") from exc
        if result.returncode != 0:
            raise WeChatReaderError("SQLCipher read query failed")

        if not isinstance(result.stdout, (bytes, bytearray, memoryview)):
            raise WeChatReaderError("SQLCipher returned an invalid query result")
        if len(result.stdout) > MAX_SQLCIPHER_OUTPUT_BYTES:
            raise WeChatReaderError("SQLCipher query result exceeded the size limit")
        output = bytes(result.stdout).strip()
        if not output:
            return []
        try:
            decoded = json.loads(output.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WeChatReaderError(
                "SQLCipher returned an invalid query result"
            ) from exc
        if not isinstance(decoded, list) or not all(
            isinstance(row, dict) for row in decoded
        ):
            raise WeChatReaderError("SQLCipher returned an invalid query result")
        return [cast(dict[str, Any], row) for row in decoded]


def _message_directory(root: Path) -> Path:
    expanded = root.expanduser()
    if expanded.is_symlink():
        raise ValueError("WeChat database root must not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    message_dir = resolved if resolved.name == "message" else resolved / "message"
    if message_dir.is_symlink():
        raise ValueError("WeChat message directory must not be a symbolic link")
    if not message_dir.is_dir():
        raise FileNotFoundError("WeChat message directory was not found")
    return message_dir


def discover_message_databases(root: str | os.PathLike[str]) -> list[Path]:
    """Discover direct ``message_N.db`` children in numeric shard order."""
    message_dir = _message_directory(Path(root))
    discovered: list[tuple[int, Path]] = []
    for candidate in message_dir.iterdir():
        match = MESSAGE_DATABASE_RE.fullmatch(candidate.name)
        if match is None:
            continue
        if candidate.is_symlink():
            raise ValueError("WeChat message database must not be a symbolic link")
        if (
            not candidate.is_file()
            or candidate.resolve(strict=True).parent != message_dir
        ):
            raise ValueError("WeChat message database path is invalid")
        discovered.append((int(match.group(1)), candidate))
    discovered.sort(key=lambda item: (item[0], item[1].name))
    return [path for _, path in discovered]


def _safe_shard_name(database: Path) -> str:
    match = MESSAGE_DATABASE_RE.fullmatch(database.name)
    if match is None or database.parent.name != "message":
        raise ValueError("invalid WeChat message database path")
    return f"message/{database.name}"


def _table_for_username(username: str) -> str:
    digest = hashlib.md5(
        username.encode("utf-8"),
        usedforsecurity=False,
    ).hexdigest()
    return f"Msg_{digest}"


def _contact_key(identity_secret: bytes, username: str) -> str:
    digest = hmac.new(
        identity_secret,
        b"ginger-contact-key-v2\x00" + username.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"contact_{digest[:32]}"


def _keyed_digest(secret: bytes, domain: bytes, *parts: bytes) -> bytes:
    digest = hmac.new(secret, domain + b"\x00", hashlib.sha256)
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _event_base_id(identity_secret: bytes, contact_key: str, local_id: int) -> str:
    digest = _keyed_digest(
        identity_secret,
        b"ginger-event-base-v2",
        contact_key.encode("utf-8"),
        str(local_id).encode("ascii"),
    )
    return f"evt_{digest.hex()[:32]}"


def _canonical_event_hmac(
    identity_secret: bytes,
    *,
    contact_key: str,
    local_id: int,
    create_time: int,
    local_type: int,
    direction: str,
    body: str,
) -> bytes:
    canonical = json.dumps(
        {
            "body": body,
            "contact_key": contact_key,
            "create_time": create_time,
            "direction": direction,
            "local_id": local_id,
            "local_type": local_type,
            "v": 1,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _keyed_digest(identity_secret, b"ginger-event-canonical-v2", canonical)


def _collision_event_id(
    identity_secret: bytes,
    base_id: str,
    canonical_hmac: bytes,
) -> str:
    digest = _keyed_digest(
        identity_secret,
        b"ginger-event-collision-v2",
        base_id.encode("ascii"),
        canonical_hmac,
    )
    return f"evt_{digest.hex()[:32]}"


def _automatic_zstd_decompressor() -> Decompressor | None:
    try:
        import zstandard  # type: ignore[import-not-found]

        decompressor = zstandard.ZstdDecompressor()

        def bounded_decompress(raw: bytes) -> bytes:
            with decompressor.stream_reader(raw) as reader:
                return cast(bytes, reader.read(MAX_ZSTD_OUTPUT_BYTES + 1))

        return bounded_decompress
    except ImportError:
        try:
            import zstd  # type: ignore[import-not-found]

            return cast(Decompressor, zstd.decompress)
        except ImportError:
            return None


@dataclass(frozen=True)
class DecodedContent:
    body: str
    state: str


def _decode_content(
    raw: bytes,
    compression_type: int,
    decompressor: Decompressor | None,
) -> DecodedContent:
    is_zstd = compression_type == 4 or raw.startswith(ZSTD_MAGIC)
    if is_zstd:
        if len(raw) > MAX_MESSAGE_CONTENT_BYTES:
            return DecodedContent(
                CONTENT_TOO_LARGE_MARKER, "compressed_input_too_large"
            )
        if decompressor is None:
            return DecodedContent(ZSTD_UNAVAILABLE_MARKER, "zstd_decoder_unavailable")
        try:
            raw = decompressor(raw)
        except Exception:
            return DecodedContent(ZSTD_FAILED_MARKER, "zstd_decode_failed")
        if not isinstance(raw, bytes):
            return DecodedContent(ZSTD_FAILED_MARKER, "zstd_decode_failed")
        if len(raw) > MAX_ZSTD_OUTPUT_BYTES:
            return DecodedContent(CONTENT_TOO_LARGE_MARKER, "zstd_output_too_large")
    if len(raw) > MAX_BODY_BYTES:
        return DecodedContent(CONTENT_TOO_LARGE_MARKER, "body_too_large")
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        return DecodedContent(BINARY_CONTENT_MARKER, "binary_undecodable")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        return DecodedContent(CONTENT_TOO_LARGE_MARKER, "body_too_large")
    return DecodedContent(body, "zstd_decoded" if is_zstd else "text")


@dataclass(frozen=True)
class PollResult:
    discovered_databases: int = 0
    scanned_tables: int = 0
    scanned_rows: int = 0
    inserted_events: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ReadbackBaseline:
    outbound_event_ids: frozenset[str] = field(default_factory=frozenset)
    high_watermark: ReadbackWatermark | None = None


def _normalized_event_ids(values: Collection[str] | None) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, (str, bytes)):
        raise TypeError("known outbound event ids must be a collection of strings")
    if len(values) > MAX_READBACK_EVENTS:
        raise ValueError(f"known outbound event ids exceed {MAX_READBACK_EVENTS}")
    normalized = frozenset(values)
    if any(
        not isinstance(event_id, str)
        or not event_id
        or len(event_id) > 512
        or "\x00" in event_id
        for event_id in normalized
    ):
        raise ValueError("known outbound event ids are invalid")
    return normalized


def _normalized_watermark(
    value: ReadbackWatermark | None,
) -> ReadbackWatermark | None:
    if value is None:
        return None
    if not isinstance(value, tuple) or len(value) not in {2, 3}:
        raise ValueError("outbound high watermark must be a two or three item tuple")
    create_time, local_id = value[:2]
    if (
        isinstance(create_time, bool)
        or not isinstance(create_time, int)
        or create_time < 0
        or isinstance(local_id, bool)
        or not isinstance(local_id, int)
        or local_id < 0
    ):
        raise ValueError("outbound high watermark contains an invalid cursor")
    if len(value) == 2:
        return create_time, local_id
    event_id = value[2]
    if (
        not isinstance(event_id, str)
        or not event_id
        or len(event_id) > 512
        or "\x00" in event_id
    ):
        raise ValueError("outbound high watermark contains an invalid event id")
    return create_time, local_id, event_id


def _event_is_after_watermark(
    event: LedgerEvent,
    watermark: ReadbackWatermark,
) -> bool:
    if len(watermark) == 2:
        return (event.create_time, event.local_id) > watermark
    return (event.create_time, event.local_id, event.event_id) > watermark


class WeChatReader:
    """Incrementally copy read-only WeChat rows into an encrypted ledger."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        ledger: EncryptedLedger,
        identity_secret: bytes,
        *,
        query: ReadOnlyQuery | None = None,
        self_username: str | None = None,
        display_name_provider: DisplayNameProvider | None = None,
        overlap_seconds: int = 5,
        batch_size: int = 1_000,
        initial_after_epoch: int | None = None,
        bootstrap_after_epoch: int | None = None,
        zstd_decompressor: Decompressor | None | bool = True,
    ) -> None:
        if not isinstance(identity_secret, bytes) or len(identity_secret) < 32:
            raise ValueError("identity secret must be at least 32 bytes")
        if self_username is not None and not isinstance(self_username, str):
            raise TypeError("self username must be a string or None")
        if not 0 <= overlap_seconds <= 86_400:
            raise ValueError("overlap must be between 0 and 86400 seconds")
        if not 1 <= batch_size <= MAX_QUERY_ROWS:
            raise ValueError(f"batch size must be between 1 and {MAX_QUERY_ROWS}")
        initial_after_epoch = _optional_nonnegative_epoch(
            initial_after_epoch,
            "initial_after_epoch",
        )
        bootstrap_after_epoch = _optional_nonnegative_epoch(
            bootstrap_after_epoch,
            "bootstrap_after_epoch",
        )
        if (
            initial_after_epoch is not None
            and bootstrap_after_epoch is not None
            and initial_after_epoch != bootstrap_after_epoch
        ):
            raise ValueError("initial_after_epoch and bootstrap_after_epoch must match")
        if zstd_decompressor is True:
            decompressor = _automatic_zstd_decompressor()
        elif zstd_decompressor is None or zstd_decompressor is False:
            decompressor = None
        elif callable(zstd_decompressor):
            decompressor = cast(Decompressor, zstd_decompressor)
        else:
            raise TypeError("zstd decompressor must be callable, false, or none")

        self._root = Path(root)
        self._ledger = ledger
        self._identity_secret = bytes(identity_secret)
        self._query = query or PlaintextSQLiteQuery()
        self._self_username = self_username
        self._display_name_provider = display_name_provider
        self._overlap_seconds = int(overlap_seconds)
        self._batch_size = int(batch_size)
        self._query_row_limit = min(self._batch_size, MAX_QUERY_PAGE_ROWS)
        self._bootstrap_after_epoch = (
            bootstrap_after_epoch
            if bootstrap_after_epoch is not None
            else initial_after_epoch
        )
        self._zstd_decompressor = decompressor

    def _list_message_tables(self, database: Path) -> list[str]:
        rows = self._query.query(
            database,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
        )
        tables = {
            str(row["name"])
            for row in rows
            if isinstance(row.get("name"), str)
            and MESSAGE_TABLE_RE.fullmatch(str(row["name"]))
        }
        return sorted(tables)

    def _table_columns(self, database: Path, table_name: str) -> set[str]:
        validated = validate_message_table(table_name)
        rows = self._query.query(database, f'PRAGMA table_info("{validated}")')
        return {str(row["name"]) for row in rows if isinstance(row.get("name"), str)}

    def _name_map(self, database: Path) -> dict[int, str]:
        rows = self._query.query(
            database,
            "SELECT rowid AS sender_id, user_name FROM Name2Id ORDER BY rowid",
        )
        result: dict[int, str] = {}
        for row in rows:
            username = row.get("user_name")
            sender_id = row.get("sender_id")
            if not isinstance(username, str) or not username:
                continue
            try:
                normalized_id = int(cast(Any, sender_id))
            except (TypeError, ValueError):
                continue
            result[normalized_id] = username
        return result

    def _message_rows(
        self,
        database: Path,
        table_name: str,
        *,
        after: Cursor,
        has_compression_column: bool,
    ) -> list[dict[str, Any]]:
        validated = validate_message_table(table_name)
        compression = (
            "CAST(WCDB_CT_message_content AS INTEGER)"
            if has_compression_column
            else "0"
        )
        sql = (
            "SELECT CAST(local_id AS INTEGER) AS local_id, "
            "CAST(local_type AS INTEGER) AS local_type, "
            "CAST(create_time AS INTEGER) AS create_time, "
            "CAST(real_sender_id AS INTEGER) AS real_sender_id, "
            "CASE WHEN message_content IS NULL THEN NULL "
            "WHEN length(message_content) > :max_content_bytes THEN NULL "
            "ELSE hex(message_content) END AS message_content_hex, "
            "CASE WHEN message_content IS NOT NULL "
            "AND length(message_content) > :max_content_bytes "
            "THEN 1 ELSE 0 END AS content_oversized, "
            f"{compression} AS compression_type "
            f'FROM "{validated}" '
            "WHERE (create_time > :after_time OR "
            "(create_time = :after_time AND local_id > :after_local_id)) "
            "ORDER BY create_time, local_id LIMIT :row_limit"
        )
        return self._query.query(
            database,
            sql,
            {
                "after_local_id": after.local_id,
                "after_time": after.create_time,
                "max_content_bytes": MAX_MESSAGE_CONTENT_BYTES,
                "row_limit": self._query_row_limit,
            },
        )

    def _direction(
        self,
        sender_id: int | None,
        sender_username: str | None,
        contact_username: str,
    ) -> Direction:
        if self._self_username is not None:
            if sender_username == self._self_username:
                return "outbound"
            return "inbound" if sender_username is not None else "unknown"
        if contact_username.endswith("@chatroom"):
            return "unknown"
        if sender_username == contact_username:
            return "inbound"
        return "unknown"

    def _event_id(
        self,
        event: LedgerEvent,
        canonical_hmac: bytes,
        page_identities: dict[str, bytes],
    ) -> str:
        base_id = _event_base_id(
            self._identity_secret,
            event.contact_key,
            event.local_id,
        )
        page_canonical = page_identities.get(base_id)
        candidate = (
            _collision_event_id(self._identity_secret, base_id, canonical_hmac)
            if event.direction == "unknown"
            else base_id
        )
        if page_canonical is not None and not hmac.compare_digest(
            page_canonical, canonical_hmac
        ):
            candidate = _collision_event_id(
                self._identity_secret,
                base_id,
                canonical_hmac,
            )
        candidate_event = replace(event, event_id=candidate)
        try:
            identity_status = self._ledger.event_identity_status(candidate_event)
        except ValueError as exc:
            if event.direction != "unknown" or "direction" not in str(exc):
                raise
            identity_status = "absent"
        if identity_status == "conflict":
            candidate = _collision_event_id(
                self._identity_secret,
                base_id,
                canonical_hmac,
            )
            candidate_event = replace(event, event_id=candidate)
            try:
                identity_status = self._ledger.event_identity_status(candidate_event)
            except ValueError as exc:
                if event.direction != "unknown" or "direction" not in str(exc):
                    raise
                identity_status = "absent"
            if identity_status == "conflict":
                raise WeChatReaderError("could not resolve a keyed event id collision")
        page_identities[candidate] = canonical_hmac
        return candidate

    def _row_event(
        self,
        row: Mapping[str, Any],
        *,
        shard: str,
        table_name: str,
        contact_username: str,
        contact_key: str,
        display_name: str | None,
        name_map: Mapping[int, str],
        page_identities: dict[str, bytes],
    ) -> LedgerEvent | None:
        try:
            local_id = int(cast(Any, row.get("local_id")))
            local_type = int(cast(Any, row.get("local_type")))
            create_time = int(cast(Any, row.get("create_time")))
            compression_type = int(cast(Any, row.get("compression_type", 0) or 0))
        except (TypeError, ValueError):
            return None
        if local_id < 0 or create_time < 0:
            return None
        sender_value = row.get("real_sender_id")
        try:
            sender_id = None if sender_value is None else int(cast(Any, sender_value))
        except (TypeError, ValueError):
            sender_id = None
        sender_username = name_map.get(sender_id) if sender_id is not None else None
        direction = self._direction(sender_id, sender_username, contact_username)

        oversized_value = row.get("content_oversized", 0)
        try:
            content_oversized = int(cast(Any, oversized_value) or 0) != 0
        except (TypeError, ValueError):
            return None
        raw_hex = row.get("message_content_hex")
        if content_oversized:
            decoded = DecodedContent(
                CONTENT_TOO_LARGE_MARKER,
                "compressed_input_too_large"
                if compression_type == 4
                else "body_too_large",
            )
        elif raw_hex is None:
            raw_content = b""
            decoded = _decode_content(
                raw_content,
                compression_type,
                self._zstd_decompressor,
            )
        elif isinstance(raw_hex, str):
            if len(raw_hex) > MAX_MESSAGE_HEX_CHARS:
                decoded = DecodedContent(
                    CONTENT_TOO_LARGE_MARKER,
                    "hex_input_too_large",
                )
            elif (
                len(raw_hex) % 2 != 0 or re.fullmatch(r"[0-9a-fA-F]*", raw_hex) is None
            ):
                return None
            else:
                raw_content = bytes.fromhex(raw_hex)
                decoded = _decode_content(
                    raw_content,
                    compression_type,
                    self._zstd_decompressor,
                )
        else:
            return None
        provisional = LedgerEvent(
            event_id="pending",
            contact_key=contact_key,
            direction=direction,
            local_type=local_type,
            create_time=create_time,
            local_id=local_id,
            body=decoded.body,
            contact_display_name=display_name,
            shard=shard,
            table_name=table_name,
            payload={
                "compression_type": compression_type,
                "content_state": decoded.state,
                "sender_resolved": sender_username is not None,
            },
        )
        canonical_hmac = _canonical_event_hmac(
            self._identity_secret,
            contact_key=contact_key,
            local_id=local_id,
            create_time=create_time,
            local_type=local_type,
            direction=direction,
            body=decoded.body,
        )
        return replace(
            provisional,
            event_id=self._event_id(
                provisional,
                canonical_hmac,
                page_identities,
            ),
        )

    def poll(self, *, bootstrap_after_epoch: int | None = None) -> PollResult:
        runtime_bootstrap = _optional_nonnegative_epoch(
            bootstrap_after_epoch,
            "bootstrap_after_epoch",
        )
        databases = discover_message_databases(self._root)
        scanned_tables = 0
        scanned_rows = 0
        inserted_events = 0
        warnings: list[str] = []

        for database in databases:
            shard = _safe_shard_name(database)
            try:
                name_map = self._name_map(database)
                tables = self._list_message_tables(database)
            except WeChatReaderError:
                warnings.append(f"{shard}: database metadata could not be read")
                continue
            usernames_by_table: dict[str, str] = {}
            ambiguous_tables: set[str] = set()
            for username in name_map.values():
                table = _table_for_username(username)
                if (
                    table in usernames_by_table
                    and usernames_by_table[table] != username
                ):
                    ambiguous_tables.add(table)
                    continue
                usernames_by_table[table] = username

            for table_name in tables:
                scanned_tables += 1
                contact_username = usernames_by_table.get(table_name)
                if contact_username is None or table_name in ambiguous_tables:
                    warnings.append(
                        f"{shard}/{table_name}: contact identity unavailable"
                    )
                    continue
                contact_key = _contact_key(self._identity_secret, contact_username)
                display_name = None
                if self._display_name_provider is not None:
                    candidate_name = self._display_name_provider(contact_username)
                    if candidate_name and candidate_name != contact_username:
                        display_name = candidate_name[:MAX_DISPLAY_NAME_CHARS]

                try:
                    columns = self._table_columns(database, table_name)
                except WeChatReaderError:
                    warnings.append(f"{shard}/{table_name}: table metadata read failed")
                    continue
                required = {
                    "create_time",
                    "local_id",
                    "local_type",
                    "message_content",
                    "real_sender_id",
                }
                if not required.issubset(columns):
                    warnings.append(
                        f"{shard}/{table_name}: required columns are missing"
                    )
                    continue

                stored_cursor = self._ledger.get_cursor(shard, table_name)
                if stored_cursor is None:
                    baseline = (
                        runtime_bootstrap
                        if runtime_bootstrap is not None
                        else self._bootstrap_after_epoch
                    )
                    page_cursor = Cursor(
                        baseline if baseline is not None else -1,
                        -1,
                    )
                    if baseline is not None:
                        self._ledger.ingest_events(
                            (),
                            shard=shard,
                            table_name=table_name,
                            cursor=Cursor(baseline, 0),
                        )
                else:
                    page_cursor = Cursor(
                        max(-1, stored_cursor.create_time - self._overlap_seconds),
                        -1,
                    )
                page_identities: dict[str, bytes] = {}

                while True:
                    try:
                        rows = self._message_rows(
                            database,
                            table_name,
                            after=page_cursor,
                            has_compression_column=(
                                "WCDB_CT_message_content" in columns
                            ),
                        )
                    except WeChatReaderError:
                        warnings.append(f"{shard}/{table_name}: message query failed")
                        break
                    if not rows:
                        break

                    events: list[LedgerEvent] = []
                    previous_page_cursor = page_cursor
                    for row in rows:
                        try:
                            row_cursor = Cursor(
                                int(cast(Any, row.get("create_time"))),
                                int(cast(Any, row.get("local_id"))),
                            )
                        except (TypeError, ValueError):
                            warnings.append(
                                f"{shard}/{table_name}: invalid cursor row skipped"
                            )
                            continue
                        if row_cursor <= page_cursor:
                            warnings.append(
                                f"{shard}/{table_name}: non-monotonic row skipped"
                            )
                            continue
                        page_cursor = row_cursor
                        scanned_rows += 1
                        event = self._row_event(
                            row,
                            shard=shard,
                            table_name=table_name,
                            contact_username=contact_username,
                            contact_key=contact_key,
                            display_name=display_name,
                            name_map=name_map,
                            page_identities=page_identities,
                        )
                        if event is None:
                            warnings.append(
                                f"{shard}/{table_name}: malformed row skipped"
                            )
                            continue
                        events.append(event)
                        if (
                            event.payload.get("content_state")
                            == "zstd_decoder_unavailable"
                        ):
                            warnings.append(
                                f"{shard}/{table_name}: zstd decoder unavailable"
                            )
                        if str(event.payload.get("content_state", "")).endswith(
                            "too_large"
                        ):
                            warnings.append(
                                f"{shard}/{table_name}: oversized content skipped"
                            )

                    if page_cursor == previous_page_cursor:
                        warnings.append(f"{shard}/{table_name}: query made no progress")
                        break
                    try:
                        inserted_events += self._ledger.ingest_events(
                            events,
                            shard=shard,
                            table_name=table_name,
                            cursor=page_cursor,
                        )
                    except ValueError as exc:
                        unknown_events = [
                            event for event in events if event.direction == "unknown"
                        ]
                        if (
                            not unknown_events
                            or "direction must be inbound or outbound" not in str(exc)
                        ):
                            raise
                        inserted_events += self._ledger.ingest_events(
                            [event for event in events if event.direction != "unknown"],
                            shard=shard,
                            table_name=table_name,
                            cursor=page_cursor,
                        )
                        warnings.append(
                            f"{shard}/{table_name}: unknown-direction events "
                            "were not persisted by the legacy ledger"
                        )
                    if len(rows) < self._query_row_limit:
                        break

        return PollResult(
            discovered_databases=len(databases),
            scanned_tables=scanned_tables,
            scanned_rows=scanned_rows,
            inserted_events=inserted_events,
            warnings=tuple(dict.fromkeys(warnings)),
        )

    def read_once(self, *, bootstrap_after_epoch: int | None = None) -> PollResult:
        """Compatibility alias for one incremental poll."""
        return self.poll(bootstrap_after_epoch=bootstrap_after_epoch)

    def readback_baseline(
        self,
        contact_key: str,
        *,
        after_epoch: int = 0,
    ) -> ReadbackBaseline:
        """Capture outbound identities and ordering state immediately before a click."""
        if not isinstance(contact_key, str) or not contact_key:
            raise ValueError("contact key must be a non-empty string")
        normalized_after = _optional_nonnegative_epoch(after_epoch, "after epoch")
        assert normalized_after is not None
        self.poll()
        events = tuple(
            self._ledger.iter_recent_events(
                limit=MAX_READBACK_EVENTS,
                contact_key=contact_key,
                after_epoch=normalized_after,
                direction="outbound",
            )
        )
        high_watermark = (
            max((event.create_time, event.local_id, event.event_id) for event in events)
            if events
            else None
        )
        return ReadbackBaseline(
            outbound_event_ids=frozenset(event.event_id for event in events),
            high_watermark=high_watermark,
        )

    def readback_confirm(
        self,
        contact_key: str,
        body: str,
        after_epoch: int,
        *,
        known_outbound_event_ids: Collection[str] | None = None,
        outbound_high_watermark: ReadbackWatermark | None = None,
        baseline: ReadbackBaseline | None = None,
    ) -> bool:
        """Confirm an exact outbound body, optionally requiring post-click identity."""
        if not isinstance(contact_key, str) or not contact_key:
            raise ValueError("contact key must be a non-empty string")
        if not isinstance(body, str):
            raise TypeError("body must be a string")
        target = body.encode("utf-8")
        if len(target) > MAX_BODY_BYTES:
            raise ValueError("readback body exceeds the size limit")
        normalized_after = _optional_nonnegative_epoch(after_epoch, "after epoch")
        assert normalized_after is not None
        if baseline is not None:
            if not isinstance(baseline, ReadbackBaseline):
                raise TypeError("baseline must be a ReadbackBaseline")
            if (
                known_outbound_event_ids is not None
                or outbound_high_watermark is not None
            ):
                raise ValueError(
                    "baseline cannot be combined with explicit readback state"
                )
            known_outbound_event_ids = baseline.outbound_event_ids
            outbound_high_watermark = baseline.high_watermark
        known_ids = _normalized_event_ids(known_outbound_event_ids)
        high_watermark = _normalized_watermark(outbound_high_watermark)

        self.poll()
        for event in self._ledger.iter_recent_events(
            limit=MAX_READBACK_EVENTS,
            contact_key=contact_key,
            after_epoch=normalized_after,
            direction="outbound",
        ):
            if event.event_id in known_ids:
                continue
            if high_watermark is not None and not _event_is_after_watermark(
                event,
                high_watermark,
            ):
                continue
            if hmac.compare_digest(event.body.encode("utf-8"), target):
                return True
        return False


WechatReader = WeChatReader
SQLiteFixtureQuery = PlaintextSQLiteQuery


__all__ = [
    "BINARY_CONTENT_MARKER",
    "CONTENT_TOO_LARGE_MARKER",
    "PlaintextSQLiteQuery",
    "PollResult",
    "ReadbackBaseline",
    "ReadbackWatermark",
    "ReadOnlyQuery",
    "SQLCipherCLIQuery",
    "SQLiteFixtureQuery",
    "WeChatReader",
    "WeChatReaderError",
    "WechatReader",
    "ZSTD_FAILED_MARKER",
    "ZSTD_UNAVAILABLE_MARKER",
    "discover_message_databases",
    "validate_message_table",
]
