"""Shared helpers for macOS WeChat database discovery and key handling."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Union


PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
SQLITE_HEADER = b"SQLite format 3\x00"
KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SALT_RE = re.compile(r"^[0-9a-fA-F]{32}$")

DEFAULT_WECHAT_ROOTS = (
    Path.home()
    / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
    Path.home()
    / "Library/Containers/com.tencent.xinWeChatBeta/Data/Documents/xwechat_files",
    Path.home() / "Library/Containers/com.tencent.xinWeChat/Data/Documents",
    Path.home() / "Library/Containers/com.tencent.xinWeChatBeta/Data/Documents",
)

PathInput = Union[str, os.PathLike]


@dataclass(frozen=True)
class DatabaseFile:
    relative_path: str
    path: Path
    size: int
    salt: str
    first_page: bytes


@dataclass(frozen=True)
class KeyStore:
    path_keys: dict[str, str]
    salt_keys: dict[str, str]

    def key_for(self, database: DatabaseFile) -> Optional[str]:
        return self.path_keys.get(database.relative_path) or self.salt_keys.get(
            database.salt
        )


def _contains_database(path: Path) -> bool:
    try:
        return any(
            child.is_file() and child.suffix == ".db"
            for child in path.rglob("*.db")
        )
    except OSError:
        return False


def _activity_time(path: Path) -> float:
    newest = 0.0
    try:
        for db_path in path.rglob("*.db"):
            try:
                newest = max(newest, db_path.stat().st_mtime)
            except OSError:
                continue
    except OSError:
        pass
    return newest


def _db_storage_candidates(root: Path) -> Iterable[Path]:
    if root.name == "db_storage":
        yield root
        return
    if root.name == "xwechat_files":
        yield from root.glob("*/db_storage")
        return

    # Current stable/beta clients store accounts below xwechat_files. The
    # direct pattern keeps compatibility with older test fixtures and layouts.
    yield from root.glob("*/db_storage")
    yield from root.glob("xwechat_files/*/db_storage")


def discover_db_dirs(roots: Optional[Iterable[Path]] = None) -> list[Path]:
    """Find account-specific db_storage directories, newest activity first."""
    found: dict[str, Path] = {}
    for raw_root in roots or DEFAULT_WECHAT_ROOTS:
        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            continue
        for candidate in _db_storage_candidates(root):
            if candidate.is_dir() and _contains_database(candidate):
                resolved = candidate.resolve()
                found[str(resolved)] = resolved
    return sorted(found.values(), key=_activity_time, reverse=True)


def resolve_db_dir(
    explicit: Optional[PathInput] = None,
) -> tuple[Path, list[Path]]:
    """Resolve one db_storage directory and return it with all candidates."""
    if explicit:
        path = Path(explicit).expanduser().resolve()
        candidates = discover_db_dirs((path,))
        if path.name == "db_storage" and path.is_dir() and _contains_database(path):
            return path, [path]
        if not candidates:
            raise FileNotFoundError(f"No db_storage directory found under: {path}")
        return candidates[0], candidates

    candidates = discover_db_dirs()
    if not candidates:
        searched = ", ".join(str(path) for path in DEFAULT_WECHAT_ROOTS)
        raise FileNotFoundError(f"No WeChat db_storage directory found under: {searched}")
    return candidates[0], candidates


def collect_databases(db_dir: Path) -> list[DatabaseFile]:
    """Collect encrypted .db files and their SQLCipher salt."""
    databases: list[DatabaseFile] = []
    for path in sorted(db_dir.rglob("*.db")):
        if path.name.endswith(("-wal", "-shm")):
            continue
        try:
            size = path.stat().st_size
            if size < PAGE_SIZE:
                continue
            with path.open("rb") as handle:
                first_page = handle.read(PAGE_SIZE)
        except OSError:
            continue
        if len(first_page) != PAGE_SIZE or first_page.startswith(SQLITE_HEADER):
            continue
        databases.append(
            DatabaseFile(
                relative_path=path.relative_to(db_dir).as_posix(),
                path=path,
                size=size,
                salt=first_page[:SALT_SIZE].hex(),
                first_page=first_page,
            )
        )
    return databases


def validate_key(value: object) -> Optional[str]:
    if isinstance(value, str) and KEY_RE.fullmatch(value):
        return value.lower()
    return None


def load_key_store(path: PathInput) -> KeyStore:
    """Load both legacy path keys and the salt-indexed v2 metadata."""
    with Path(path).expanduser().open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Key file must contain a JSON object")

    path_keys: dict[str, str] = {}
    for relative_path, value in data.items():
        if relative_path.startswith("__"):
            continue
        key = validate_key(value)
        if key:
            path_keys[relative_path] = key

    salt_keys: dict[str, str] = {}
    raw_salt_keys = data.get("__keys_by_salt__", {})
    if isinstance(raw_salt_keys, dict):
        for salt, value in raw_salt_keys.items():
            key = validate_key(value)
            if isinstance(salt, str) and SALT_RE.fullmatch(salt) and key:
                salt_keys[salt.lower()] = key

    return KeyStore(path_keys=path_keys, salt_keys=salt_keys)


def load_key_store_if_present(path: PathInput) -> KeyStore:
    try:
        return load_key_store(path)
    except FileNotFoundError:
        return KeyStore(path_keys={}, salt_keys={})


def save_key_store(
    path: PathInput,
    databases: Iterable[DatabaseFile],
    keys_by_salt: Mapping[str, str],
) -> None:
    """Atomically save a backward-compatible key file with mode 0600."""
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, object] = {}
    if output.exists():
        try:
            with output.open(encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict):
                existing = loaded
        except (OSError, ValueError):
            existing = {}

    normalized_salts = {
        salt.lower(): key.lower()
        for salt, key in keys_by_salt.items()
        if SALT_RE.fullmatch(salt) and validate_key(key)
    }
    old_salts = existing.get("__keys_by_salt__", {})
    if isinstance(old_salts, dict):
        for salt, value in old_salts.items():
            key = validate_key(value)
            if isinstance(salt, str) and SALT_RE.fullmatch(salt) and key:
                normalized_salts.setdefault(salt.lower(), key)

    result = {
        key: value
        for key, value in existing.items()
        if not key.startswith("__") and validate_key(value)
    }
    for database in databases:
        key = normalized_salts.get(database.salt)
        if key:
            result[database.relative_path] = key
    result["__format__"] = "ginger-wechat-keys-v2"
    result["__keys_by_salt__"] = dict(sorted(normalized_salts.items()))

    fd, temp_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temp_name, output)
        output.chmod(0o600)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def verify_raw_key(key_hex: str, first_page: bytes) -> bool:
    """Verify a 32-byte raw key against a WeChat SQLCipher first page."""
    key = validate_key(key_hex)
    if not key or len(first_page) != PAGE_SIZE:
        return False
    salt = first_page[:SALT_SIZE]
    hmac_salt = bytes(value ^ 0x3A for value in salt)
    hmac_key = hashlib.pbkdf2_hmac(
        "sha512", bytes.fromhex(key), hmac_salt, 2, dklen=KEY_SIZE
    )
    encrypted_payload = first_page[SALT_SIZE : PAGE_SIZE - 64]
    expected = first_page[PAGE_SIZE - 64 :]
    digest = hmac.new(hmac_key, encrypted_payload, hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(digest.digest(), expected)


def find_sqlcipher() -> Optional[str]:
    from_path = shutil.which("sqlcipher")
    if from_path:
        return from_path
    for candidate in (
        "/opt/homebrew/opt/sqlcipher/bin/sqlcipher",
        "/usr/local/opt/sqlcipher/bin/sqlcipher",
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def quote_sql_string(value: str) -> str:
    return value.replace("'", "''")
