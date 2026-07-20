#!/usr/bin/env python3
"""Batch-decrypt macOS WeChat 4.x SQLCipher databases."""

from __future__ import annotations

import argparse
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.wechat_db.common import (  # noqa: E402
    DatabaseFile,
    collect_databases,
    find_sqlcipher,
    load_key_store,
    quote_sql_string,
    resolve_db_dir,
    verify_raw_key,
)


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _absolute_output_path(path: Path) -> Path:
    return path.expanduser().absolute()


def _validate_owned_output_chain(path: Path) -> None:
    """Reject user-controlled symlinks and foreign-owned path components."""
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    seen_owned_component = current_uid is None
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not _lexists(current):
            continue
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            # macOS has root-owned aliases such as /var -> /private/var. They are
            # tolerated only before entering the current user's owned subtree.
            if (
                seen_owned_component
                or current_uid is None
                or metadata.st_uid == current_uid
            ):
                raise ValueError(f"Refusing symbolic-link output path: {current}")
            continue
        if current_uid is None:
            continue
        if metadata.st_uid == current_uid:
            seen_owned_component = True
        elif seen_owned_component:
            raise ValueError(f"Output path is not owned by the current user: {current}")
    if not seen_owned_component:
        raise ValueError(f"Output path has no current-user-owned parent: {path}")


def _validate_owned_directory(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Refusing symbolic-link output directory: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"Expected an output directory: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError(f"Output directory is not owned by the current user: {path}")


def _ensure_private_output_directory(path: Path) -> Path:
    path = _absolute_output_path(path)
    _validate_owned_output_chain(path)

    missing: list[Path] = []
    cursor = path
    while not _lexists(cursor):
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    _validate_owned_directory(cursor)

    for directory in reversed(missing):
        try:
            directory.mkdir(mode=PRIVATE_DIR_MODE)
        except FileExistsError:
            pass
        _validate_owned_directory(directory)
        directory.chmod(PRIVATE_DIR_MODE)

    _validate_owned_directory(path)
    path.chmod(PRIVATE_DIR_MODE)
    return path


def _prepare_private_output_file(path: Path) -> Path:
    path = _absolute_output_path(path)
    _ensure_private_output_directory(path.parent)
    _validate_owned_output_chain(path)
    if _lexists(path):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"Refusing symbolic-link output file: {path}")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Expected a regular output file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError(f"Output file is not owned by the current user: {path}")
        path.chmod(PRIVATE_FILE_MODE)
    return path


def _validate_owned_regular_file(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Expected a non-symlink regular output file: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError(f"Output file is not owned by the current user: {path}")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def verify_plain_database(path: Path) -> tuple[bool, str]:
    if not path.is_file() or path.stat().st_size == 0:
        return False, "output file is missing or empty"
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            row = connection.execute("PRAGMA quick_check").fetchone()
            tables = connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
            ).fetchone()[0]
        if not row or row[0] != "ok":
            return False, f"quick_check returned: {row[0] if row else 'no result'}"
        return True, f"OK ({tables} tables)"
    except (OSError, sqlite3.DatabaseError) as exc:
        return False, str(exc)


def decrypt_database(
    sqlcipher: str,
    database: DatabaseFile,
    destination: Path,
    key: str,
    timeout: int,
) -> tuple[bool, str]:
    destination = _prepare_private_output_file(destination)
    descriptor, temp_name = tempfile.mkstemp(
        dir=str(destination.parent), prefix=f".{destination.name}.", suffix=".tmp"
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
    finally:
        os.close(descriptor)
    escaped_output = quote_sql_string(str(temp_path.resolve()))
    commands = f""".bail on
PRAGMA key = \"x'{key}'\";
PRAGMA cipher_page_size = 4096;
SELECT count(*) FROM sqlite_master;
ATTACH DATABASE '{escaped_output}' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
"""
    try:
        try:
            result = subprocess.run(
                [sqlcipher, str(database.path)],
                input=commands,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"timed out after {timeout}s"
        except OSError as exc:
            return False, str(exc)

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            return (
                False,
                detail[-1] if detail else f"sqlcipher exited {result.returncode}",
            )

        valid, detail = verify_plain_database(temp_path)
        if not valid:
            return False, detail
        _validate_owned_regular_file(temp_path)
        temp_path.chmod(PRIVATE_FILE_MODE)
        _prepare_private_output_file(destination)
        os.replace(temp_path, destination)
        destination.chmod(PRIVATE_FILE_MODE)
        _fsync_directory(destination.parent)
        return True, detail
    finally:
        if _lexists(temp_path):
            temp_path.unlink()


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Decrypt macOS WeChat 4.x databases")
    parser.add_argument("--db-dir", help="Account db_storage directory")
    parser.add_argument("--keys", default="wechat_keys.json")
    parser.add_argument("-o", "--output", default="decrypted")
    parser.add_argument("--force", action="store_true", help="Replace valid outputs")
    parser.add_argument("--timeout", type=int, default=600, help="Seconds per database")
    args = parser.parse_args()

    try:
        db_dir, candidates = resolve_db_dir(args.db_dir)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if len(candidates) > 1 and not args.db_dir:
        print(f"[*] Multiple accounts found; using most recently active: {db_dir}")
    else:
        print(f"[*] Database directory: {db_dir}")

    try:
        key_store = load_key_store(args.keys)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(f"Could not load key file {args.keys}: {exc}")
    sqlcipher = find_sqlcipher()
    if not sqlcipher:
        parser.error("sqlcipher was not found. Install it with: brew install sqlcipher")

    databases = collect_databases(db_dir)
    try:
        output = _ensure_private_output_directory(Path(args.output))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    decrypted = skipped = missing = failed = 0
    print(f"[*] Decrypting {len(databases)} databases with {sqlcipher}")

    for database in databases:
        key = key_store.key_for(database)
        if not key:
            print(f"[MISS] {database.relative_path}: no key for salt {database.salt}")
            missing += 1
            continue
        if not verify_raw_key(key, database.first_page):
            print(f"[FAIL] {database.relative_path}: key did not pass page HMAC verification")
            failed += 1
            continue

        try:
            destination = _prepare_private_output_file(
                output.joinpath(*database.relative_path.split("/"))
            )
        except (OSError, ValueError) as exc:
            print(f"[FAIL] {database.relative_path}: {exc}")
            failed += 1
            continue
        if destination.exists() and not args.force:
            valid, _ = verify_plain_database(destination)
            if valid:
                print(f"[SKIP] {database.relative_path}: valid plaintext database exists")
                skipped += 1
                continue

        success, detail = decrypt_database(
            sqlcipher, database, destination, key, max(1, args.timeout)
        )
        if success:
            print(f"[ OK ] {database.relative_path}: {detail}")
            decrypted += 1
        else:
            print(f"[FAIL] {database.relative_path}: {detail}")
            failed += 1

    print(
        f"[*] Done: {decrypted} decrypted, {skipped} unchanged, "
        f"{missing} missing keys, {failed} failed"
    )
    if decrypted or skipped:
        print(f"[*] Plaintext database root: {output}")
    return 1 if missing or failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
