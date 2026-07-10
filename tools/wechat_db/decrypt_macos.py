#!/usr/bin/env python3
"""Batch-decrypt macOS WeChat 4.x SQLCipher databases."""

from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
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
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temp_path.unlink(missing_ok=True)
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
        result = subprocess.run(
            [sqlcipher, str(database.path)],
            input=commands,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        temp_path.unlink(missing_ok=True)
        return False, f"timed out after {timeout}s"
    except OSError as exc:
        temp_path.unlink(missing_ok=True)
        return False, str(exc)

    if result.returncode != 0:
        temp_path.unlink(missing_ok=True)
        detail = (result.stderr or result.stdout).strip().splitlines()
        return False, detail[-1] if detail else f"sqlcipher exited {result.returncode}"

    valid, detail = verify_plain_database(temp_path)
    if not valid:
        temp_path.unlink(missing_ok=True)
        return False, detail
    os.replace(temp_path, destination)
    return True, detail


def main() -> int:
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
    output = Path(args.output).expanduser().resolve()
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

        destination = output.joinpath(*database.relative_path.split("/"))
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
