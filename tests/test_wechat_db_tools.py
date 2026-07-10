from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.wechat_db import common
from tools.wechat_db.decrypt_macos import verify_plain_database
from tools.wechat_db.find_keys_macos import choose_process_id, parse_key_specs


class WeChatDatabaseToolTests(unittest.TestCase):
    def test_discovery_prefers_most_recent_account(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old = root / "old_account" / "db_storage" / "message" / "message_0.db"
            new = root / "new_account" / "db_storage" / "contact" / "contact.db"
            old.parent.mkdir(parents=True)
            new.parent.mkdir(parents=True)
            old.write_bytes(b"a" * common.PAGE_SIZE)
            new.write_bytes(b"b" * common.PAGE_SIZE)
            os.utime(old, (10, 10))
            os.utime(new, (20, 20))

            found = common.discover_db_dirs((root,))

            self.assertEqual(found, [new.parents[1].resolve(), old.parents[1].resolve()])

    def test_discovery_supports_current_xwechat_files_layout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            documents = Path(temp_dir) / "Documents"
            db_path = (
                documents
                / "xwechat_files"
                / "wxid_example_0ad"
                / "db_storage"
                / "message"
                / "message_0.db"
            )
            db_path.parent.mkdir(parents=True)
            db_path.write_bytes(b"a" * common.PAGE_SIZE)

            found = common.discover_db_dirs((documents,))

            self.assertEqual(found, [db_path.parents[1].resolve()])

    def test_key_store_supports_legacy_paths_and_salt_index(self):
        key_a = "a" * 64
        key_b = "b" * 64
        salt = "1" * 32
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "keys.json"
            path.write_text(
                json.dumps(
                    {
                        "message/message_0.db": key_a,
                        "__format__": "ginger-wechat-keys-v2",
                        "__keys_by_salt__": {salt: key_b},
                    }
                ),
                encoding="utf-8",
            )

            store = common.load_key_store(path)

            self.assertEqual(store.path_keys["message/message_0.db"], key_a)
            self.assertEqual(store.salt_keys[salt], key_b)

    def test_saved_key_file_is_private_and_backward_compatible(self):
        key = "c" * 64
        page = b"2" * common.PAGE_SIZE
        database = common.DatabaseFile(
            "contact/contact.db", Path("contact.db"), len(page), "2" * 32, page
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "wechat_keys.json"

            common.save_key_store(path, [database], {database.salt: key})
            data = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(data[database.relative_path], key)
            self.assertEqual(data["__keys_by_salt__"][database.salt], key)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_first_page_hmac_verification(self):
        key = bytes.fromhex("ab" * common.KEY_SIZE)
        salt = bytes.fromhex("cd" * common.SALT_SIZE)
        page = bytearray(os.urandom(common.PAGE_SIZE))
        page[: common.SALT_SIZE] = salt
        hmac_salt = bytes(value ^ 0x3A for value in salt)
        hmac_key = hashlib.pbkdf2_hmac(
            "sha512", key, hmac_salt, 2, dklen=common.KEY_SIZE
        )
        digest = hmac.new(
            hmac_key,
            page[common.SALT_SIZE : common.PAGE_SIZE - 64],
            hashlib.sha512,
        )
        digest.update(struct.pack("<I", 1))
        page[-64:] = digest.digest()

        self.assertTrue(common.verify_raw_key(key.hex(), bytes(page)))
        self.assertFalse(common.verify_raw_key((b"x" * common.KEY_SIZE).hex(), bytes(page)))

    def test_keyspec_parser_supports_key_only_and_key_plus_salt(self):
        key = b"a" * 64
        salt = b"b" * 32
        parsed = parse_key_specs(b"before x'" + key + b"' x'" + key + salt + b"' after")
        self.assertEqual(parsed, [(key.decode(), None), (key.decode(), salt.decode())])

    @mock.patch("tools.wechat_db.find_keys_macos._open_database_score")
    @mock.patch("tools.wechat_db.find_keys_macos.list_process_ids")
    def test_process_selection_uses_unique_database_owner(self, list_pids, score):
        list_pids.return_value = [100, 200]
        score.side_effect = lambda pid, _db_dir: {100: 0, 200: 4}[pid]
        selected, pids = choose_process_id("WeChat", Path("/tmp/db_storage"), None)
        self.assertEqual(selected, 200)
        self.assertEqual(pids, [100, 200])

    @mock.patch("tools.wechat_db.find_keys_macos._open_database_score")
    @mock.patch("tools.wechat_db.find_keys_macos.list_process_ids")
    def test_process_selection_error_gives_pid_commands(self, list_pids, score):
        list_pids.return_value = [100, 200]
        score.return_value = 0

        with self.assertRaisesRegex(RuntimeError, r"--pid 100"):
            choose_process_id("WeChat", Path("/tmp/db_storage"), None)

    def test_plain_database_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "plain.db"
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")

            valid, detail = verify_plain_database(path)

            self.assertTrue(valid, detail)
            self.assertIn("1 tables", detail)


if __name__ == "__main__":
    unittest.main()
