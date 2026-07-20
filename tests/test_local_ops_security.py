from __future__ import annotations

import importlib.metadata
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import export_contact
import personal_agent
from personal_agent import cli
from personal_agent.service import ServiceManager
from tools.wechat_db import decrypt_macos
from tools.wechat_db.common import DatabaseFile


ROOT = Path(__file__).resolve().parents[1]


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class PrivateOutputTests(unittest.TestCase):
    def test_export_json_is_atomic_and_private(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "private" / "contact.json"

            export_contact._atomic_write_json(output, {"message": "private"})

            self.assertEqual(_mode(output.parent), 0o700)
            self.assertEqual(_mode(output), 0o600)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {"message": "private"},
            )

            original = output.read_bytes()
            with self.assertRaises(TypeError):
                export_contact._atomic_write_json(output, {"invalid": {1}})
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(list(output.parent.glob(f".{output.name}.*.tmp")), [])

    def test_export_rejects_symlink_and_foreign_owned_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target.json"
            target.write_text("untouched", encoding="utf-8")
            link = root / "contact.json"
            link.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "symbolic-link"):
                export_contact._atomic_write_json(link, {"secret": True})
            self.assertEqual(target.read_text(encoding="utf-8"), "untouched")

            foreign = root / "foreign.json"
            with mock.patch.object(
                export_contact.os, "getuid", return_value=os.getuid() + 1
            ):
                with self.assertRaisesRegex(ValueError, "current-user-owned"):
                    export_contact._prepare_private_output_file(foreign)

    def test_decrypt_uses_private_atomic_destination(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            encrypted = root / "encrypted.db"
            encrypted.write_bytes(b"encrypted")
            database = DatabaseFile(
                "message/message_0.db",
                encrypted,
                encrypted.stat().st_size,
                "00" * 16,
                b"",
            )
            destination = root / "decrypted" / "message" / "message_0.db"

            def fake_sqlcipher(arguments, **kwargs):
                commands = kwargs["input"]
                match = re.search(r"ATTACH DATABASE '([^']+)'", commands)
                self.assertIsNotNone(match)
                temp_path = Path(match.group(1))
                with sqlite3.connect(temp_path) as connection:
                    connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
                return _completed(0)

            with mock.patch.object(
                decrypt_macos.subprocess, "run", side_effect=fake_sqlcipher
            ):
                success, detail = decrypt_macos.decrypt_database(
                    "/usr/local/bin/sqlcipher",
                    database,
                    destination,
                    "ab" * 32,
                    5,
                )

            self.assertTrue(success, detail)
            self.assertEqual(_mode(destination.parent.parent), 0o700)
            self.assertEqual(_mode(destination.parent), 0o700)
            self.assertEqual(_mode(destination), 0o600)
            self.assertTrue(decrypt_macos.verify_plain_database(destination)[0])
            self.assertEqual(
                list(destination.parent.glob(f".{destination.name}.*.tmp")), []
            )

    def test_decrypt_rejects_symlink_without_invoking_sqlcipher(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            encrypted = root / "encrypted.db"
            encrypted.write_bytes(b"encrypted")
            database = DatabaseFile("message.db", encrypted, 9, "00" * 16, b"")
            target = root / "target.db"
            target.write_bytes(b"untouched")
            destination = root / "plain.db"
            destination.symlink_to(target)

            with mock.patch.object(decrypt_macos.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "symbolic-link"):
                    decrypt_macos.decrypt_database(
                        "sqlcipher", database, destination, "ab" * 32, 5
                    )
            run.assert_not_called()
            self.assertEqual(target.read_bytes(), b"untouched")

            foreign = root / "foreign.db"
            with mock.patch.object(
                decrypt_macos.os, "getuid", return_value=os.getuid() + 1
            ):
                with self.assertRaisesRegex(ValueError, "current-user-owned"):
                    decrypt_macos._prepare_private_output_file(foreign)

    def test_command_entries_set_private_umask(self):
        with mock.patch.object(export_contact.os, "umask") as export_umask:
            with mock.patch.object(sys, "argv", ["export_contact.py"]):
                with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
                    export_contact.main()
        export_umask.assert_called_once_with(0o077)

        with mock.patch.object(decrypt_macos.os, "umask") as decrypt_umask:
            with mock.patch.object(sys, "argv", ["ginger-wechat-decrypt"]):
                with mock.patch.object(
                    decrypt_macos,
                    "resolve_db_dir",
                    side_effect=FileNotFoundError("missing database"),
                ):
                    with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        decrypt_macos.main()
        decrypt_umask.assert_called_once_with(0o077)


class ServiceSecurityTests(unittest.TestCase):
    def _manager(self, root: Path, runner) -> tuple[ServiceManager, Path]:
        plist = root / "agent.plist"
        plist.write_text("plist", encoding="utf-8")
        paths = SimpleNamespace(
            root=root,
            logs=root / "logs",
            launch_agent=plist,
            pause_marker=root / "PAUSED",
            kill_switch=root / "KILL_SWITCH",
        )
        manager = ServiceManager(
            paths,
            Path(sys.executable),
            root / "config.toml",
            30,
            runner=runner,
        )
        return manager, plist

    def test_uninstall_keeps_plist_when_bootout_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            calls = []

            def runner(arguments, **_kwargs):
                calls.append(arguments)
                return _completed(5, stderr="permission denied")

            manager, plist = self._manager(Path(temp_dir), runner)
            with self.assertRaisesRegex(RuntimeError, "Could not bootout"):
                manager.uninstall()

            self.assertTrue(plist.exists())
            self.assertEqual(len(calls), 1)

    def test_uninstall_keeps_plist_when_service_is_still_loaded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            responses = iter((_completed(0), _completed(0, stdout="loaded")))
            manager, plist = self._manager(
                Path(temp_dir), lambda _arguments, **_kwargs: next(responses)
            )

            with self.assertRaisesRegex(RuntimeError, "still loaded"):
                manager.uninstall()
            self.assertTrue(plist.exists())

    def test_uninstall_print_confirms_stop_before_plist_removal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            calls = []
            plist_holder = {}

            def runner(arguments, **_kwargs):
                calls.append(arguments)
                if arguments[1] == "print":
                    self.assertTrue(plist_holder["path"].exists())
                    return _completed(113, stderr="service not found")
                return _completed(0)

            manager, plist = self._manager(root, runner)
            plist_holder["path"] = plist

            result = manager.uninstall()

            self.assertFalse(plist.exists())
            self.assertTrue(result["stopped"])
            self.assertTrue(result["removed"])
            self.assertEqual([call[1] for call in calls], ["bootout", "print"])

    def test_agent_executable_is_current_interpreter_sibling_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            interpreter_dir = root / "venv" / "bin"
            interpreter_dir.mkdir(parents=True)
            interpreter = interpreter_dir / "python"
            executable = interpreter_dir / "ginger-agent"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)

            with mock.patch.object(cli.sys, "executable", str(interpreter)):
                self.assertEqual(cli._agent_executable(), executable.absolute())

                executable.chmod(0o720)
                with self.assertRaisesRegex(ValueError, "group- or world-writable"):
                    cli._agent_executable()

                executable.unlink()
                real_entry = root / "real-agent"
                real_entry.write_text("#!/bin/sh\n", encoding="utf-8")
                real_entry.chmod(0o700)
                executable.symlink_to(real_entry)
                with self.assertRaisesRegex(ValueError, "symbolic-link"):
                    cli._agent_executable()

    def test_agent_executable_does_not_fall_back_to_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            interpreter = root / "venv" / "bin" / "python"
            path_entry = root / "path" / "ginger-agent"
            path_entry.parent.mkdir()
            path_entry.write_text("#!/bin/sh\n", encoding="utf-8")
            path_entry.chmod(0o700)

            with mock.patch.object(cli.sys, "executable", str(interpreter)):
                with mock.patch.dict(os.environ, {"PATH": str(path_entry.parent)}):
                    with self.assertRaisesRegex(ValueError, "missing"):
                        cli._agent_executable()


class ReleaseAndCliSecurityTests(unittest.TestCase):
    def test_installer_validates_all_entries_before_symlink_switch(self):
        script = (ROOT / "install-macos.sh").read_text(encoding="utf-8")
        validation = script.index('"$ENTRY" --help')
        switch = script.index('ln -s "$NEW_VENV" "$NEW_LINK"')
        self.assertLess(validation, switch)
        before_switch = script[:switch]
        for command in (
            "ginger-agent",
            "ginger-shadow-replay",
            "ginger-wechat-db-doctor",
            "ginger-wechat-find-keys",
            "ginger-wechat-decrypt",
        ):
            self.assertIn(command, before_switch)

    def test_package_version_comes_from_distribution_metadata(self):
        try:
            expected = importlib.metadata.version("ginger-personal-agent")
        except importlib.metadata.PackageNotFoundError:
            expected = "0+unknown"
        self.assertEqual(personal_agent.__version__, expected)
        source = (ROOT / "personal_agent" / "__init__.py").read_text(encoding="utf-8")
        self.assertNotIn('__version__ = "0.2.0rc1"', source)
        self.assertNotIn('__version__ = "0.1.0"', source)

    def test_distillation_mutations_redact_payload_from_stdout(self):
        result = {
            "version_id": "v1",
            "payload_hash": "hash",
            "payload": {"private": "do not print"},
        }
        cases = (
            (
                "_command_distill_put",
                [
                    "distill-put",
                    "--domain",
                    "style",
                    "--payload-file",
                    "ignored.json",
                    "--confidence",
                    "1",
                ],
            ),
            (
                "_command_distill_activate",
                ["distill-activate", "--version-id", "v1"],
            ),
            (
                "_command_distill_rollback",
                [
                    "distill-rollback",
                    "--domain",
                    "style",
                    "--version-id",
                    "v1",
                ],
            ),
        )
        for handler, argv in cases:
            with self.subTest(command=argv[0]):
                stdout = io.StringIO()
                with mock.patch.object(cli, handler, return_value=dict(result)):
                    with redirect_stdout(stdout):
                        self.assertEqual(cli.main(argv), 0)
                public = json.loads(stdout.getvalue())
                self.assertNotIn("payload", public)
                self.assertEqual(public["payload_hash"], "hash")
                self.assertNotIn("do not print", stdout.getvalue())

    def test_distillation_list_payload_requires_explicit_include(self):
        versions = [
            {
                "version_id": "v1",
                "payload_hash": "hash",
                "payload": {"private": "listed only on request"},
            }
        ]

        def invoke(include_payload: bool):
            args = SimpleNamespace(
                domain="style", contact_key=None, include_payload=include_payload
            )
            with mock.patch.object(cli, "_runtime_config", return_value=object()):
                with mock.patch.object(
                    cli,
                    "_with_ledger",
                    side_effect=lambda _config, callback: callback(object()),
                ):
                    with mock.patch.object(
                        cli, "list_distillations", return_value=list(versions)
                    ):
                        return cli._command_distill_list(args)

        self.assertNotIn("payload", invoke(False)["versions"][0])
        self.assertEqual(
            invoke(True)["versions"][0]["payload"],
            {"private": "listed only on request"},
        )


if __name__ == "__main__":
    unittest.main()
