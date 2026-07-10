#!/usr/bin/env python3
"""Read-only compatibility checks for the bundled macOS WeChat DB tools."""

from __future__ import annotations

import argparse
import platform
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.wechat_db.common import (  # noqa: E402
    collect_databases,
    find_sqlcipher,
    resolve_db_dir,
)
from tools.wechat_db.find_keys_macos import process_database_scores  # noqa: E402


WECHAT_APPS = (
    Path("/Applications/WeChat.app"),
    Path.home() / "Applications/WeChat.app",
    Path("/Applications/Weixin.app"),
    Path.home() / "Applications/Weixin.app",
)


def read_app_version(app_path: Path) -> tuple[str, str]:
    info_path = app_path / "Contents/Info.plist"
    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return "unknown", "unknown"
    return (
        str(info.get("CFBundleShortVersionString", "unknown")),
        str(info.get("CFBundleVersion", "unknown")),
    )


def command_output(command: list[str]) -> Optional[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout or result.stderr).strip()
    return output or None


def print_status(label: str, value: str) -> None:
    print(f"{label:<18} {value}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check macOS WeChat 4.x data, LLDB, and SQLCipher readiness"
    )
    parser.add_argument("--db-dir", help="Account db_storage directory")
    parser.add_argument("--process-name", default="WeChat")
    args = parser.parse_args()

    print("WeChat database tool doctor (read-only)")
    print_status("macOS", platform.mac_ver()[0] or "unknown")
    print_status("architecture", platform.machine())

    installed_apps = [path for path in WECHAT_APPS if path.is_dir()]
    if installed_apps:
        for app_path in installed_apps:
            version, build = read_app_version(app_path)
            print_status("WeChat app", f"{version} ({build}) at {app_path}")
    else:
        print_status("WeChat app", "not found in /Applications or ~/Applications")

    try:
        db_dir, candidates = resolve_db_dir(args.db_dir)
    except FileNotFoundError as exc:
        print_status("database", f"not found: {exc}")
        db_dir = None
        candidates = []
    if db_dir is not None:
        databases = collect_databases(db_dir)
        salt_count = len({database.salt for database in databases})
        print_status("database", str(db_dir))
        print_status("encrypted DBs", f"{len(databases)} files / {salt_count} salts")
        if len(candidates) > 1:
            print_status("accounts", f"{len(candidates)} found; newest activity selected")

        scores = process_database_scores(args.process_name, db_dir)
        if scores:
            for process_id, open_count in scores.items():
                print_status("WeChat PID", f"{process_id} ({open_count} open DB files)")
            best = max(scores.values())
            winners = [pid for pid, score in scores.items() if score == best and score > 0]
            if len(winners) == 1:
                print_status("recommended PID", str(winners[0]))
            elif len(scores) > 1:
                print_status("PID selection", "ambiguous; pass --pid to find_keys_macos.py")
        else:
            print_status("WeChat process", f"no running process named {args.process_name}")

    lldb = shutil.which("lldb")
    print_status("lldb", lldb or "not found (install Xcode Command Line Tools)")
    if lldb:
        print_status("lldb Python", command_output([lldb, "-P"]) or "module path unavailable")
    print_status("sqlcipher", find_sqlcipher() or "not found (brew install sqlcipher)")
    print_status("SIP", command_output(["csrutil", "status"]) or "status unavailable")

    if db_dir is not None:
        print("\nKey scan command:")
        print(
            '  PYTHONPATH="$(lldb -P)" '
            "/Library/Developer/CommandLineTools/usr/bin/python3 "
            "tools/wechat_db/find_keys_macos.py --output wechat_keys.json"
        )
        print("Decrypt command:")
        print(
            "  python3 tools/wechat_db/decrypt_macos.py "
            "--keys wechat_keys.json --output decrypted"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
