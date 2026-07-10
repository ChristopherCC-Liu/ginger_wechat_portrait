#!/usr/bin/env python3
"""Extract per-database SQLCipher keys from a running macOS WeChat 4.x process."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.wechat_db.common import (  # noqa: E402
    DatabaseFile,
    collect_databases,
    load_key_store_if_present,
    resolve_db_dir,
    save_key_store,
    verify_raw_key,
)


KEYSPEC_RE = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
OVERLAP_BYTES = 256


def parse_key_specs(data: bytes) -> list[tuple[str, Optional[str]]]:
    """Return raw-key and optional salt candidates from SQLCipher keyspecs."""
    candidates: list[tuple[str, Optional[str]]] = []
    for match in KEYSPEC_RE.finditer(data):
        value = match.group(1).decode("ascii").lower()
        if len(value) == 64:
            candidates.append((value, None))
        elif len(value) == 96:
            candidates.append((value[:64], value[64:]))
        elif len(value) > 96 and len(value) % 2 == 0:
            candidates.append((value[:64], value[-32:]))
    return candidates


def list_process_ids(process_name: str) -> list[int]:
    result = subprocess.run(
        ["pgrep", "-x", process_name], capture_output=True, text=True, check=False
    )
    return sorted(
        int(line) for line in result.stdout.splitlines() if line.strip().isdigit()
    )


def _open_database_score(pid: int, db_dir: Path) -> int:
    try:
        result = subprocess.run(
            ["lsof", "-Fn", "-a", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    prefix = str(db_dir.resolve()) + os.sep
    return sum(
        1
        for line in result.stdout.splitlines()
        if line.startswith("n") and line[1:].startswith(prefix) and ".db" in line
    )


def choose_process_id(
    process_name: str, db_dir: Path, requested_pid: Optional[int]
) -> tuple[int, list[int]]:
    pids = list_process_ids(process_name)
    if requested_pid is not None:
        if requested_pid not in pids:
            raise RuntimeError(
                f"PID {requested_pid} is not a running process named {process_name}"
            )
        return requested_pid, pids
    if not pids:
        raise RuntimeError(f"No running process named {process_name}")
    if len(pids) == 1:
        return pids[0], pids

    scores = {pid: _open_database_score(pid, db_dir) for pid in pids}
    best = max(scores.values())
    winners = [pid for pid, score in scores.items() if score == best and score > 0]
    if len(winners) == 1:
        return winners[0], pids
    commands = "\n".join(
        "  PYTHONPATH=\"$(lldb -P)\" "
        f"/Library/Developer/CommandLineTools/usr/bin/python3 {Path(__file__).resolve()} "
        f"--pid {pid}  # open database files: {scores[pid]}"
        for pid in pids
    )
    raise RuntimeError(
        "More than one WeChat process is running and no unique database owner "
        f"could be selected:\n{commands}"
    )


def process_database_scores(process_name: str, db_dir: Path) -> dict[int, int]:
    return {
        pid: _open_database_score(pid, db_dir)
        for pid in list_process_ids(process_name)
    }


def _group_by_salt(databases: list[DatabaseFile]) -> dict[str, list[DatabaseFile]]:
    grouped: dict[str, list[DatabaseFile]] = {}
    for database in databases:
        grouped.setdefault(database.salt, []).append(database)
    return grouped


def _match_key(
    key: str,
    salt: Optional[str],
    by_salt: dict[str, list[DatabaseFile]],
    remaining: set[str],
) -> Optional[str]:
    salts = [salt] if salt in remaining else list(remaining) if salt is None else []
    for candidate_salt in salts:
        database = by_salt[candidate_salt][0]
        if verify_raw_key(key, database.first_page):
            return candidate_salt
    return None


def scan_process_memory(
    process,
    lldb_module,
    databases: list[DatabaseFile],
    known_keys: dict[str, str],
    chunk_size: int,
) -> dict[str, str]:
    by_salt = _group_by_salt(databases)
    found = dict(known_keys)
    remaining = set(by_salt) - set(found)
    error = lldb_module.SBError()
    region_info = lldb_module.SBMemoryRegionInfo()
    regions: list[tuple[int, int]] = []
    address = 0

    while True:
        result = process.GetMemoryRegionInfo(address, region_info)
        if result.Fail():
            break
        base = region_info.GetRegionBase()
        end = region_info.GetRegionEnd()
        if end <= base:
            break
        size = end - base
        if (
            region_info.IsReadable()
            and not region_info.IsExecutable()
            and 0 < size <= 2 * 1024 * 1024 * 1024
        ):
            regions.append((base, size))
        address = end
        if address == 0:
            break

    total = sum(size for _, size in regions)
    scanned = 0
    seen_keys: set[tuple[str, Optional[str]]] = set()
    print(f"[*] Scanning {len(regions)} readable regions ({total / 1048576:.0f} MB)")

    for index, (base, size) in enumerate(regions):
        offset = 0
        previous = b""
        while offset < size and remaining:
            read_size = min(chunk_size, size - offset)
            data = process.ReadMemory(base + offset, read_size, error)
            offset += read_size
            scanned += read_size
            if not error.Success() or not data:
                previous = b""
                continue

            combined = previous + data
            for candidate in parse_key_specs(combined):
                if candidate in seen_keys:
                    continue
                seen_keys.add(candidate)
                key, salt = candidate
                matched_salt = _match_key(key, salt, by_salt, remaining)
                if matched_salt:
                    found[matched_salt] = key
                    remaining.remove(matched_salt)
                    names = ", ".join(
                        item.relative_path for item in by_salt[matched_salt]
                    )
                    print(f"[+] Verified key for: {names}")
            previous = combined[-OVERLAP_BYTES:]

        if (index + 1) % 50 == 0 or index == len(regions) - 1 or not remaining:
            progress = scanned / total * 100 if total else 100
            print(f"[*] {progress:.1f}% scanned; {len(found)}/{len(by_salt)} salts found")
        if not remaining:
            break

    if remaining and found:
        for salt in list(remaining):
            database = by_salt[salt][0]
            for key in set(found.values()):
                if verify_raw_key(key, database.first_page):
                    found[salt] = key
                    remaining.remove(salt)
                    break
    return found


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract per-database keys from macOS WeChat 4.x memory"
    )
    parser.add_argument("--db-dir", help="Account db_storage directory")
    parser.add_argument("--pid", type=int, help="Exact WeChat PID when several are running")
    parser.add_argument("--process-name", default="WeChat")
    parser.add_argument(
        "--list-processes",
        action="store_true",
        help="List matching PIDs and their open database counts, then exit",
    )
    parser.add_argument("--output", default="wechat_keys.json")
    parser.add_argument("--chunk-size-mb", type=int, default=8)
    args = parser.parse_args()

    try:
        db_dir, db_candidates = resolve_db_dir(args.db_dir)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    if len(db_candidates) > 1 and not args.db_dir:
        print(f"[*] Multiple accounts found; using most recently active: {db_dir}")
    else:
        print(f"[*] Database directory: {db_dir}")

    databases = collect_databases(db_dir)
    if not databases:
        parser.error(f"No encrypted databases found in {db_dir}")
    print(f"[*] Found {len(databases)} databases and {len({d.salt for d in databases})} salts")

    if args.list_processes:
        scores = process_database_scores(args.process_name, db_dir)
        if not scores:
            print(f"[!] No running process named {args.process_name}")
            return 1
        for process_id, open_count in scores.items():
            print(f"PID {process_id}: {open_count} open database files under {db_dir}")
        return 0

    try:
        pid, all_pids = choose_process_id(args.process_name, db_dir, args.pid)
    except RuntimeError as exc:
        parser.error(str(exc))
    if len(all_pids) > 1:
        print(f"[*] Selected PID {pid} from: {', '.join(map(str, all_pids))}")

    try:
        import lldb
    except ImportError:
        parser.error(
            "Python cannot import lldb. Run with: "
            "PYTHONPATH=\"$(lldb -P)\" /Library/Developer/CommandLineTools/usr/bin/python3 "
            f"{Path(__file__).resolve()} --pid {pid}"
        )

    existing = load_key_store_if_present(args.output)
    known: dict[str, str] = {}
    for database in databases:
        key = existing.key_for(database)
        if key and verify_raw_key(key, database.first_page):
            known[database.salt] = key
    if known:
        print(f"[*] Reusing {len(known)} verified salts from {args.output}")

    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)
    target = debugger.CreateTarget("")
    error = lldb.SBError()
    process = None
    try:
        process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
        if not error.Success():
            parser.error(
                f"Could not attach to PID {pid}: {error.GetCString()}. "
                "Use your own Mac, grant Terminal Developer Tools access, and check SIP status."
            )
        print(f"[+] Attached to {args.process_name} (PID {pid})")
        found = scan_process_memory(
            process,
            lldb,
            databases,
            known,
            max(1, args.chunk_size_mb) * 1024 * 1024,
        )
    finally:
        if process is not None and process.IsValid():
            process.Detach()
        lldb.SBDebugger.Destroy(debugger)

    save_key_store(args.output, databases, found)
    expected = {database.salt for database in databases}
    print(f"[*] Saved {len(found)}/{len(expected)} verified salt keys to {args.output}")
    if expected - set(found):
        print("[!] Some databases were not open in WeChat memory; open related views and rerun.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
