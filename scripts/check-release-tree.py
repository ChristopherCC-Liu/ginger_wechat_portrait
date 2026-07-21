#!/usr/bin/env python3
"""Fail-closed source-release path and content scanner."""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 5 * 1024 * 1024
EXACT_PATHS = {
    ".gitignore",
    "MANIFEST.in",
    "NOTICE.md",
    "README.md",
    "SKILL.md",
    "config.example.toml",
    "data_loader.py",
    "export_contact.py",
    "install-macos.sh",
    "main.py",
    "personality.py",
    "pyproject.toml",
    "report.py",
    "requirements.lock",
    "requirements.txt",
    "sampler.py",
    "stats.py",
    "uv.lock",
    "visualizer.py",
    "安装指南.md",
}
ALLOWED_PATTERNS = (
    ".claude/commands/*.md",
    ".github/workflows/*.yml",
    "docs/*.md",
    "docs/*.json",
    "packaging/*.plist",
    "packaging/*.txt",
    "personal_agent/*.py",
    "pics/*.png",
    "scripts/*.py",
    "scripts/*.sh",
    "tests/*.py",
    "tests/fixtures/*.json",
    "tools/*.py",
    "tools/wechat_db/*.py",
)
TEXT_SUFFIXES = {
    "",
    ".in",
    ".json",
    ".lock",
    ".md",
    ".plist",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yml",
}
SYNTHETIC_WXID_PREFIXES = (
    "wxid_example_",
    "wxid_fixture_",
    "wxid_hidden",
    "wxid_private_",
    "wxid_raw_",
    "wxid_test_",
    "wxid_xxx_",
    "wxid_zstd_",
)
SECRET_PATTERNS = (
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    (
        "exposed_compound_key",
        re.compile(r"\b[a-fA-F0-9]{32}\.[A-Za-z0-9]{16,}\b"),
    ),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*"
            r"['\"][^'\"\r\n]{12,}['\"]"
        ),
    ),
)
LOCAL_PATH_RE = re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/")
WXID_RE = re.compile(r"\bwxid_[A-Za-z0-9_-]{4,}\b")


class ReleaseScanError(RuntimeError):
    pass


def _allowed(path: PurePosixPath) -> bool:
    value = path.as_posix()
    if value in EXACT_PATHS:
        return True
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in ALLOWED_PATTERNS)


def _scan_text(path: PurePosixPath, text: str) -> list[str]:
    findings: list[str] = []
    if LOCAL_PATH_RE.search(text):
        findings.append("local_absolute_path")
    for match in WXID_RE.finditer(text):
        value = match.group(0)
        if not value.startswith(SYNTHETIC_WXID_PREFIXES):
            findings.append(f"wechat_identifier:{value[:24]}")
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if "sk-this_should_never_be_in_config" in value:
                continue
            findings.append(label)
            break
    return findings


def _scan_blob(path: PurePosixPath, payload: bytes) -> list[str]:
    findings: list[str] = []
    if len(payload) > MAX_FILE_BYTES:
        findings.append("file_too_large")
        return findings
    if payload.startswith(b"SQLite format 3\x00"):
        findings.append("sqlite_database")
    if path.suffix == ".png":
        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            findings.append("invalid_png")
        return findings
    if path.suffix not in TEXT_SUFFIXES and path.name != ".gitignore":
        findings.append("unexpected_binary_type")
        return findings
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        findings.append("non_utf8_source")
        return findings
    findings.extend(_scan_text(path, text))
    return findings


def _git_paths(include_untracked: bool) -> list[Path]:
    arguments = ["git", "ls-files", "-z", "--cached"]
    if include_untracked:
        arguments.extend(["--others", "--exclude-standard"])
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return [Path(item.decode("utf-8")) for item in result.stdout.split(b"\0") if item]


def _scan_worktree(include_untracked: bool) -> list[str]:
    violations: list[str] = []
    for relative in _git_paths(include_untracked):
        pure = PurePosixPath(relative.as_posix())
        absolute = ROOT / relative
        if not _allowed(pure):
            violations.append(f"path_not_allowlisted:{pure}")
            continue
        if absolute.is_symlink():
            violations.append(f"symlink:{pure}")
            continue
        if not absolute.is_file():
            violations.append(f"not_regular_file:{pure}")
            continue
        violations.extend(
            f"{finding}:{pure}" for finding in _scan_blob(pure, absolute.read_bytes())
        )
    return violations


def _archive_members(path: Path) -> Iterator[tuple[PurePosixPath, bytes]]:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        roots = {PurePosixPath(item.name).parts[0] for item in members if item.name}
        if len(roots) != 1:
            raise ReleaseScanError("archive must contain exactly one root directory")
        for member in members:
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ReleaseScanError("archive contains an unsafe path")
            if (
                member.issym()
                or member.islnk()
                or not (member.isfile() or member.isdir())
            ):
                raise ReleaseScanError("archive contains a link or special file")
            if member.isdir():
                continue
            relative = PurePosixPath(*member_path.parts[1:])
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ReleaseScanError("archive member could not be read")
            yield relative, extracted.read(MAX_FILE_BYTES + 1)


def _scan_archive(path: Path) -> list[str]:
    violations: list[str] = []
    for relative, payload in _archive_members(path):
        if not _allowed(relative):
            violations.append(f"path_not_allowlisted:{relative}")
            continue
        violations.extend(
            f"{finding}:{relative}" for finding in _scan_blob(relative, payload)
        )
    return violations


def _print_and_exit(violations: Iterable[str]) -> int:
    unique = sorted(set(violations))
    if not unique:
        print("release privacy scan: OK")
        return 0
    for violation in unique:
        print(f"release privacy scan: {violation}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--candidate-tree", action="store_true")
    source.add_argument("--tracked-tree", action="store_true")
    source.add_argument("--archive", type=Path)
    args = parser.parse_args()
    try:
        if args.archive is not None:
            violations = _scan_archive(args.archive.expanduser().absolute())
        else:
            violations = _scan_worktree(include_untracked=args.candidate_tree)
    except (OSError, ReleaseScanError, subprocess.CalledProcessError) as exc:
        print(f"release privacy scan: scanner_error:{type(exc).__name__}")
        return 1
    return _print_and_exit(violations)


if __name__ == "__main__":
    raise SystemExit(main())
