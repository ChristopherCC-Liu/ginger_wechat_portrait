"""Private, atomic persistence helpers for local chat-agent state."""

from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Iterable

import fcntl


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _validate_owned_regular_file(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic link: {path}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Expected a regular file: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError(f"File is not owned by the current user: {path}")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def ensure_private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link directory: {path}")
    if path.exists():
        metadata = path.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"Expected a directory: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError(f"Directory is not owned by the current user: {path}")
    else:
        path.mkdir(parents=True, exist_ok=False)
    path.chmod(PRIVATE_DIR_MODE)
    return path


def atomic_write_text(path: Path, content: str) -> None:
    ensure_private_dir(path.parent)
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link output: {path}")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            os.chmod(temp_path, PRIVATE_FILE_MODE)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        path.chmod(PRIVATE_FILE_MODE)
        _fsync_directory(path.parent)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(
        path,
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def write_jsonl(path: Path, rows: Iterable[Any]) -> None:
    ensure_private_dir(path.parent)
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link output: {path}")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            os.chmod(temp_path, PRIVATE_FILE_MODE)
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        path.chmod(PRIVATE_FILE_MODE)
        _fsync_directory(path.parent)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def append_jsonl(path: Path, row: Any) -> None:
    ensure_private_dir(path.parent)
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link output: {path}")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(
        path,
        flags,
        PRIVATE_FILE_MODE,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Expected a regular audit file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError(f"Audit file is not owned by the current user: {path}")
        payload = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"Short write while appending {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    path.chmod(PRIVATE_FILE_MODE)


def read_json(path: Path) -> Any:
    _validate_owned_regular_file(path)
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_or_create_secret(path: Path) -> bytes:
    ensure_private_dir(path.parent)
    if path.exists():
        _validate_owned_regular_file(path)
        value = path.read_text(encoding="ascii").strip()
        try:
            secret = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"Invalid local identity secret: {path}") from exc
        if len(secret) < 32:
            raise ValueError(f"Local identity secret is too short: {path}")
        path.chmod(PRIVATE_FILE_MODE)
        return secret

    secret = secrets.token_bytes(32)
    atomic_write_text(path, secret.hex() + "\n")
    return secret


@contextmanager
def state_lock(directory: Path) -> Generator[None, None, None]:
    ensure_private_dir(directory)
    path = directory / ".state.lock"
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link lock: {path}")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"Expected a regular lock file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError(f"Lock file is not owned by the current user: {path}")
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
