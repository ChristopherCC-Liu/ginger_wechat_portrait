"""Build a private personal-agent state bundle from local exports."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from .emotion_cycle import calculate_emotion_cycle
from .ingest import load_yourself_style, normalize_exports
from .policy import policy_document, triage_pending_inbound
from .report import render_dashboard
from .schema import BUNDLE_SCHEMA, POLICY_VERSION
from .storage import (
    PRIVATE_FILE_MODE,
    append_jsonl,
    atomic_write_text,
    ensure_private_dir,
    load_or_create_secret,
    read_json,
    state_lock,
    write_json,
    write_jsonl,
)


STATE_MARKER = ".ginger-personal-agent-state"
STATE_ALLOWED_FILES = {
    STATE_MARKER,
    ".gitignore",
    ".identity_secret",
    ".state.lock",
    "audit.jsonl",
    "drafts.json",
    "emotion_cycle.json",
    "emotion_dashboard.html",
    "events.jsonl",
    "manifest.json",
    "policy.json",
    "style_context.md",
    "style_profile.json",
    "triage_queue.json",
}


def _prepare_output_dir(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise ValueError(f"Refusing symbolic-link state directory: {output_dir}")
    if output_dir.exists():
        metadata = output_dir.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"State output is not a directory: {output_dir}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError(
                f"State directory is not owned by the current user: {output_dir}"
            )
        entries = list(output_dir.iterdir())
        unknown = sorted(
            entry.name for entry in entries if entry.name not in STATE_ALLOWED_FILES
        )
        if unknown:
            raise ValueError(
                f"Refusing non-state directory with unknown files: {', '.join(unknown)}"
            )
        for entry in entries:
            entry_metadata = entry.lstat()
            if stat.S_ISLNK(entry_metadata.st_mode) or not stat.S_ISREG(
                entry_metadata.st_mode
            ):
                raise ValueError(f"State entry must be a regular file: {entry}")
            if hasattr(os, "getuid") and entry_metadata.st_uid != os.getuid():
                raise ValueError(
                    f"State entry is not owned by the current user: {entry}"
                )
        if entries:
            marker_path = output_dir / STATE_MARKER
            if marker_path.exists():
                if marker_path.read_text(encoding="ascii").strip() != BUNDLE_SCHEMA:
                    raise ValueError(f"Invalid state marker: {marker_path}")
            else:
                manifest_path = output_dir / "manifest.json"
                existing_manifest = (
                    read_json(manifest_path) if manifest_path.exists() else None
                )
                if (
                    not isinstance(existing_manifest, dict)
                    or existing_manifest.get("schema") != BUNDLE_SCHEMA
                ):
                    raise ValueError(
                        f"Existing directory is not a Ginger state bundle: {output_dir}"
                    )

    ensure_private_dir(output_dir)
    atomic_write_text(output_dir / STATE_MARKER, BUNDLE_SCHEMA + "\n")
    atomic_write_text(output_dir / ".gitignore", "*\n!.gitignore\n")


def _persisted_event(event: Any, retain_message_text: bool) -> Dict[str, Any]:
    row = event.to_dict()
    text = event.text
    row["text_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    row["text_retained"] = retain_message_text
    if not retain_message_text:
        row["text"] = None
    return row


def _persisted_queue_item(
    item: Dict[str, Any], retain_message_text: bool
) -> Dict[str, Any]:
    row = dict(item)
    preview = str(row.get("message_preview") or "")
    row["message_preview_sha256"] = hashlib.sha256(preview.encode("utf-8")).hexdigest()
    row["message_preview_retained"] = retain_message_text
    if not retain_message_text:
        row["message_preview"] = None
    return row


def build_bundle(
    export_paths: Sequence[Path],
    output_dir: Path,
    yourself_skill: Optional[Path] = None,
    timezone_name: str = "Asia/Shanghai",
    retain_message_text: bool = False,
) -> Dict[str, Any]:
    if not export_paths:
        raise ValueError("At least one Ginger export is required")
    missing = [str(path) for path in export_paths if not path.is_file()]
    if missing:
        raise ValueError(f"Export file not found: {', '.join(missing)}")

    _prepare_output_dir(output_dir)
    with state_lock(output_dir):
        return _build_bundle_locked(
            export_paths,
            output_dir,
            yourself_skill,
            timezone_name,
            retain_message_text,
        )


def _build_bundle_locked(
    export_paths: Sequence[Path],
    output_dir: Path,
    yourself_skill: Optional[Path],
    timezone_name: str,
    retain_message_text: bool,
) -> Dict[str, Any]:
    secret = load_or_create_secret(output_dir / ".identity_secret")
    events, sources = normalize_exports(export_paths, secret, timezone_name)
    if not events:
        raise ValueError("No valid messages were found in the supplied exports")

    emotion_cycle = calculate_emotion_cycle(events)
    triage_queue = triage_pending_inbound(events)
    policy = policy_document()
    style_profile: Dict[str, Any] = {
        "schema": "ginger_style_profile_v1",
        "source": None,
        "authority": "style_and_personal_context_only",
        "may_override_policy": False,
        "available": False,
    }
    style_context_file = None
    style_context_path = output_dir / "style_context.md"
    if yourself_skill is not None:
        style_profile, style_context = load_yourself_style(yourself_skill)
        style_profile["available"] = True
        style_context_file = "style_context.md"
        atomic_write_text(style_context_path, style_context)
    elif style_context_path.exists():
        style_context_path.unlink()

    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "created_at": created_at,
        "timezone": timezone_name,
        "event_count": len(events),
        "contact_count": len({event.contact_key for event in events}),
        "source_count": len(sources),
        "sources": [source.to_dict() for source in sources],
        "style_profile_available": style_profile["available"],
        "policy_version": POLICY_VERSION,
        "transport_send_allowed": False,
        "files": {
            "events": "events.jsonl",
            "emotion_cycle": "emotion_cycle.json",
            "emotion_dashboard": "emotion_dashboard.html",
            "triage_queue": "triage_queue.json",
            "style_profile": "style_profile.json",
            "style_context": style_context_file,
            "policy": "policy.json",
            "drafts": "drafts.json",
            "audit": "audit.jsonl",
        },
        "privacy": {
            "directory_mode": "0700",
            "file_mode": "0600",
            "raw_wxids_retained": False,
            "message_text_retained_locally": retain_message_text,
            "network_calls": False,
        },
    }

    write_jsonl(
        output_dir / "events.jsonl",
        (_persisted_event(event, retain_message_text) for event in events),
    )
    write_json(output_dir / "emotion_cycle.json", emotion_cycle)
    write_json(
        output_dir / "triage_queue.json",
        [_persisted_queue_item(item, retain_message_text) for item in triage_queue],
    )
    write_json(output_dir / "style_profile.json", style_profile)
    write_json(output_dir / "policy.json", policy)
    drafts_path = output_dir / "drafts.json"
    if not drafts_path.exists():
        write_json(drafts_path, [])
    else:
        if not isinstance(read_json(drafts_path), list):
            raise ValueError(f"Draft store must contain a JSON list: {drafts_path}")
        drafts_path.chmod(PRIVATE_FILE_MODE)
    write_json(output_dir / "manifest.json", manifest)
    atomic_write_text(
        output_dir / "emotion_dashboard.html",
        render_dashboard(emotion_cycle, manifest, policy),
    )
    append_jsonl(
        output_dir / "audit.jsonl",
        {
            "at": created_at,
            "action": "bundle_built",
            "event_count": len(events),
            "contact_count": manifest["contact_count"],
            "transport_send_allowed": False,
        },
    )
    return manifest
