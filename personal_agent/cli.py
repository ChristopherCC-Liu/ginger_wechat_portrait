"""Command-line entry point for the local personal chat-agent state."""

from __future__ import annotations

import argparse
import getpass
import json
import secrets as secret_bytes
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .builder import STATE_MARKER, build_bundle
from .config import DEFAULT_CONFIG_PATH, AgentConfig, load_config
from .crypto_store import MacOSKeychain
from .distillation import AUTOMATIC, USER_CONFIRMED
from .learning import refresh_distillation
from .operations import (
    approve_draft,
    arm_send_canary,
    cost_report,
    distillation_service,
    import_wechat_keys,
    list_distillations,
    list_drafts,
    open_ledger,
    save_correction,
    typing_validate_draft,
)
from .policy import review_draft, stage_draft
from .runtime import KEYCHAIN_SERVICE, run_configured_once
from .schema import BUNDLE_SCHEMA
from .service import (
    ServiceManager,
    doctor,
    pause,
    resume,
    set_kill_switch,
    validate_agent_executable,
)
from .storage import append_jsonl, read_json, state_lock, write_json


def _state_dir(value: str) -> Path:
    path = Path(value).expanduser().absolute()
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link state directory: {path}")
    marker_path = path / STATE_MARKER
    manifest_path = path / "manifest.json"
    if (
        marker_path.is_symlink()
        or manifest_path.is_symlink()
        or not marker_path.is_file()
        or not manifest_path.is_file()
    ):
        raise ValueError(f"Not a personal-agent state directory: {path}")
    if marker_path.read_text(encoding="ascii").strip() != BUNDLE_SCHEMA:
        raise ValueError(f"Invalid personal-agent state marker: {path}")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_SCHEMA:
        raise ValueError(f"Invalid personal-agent manifest: {path}")
    return path


def _find_by_id(rows: Sequence[Dict[str, Any]], key: str, value: str) -> Dict[str, Any]:
    for row in rows:
        if isinstance(row, dict) and row.get(key) == value:
            return row
    raise ValueError(f"Unknown {key}: {value}")


def _read_object_list(path: Path, label: str) -> List[Dict[str, Any]]:
    value = read_json(path)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must contain a JSON list of objects: {path}")
    return value


def _style_snapshot(state_dir: Path) -> Dict[str, Any]:
    profile = read_json(state_dir / "style_profile.json")
    if not isinstance(profile, dict):
        raise ValueError("Style profile must contain a JSON object")
    return {
        key: profile[key]
        for key in (
            "schema",
            "source",
            "self_memory_sha256",
            "persona_sha256",
            "authority",
        )
        if key in profile
    }


def _draft_text(args: argparse.Namespace) -> str:
    if args.text_file:
        return Path(args.text_file).expanduser().read_text(encoding="utf-8")
    return args.text or ""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m personal_agent.cli",
        description="Operate Ginger Personal Agent and the legacy v1 state bundle.",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="v2 runtime config (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="Build state from Ginger JSON exports")
    build.add_argument("--export", dest="exports", action="append", required=True)
    build.add_argument("--output", default="personal_agent_state")
    build.add_argument("--yourself-skill", default=None)
    build.add_argument("--timezone", default="Asia/Shanghai")
    build.add_argument(
        "--retain-message-text",
        action="store_true",
        help="Persist message text in state (off by default; requires encrypted storage)",
    )

    draft = subparsers.add_parser("draft", help="Stage a draft for mandatory review")
    draft.add_argument("--state", default="personal_agent_state")
    draft.add_argument("--queue-id", required=True)
    draft_text = draft.add_mutually_exclusive_group(required=True)
    draft_text.add_argument("--text")
    draft_text.add_argument("--text-file")

    review = subparsers.add_parser("review", help="Approve for manual copy or reject")
    review.add_argument("--state", default="personal_agent_state")
    review.add_argument("--draft-id", required=True)
    review.add_argument("--decision", choices=("approve", "reject"), required=True)
    review.add_argument("--actor", default="user")
    review.add_argument("--note", default=None)

    status = subparsers.add_parser("status", help="Show v2 service or legacy state")
    status.add_argument("--state", default=None, help="Show a legacy v1 state")

    subparsers.add_parser("run-once", help="Poll and process one bounded v2 cycle")
    subparsers.add_parser("doctor", help="Run read-only local readiness checks")
    subparsers.add_parser("install-service", help="Install and load the LaunchAgent")
    subparsers.add_parser("uninstall-service", help="Unload and remove the LaunchAgent")
    subparsers.add_parser("pause", help="Pause scheduled processing")
    subparsers.add_parser("resume", help="Resume after a normal pause")
    subparsers.add_parser("cost-report", help="Show persistent daily model usage")

    kill = subparsers.add_parser("kill-switch", help="Control the emergency stop")
    kill_action = kill.add_mutually_exclusive_group(required=True)
    kill_action.add_argument("--enable", action="store_true")
    kill_action.add_argument("--clear", action="store_true")

    secret = subparsers.add_parser("secret-set", help="Store a value in macOS Keychain")
    secret.add_argument("--name", required=True)
    secret_source = secret.add_mutually_exclusive_group()
    secret_source.add_argument("--generate-bytes", type=int)
    secret_source.add_argument("--stdin", action="store_true")

    key_import = subparsers.add_parser(
        "import-wechat-keys", help="Import legacy DB keys into Keychain"
    )
    key_import.add_argument("--keys-file", required=True)

    drafts = subparsers.add_parser("drafts", help="List encrypted v2 draft metadata")
    drafts.add_argument("--include-body", action="store_true")

    approve = subparsers.add_parser(
        "approve-draft", help="Create a short-lived approval that cannot send"
    )
    approve.add_argument("--draft-id", required=True)
    approve.add_argument("--expires-seconds", type=int, default=600)

    typing = subparsers.add_parser(
        "typing-validate", help="Verify recipient/body without pressing Return"
    )
    typing.add_argument("--draft-id", required=True)

    arm_send = subparsers.add_parser(
        "arm-send-canary",
        help="Arm one short-lived, draft-bound Accessibility click",
    )
    arm_send.add_argument("--draft-id", required=True)
    arm_send.add_argument("--expires-seconds", type=int, default=600)
    arm_send.add_argument("--confirm", required=True)

    correction = subparsers.add_parser(
        "record-correction", help="Record draft/edit/final differences"
    )
    correction.add_argument("--draft-id", required=True)
    correction.add_argument("--user-edit-file", required=True)
    correction.add_argument("--final-reply-file", required=True)

    distill_put = subparsers.add_parser(
        "distill-put", help="Create an immutable distillation version"
    )
    distill_put.add_argument("--domain", required=True)
    distill_put.add_argument("--payload-file", required=True)
    distill_put.add_argument("--contact-key")
    distill_put.add_argument("--evidence-id", action="append", default=[])
    distill_put.add_argument("--confidence", type=float, required=True)
    distill_put.add_argument("--protected-field", action="append", default=[])
    distill_put.add_argument("--user-confirmed", action="store_true")
    distill_put.add_argument("--activate", action="store_true")

    distill_list = subparsers.add_parser(
        "distill-list", help="List versions in one isolated scope"
    )
    distill_list.add_argument("--domain", required=True)
    distill_list.add_argument("--contact-key")
    distill_list.add_argument("--include-payload", action="store_true")

    rollback = subparsers.add_parser(
        "distill-rollback", help="Activate an ancestor distillation version"
    )
    rollback.add_argument("--domain", required=True)
    rollback.add_argument("--version-id", required=True)
    rollback.add_argument("--contact-key")

    activate = subparsers.add_parser(
        "distill-activate", help="Explicitly activate an existing safe version"
    )
    activate.add_argument("--version-id", required=True)

    refresh = subparsers.add_parser(
        "distill-refresh", help="Run local correction and emotion distillation"
    )
    refresh.add_argument("--force", action="store_true")
    return parser


def _command_build(args: argparse.Namespace) -> Dict[str, Any]:
    return build_bundle(
        export_paths=[Path(value).expanduser().resolve() for value in args.exports],
        output_dir=Path(args.output).expanduser().absolute(),
        yourself_skill=(
            Path(args.yourself_skill).expanduser().resolve()
            if args.yourself_skill
            else None
        ),
        timezone_name=args.timezone,
        retain_message_text=args.retain_message_text,
    )


def _command_draft(args: argparse.Namespace) -> Dict[str, Any]:
    state_dir = _state_dir(args.state)
    with state_lock(state_dir):
        queue = _read_object_list(state_dir / "triage_queue.json", "Triage queue")
        queue_item = _find_by_id(queue, "queue_id", args.queue_id)
        draft = stage_draft(queue_item, _draft_text(args), _style_snapshot(state_dir))
        drafts = _read_object_list(state_dir / "drafts.json", "Draft store")
        if any(item.get("draft_id") == draft["draft_id"] for item in drafts):
            raise ValueError(f"Duplicate draft_id: {draft['draft_id']}")
        drafts.append(draft)
        write_json(state_dir / "drafts.json", drafts)
        append_jsonl(
            state_dir / "audit.jsonl",
            {
                "at": draft["created_at"],
                "action": "draft_staged",
                "draft_id": draft["draft_id"],
                "queue_id": draft["queue_id"],
                "send_allowed": False,
            },
        )
    return draft


def _command_review(args: argparse.Namespace) -> Dict[str, Any]:
    state_dir = _state_dir(args.state)
    with state_lock(state_dir):
        drafts = _read_object_list(state_dir / "drafts.json", "Draft store")
        draft = _find_by_id(drafts, "draft_id", args.draft_id)
        reviewed = review_draft(draft, args.decision, actor=args.actor, note=args.note)
        drafts[drafts.index(draft)] = reviewed
        write_json(state_dir / "drafts.json", drafts)
        append_jsonl(
            state_dir / "audit.jsonl",
            {
                "at": reviewed["reviewed_at"],
                "action": {
                    "approve": "draft_approved",
                    "reject": "draft_rejected",
                }[args.decision],
                "draft_id": reviewed["draft_id"],
                "actor": args.actor,
                "send_allowed": False,
            },
        )
    return reviewed


def _command_legacy_status(args: argparse.Namespace) -> Dict[str, Any]:
    state_dir = _state_dir(args.state)
    with state_lock(state_dir):
        manifest = read_json(state_dir / "manifest.json")
        queue = _read_object_list(state_dir / "triage_queue.json", "Triage queue")
        drafts = _read_object_list(state_dir / "drafts.json", "Draft store")
    return {
        "schema": manifest["schema"],
        "event_count": manifest["event_count"],
        "contact_count": manifest["contact_count"],
        "queue_count": len(queue),
        "draft_counts": {
            status: sum(1 for draft in drafts if draft.get("status") == status)
            for status in sorted(
                str(draft.get("status") or "unknown") for draft in drafts
            )
        },
        "transport_send_allowed": manifest["transport_send_allowed"],
    }


def _config_path(args: argparse.Namespace) -> Path:
    return Path(args.config).expanduser().absolute()


def _runtime_config(args: argparse.Namespace) -> AgentConfig:
    return load_config(_config_path(args))


def _agent_executable() -> Path:
    interpreter_dir = Path(sys.executable).expanduser().absolute().parent
    return validate_agent_executable(interpreter_dir / "ginger-agent")


def _service_manager(config: AgentConfig, args: argparse.Namespace) -> ServiceManager:
    return ServiceManager(
        config.paths,
        _agent_executable(),
        _config_path(args),
        config.poll_interval_seconds,
    )


def _command_v2_status(args: argparse.Namespace) -> Dict[str, Any]:
    config = _runtime_config(args)
    service = _service_manager(config, args).status()
    return {
        "schema": "ginger_agent_status_v2",
        "mode": config.mode,
        "real_send_enabled": config.sender.real_send_enabled,
        "typing_only": config.sender.typing_only,
        "allowlist_size": len(config.allowlist),
        "service": service,
        "runtime_root": str(config.paths.root),
    }


def _command_secret_set(args: argparse.Namespace) -> Dict[str, Any]:
    _runtime_config(args)
    if args.generate_bytes is not None:
        if not 1 <= args.generate_bytes <= 4096:
            raise ValueError("generate-bytes must be between 1 and 4096")
        value = secret_bytes.token_bytes(args.generate_bytes)
        source = "generated"
    elif args.stdin:
        value = sys.stdin.buffer.read().rstrip(b"\r\n")
        source = "stdin"
    else:
        value = getpass.getpass(f"Secret value for {args.name}: ").encode("utf-8")
        source = "prompt"
    if not value:
        raise ValueError("Refusing to store an empty secret")
    MacOSKeychain(KEYCHAIN_SERVICE).set_secret(args.name, value)
    return {
        "schema": "ginger_secret_set_v2",
        "name": args.name,
        "bytes": len(value),
        "source": source,
        "value_logged": False,
    }


def _with_ledger(
    config: AgentConfig,
    callback: Any,
) -> Any:
    with state_lock(config.paths.root / "state"):
        ledger, _ = open_ledger(config)
        try:
            return callback(ledger)
        finally:
            ledger.close()


def _read_json_object(path_value: str) -> Dict[str, Any]:
    path = Path(path_value).expanduser().absolute()
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def _command_distill_put(args: argparse.Namespace) -> Dict[str, Any]:
    config = _runtime_config(args)
    payload = _read_json_object(args.payload_file)

    def execute(ledger: Any) -> Dict[str, Any]:
        version = distillation_service(ledger).create_version(
            args.domain,
            payload,
            evidence_ids=args.evidence_id,
            confidence=args.confidence,
            contact_key=args.contact_key,
            correction_type=USER_CONFIRMED if args.user_confirmed else AUTOMATIC,
            protected_fields=args.protected_field,
            activate=args.activate,
        )
        return {**version.to_dict(), "active": args.activate}

    return _with_ledger(config, execute)


def _command_distill_list(args: argparse.Namespace) -> Dict[str, Any]:
    config = _runtime_config(args)

    def execute(ledger: Any) -> Dict[str, Any]:
        versions = list_distillations(ledger, args.domain, args.contact_key)
        if not args.include_payload:
            versions = [
                {key: value for key, value in item.items() if key != "payload"}
                for item in versions
            ]
        return {
            "schema": "ginger_distillation_list_v2",
            "domain": args.domain,
            "contact_key": args.contact_key,
            "versions": versions,
        }

    return _with_ledger(config, execute)


def _command_distill_rollback(args: argparse.Namespace) -> Dict[str, Any]:
    config = _runtime_config(args)

    def execute(ledger: Any) -> Dict[str, Any]:
        version = distillation_service(ledger).rollback(
            args.domain,
            args.version_id,
            contact_key=args.contact_key,
        )
        return {**version.to_dict(), "active": True, "rollback": True}

    return _with_ledger(config, execute)


def _command_distill_activate(args: argparse.Namespace) -> Dict[str, Any]:
    config = _runtime_config(args)

    def execute(ledger: Any) -> Dict[str, Any]:
        version = distillation_service(ledger).activate(args.version_id)
        return {**version.to_dict(), "active": True}

    return _with_ledger(config, execute)


def _command_distill_refresh(args: argparse.Namespace) -> Dict[str, Any]:
    config = _runtime_config(args)
    return _with_ledger(
        config,
        lambda ledger: refresh_distillation(
            ledger,
            timezone_name=config.timezone,
            interval_seconds=config.learning.refresh_interval_seconds,
            minimum_corrections=config.learning.minimum_corrections,
            activate_safe=config.learning.auto_activate_safe,
            force=bool(args.force),
        ),
    )


def _public_result(command: str, result: Dict[str, Any]) -> Dict[str, Any]:
    if command == "build":
        return {
            key: result[key]
            for key in (
                "schema",
                "created_at",
                "event_count",
                "contact_count",
                "source_count",
                "style_profile_available",
                "transport_send_allowed",
                "privacy",
            )
        }
    if command in {"draft", "review"}:
        return {
            key: result.get(key)
            for key in (
                "draft_id",
                "queue_id",
                "status",
                "created_at",
                "reviewed_at",
                "send_allowed",
            )
        }
    if command in {"distill-put", "distill-activate", "distill-rollback"}:
        return {key: value for key, value in result.items() if key != "payload"}
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = _command_build(args)
        elif args.command == "draft":
            result = _command_draft(args)
        elif args.command == "review":
            result = _command_review(args)
        elif args.command == "run-once":
            result = run_configured_once(_runtime_config(args))
        elif args.command == "doctor":
            config = _runtime_config(args)
            result = doctor(config, _config_path(args))
        elif args.command == "install-service":
            config = _runtime_config(args)
            result = _service_manager(config, args).install()
        elif args.command == "uninstall-service":
            config = _runtime_config(args)
            result = _service_manager(config, args).uninstall()
        elif args.command == "pause":
            result = pause(_runtime_config(args).paths)
        elif args.command == "resume":
            result = resume(_runtime_config(args).paths)
        elif args.command == "kill-switch":
            result = set_kill_switch(
                _runtime_config(args).paths,
                enabled=bool(args.enable),
            )
        elif args.command == "cost-report":
            config = _runtime_config(args)
            with state_lock(config.paths.root / "state"):
                result = cost_report(config)
        elif args.command == "secret-set":
            result = _command_secret_set(args)
        elif args.command == "import-wechat-keys":
            result = import_wechat_keys(
                _runtime_config(args),
                Path(args.keys_file),
            )
        elif args.command == "drafts":
            config = _runtime_config(args)
            result = {
                "schema": "ginger_draft_list_v2",
                "drafts": _with_ledger(
                    config,
                    lambda ledger: list_drafts(
                        ledger,
                        include_body=args.include_body,
                    ),
                ),
            }
        elif args.command == "approve-draft":
            config = _runtime_config(args)
            result = _with_ledger(
                config,
                lambda ledger: approve_draft(
                    config,
                    ledger,
                    args.draft_id,
                    expires_seconds=args.expires_seconds,
                ),
            )
        elif args.command == "typing-validate":
            config = _runtime_config(args)
            result = _with_ledger(
                config,
                lambda ledger: typing_validate_draft(
                    config,
                    ledger,
                    args.draft_id,
                ),
            )
        elif args.command == "arm-send-canary":
            config = _runtime_config(args)
            result = _with_ledger(
                config,
                lambda ledger: arm_send_canary(
                    config,
                    ledger,
                    args.draft_id,
                    confirmation=args.confirm,
                    expires_seconds=args.expires_seconds,
                ),
            )
        elif args.command == "record-correction":
            config = _runtime_config(args)
            user_edit = (
                Path(args.user_edit_file).expanduser().read_text(encoding="utf-8")
            )
            final_reply = (
                Path(args.final_reply_file).expanduser().read_text(encoding="utf-8")
            )
            result = _with_ledger(
                config,
                lambda ledger: save_correction(
                    ledger,
                    args.draft_id,
                    user_edit=user_edit,
                    final_reply=final_reply,
                ),
            )
        elif args.command == "distill-put":
            result = _command_distill_put(args)
        elif args.command == "distill-list":
            result = _command_distill_list(args)
        elif args.command == "distill-rollback":
            result = _command_distill_rollback(args)
        elif args.command == "distill-activate":
            result = _command_distill_activate(args)
        elif args.command == "distill-refresh":
            result = _command_distill_refresh(args)
        elif args.command == "status" and args.state:
            result = _command_legacy_status(args)
        else:
            result = _command_v2_status(args)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            _public_result(args.command, result),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    if args.command == "doctor" and result.get("ready") is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
