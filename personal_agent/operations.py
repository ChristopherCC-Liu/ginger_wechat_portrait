"""Auditable CLI operations for the v2 runtime."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any, Mapping, Optional, cast

from tools.wechat_db.common import collect_databases, load_key_store

from .config import AgentConfig
from .corrections import propose_distillation_candidates, record_correction
from .costs import DailyLimits, ModelPricing
from .crypto_store import MacOSKeychain, SecretStore
from .distillation import RELATIONSHIP, USER_CONFIRMED, DistillationService
from .ledger import EncryptedLedger, JSONValue, RuntimeRecord
from .runtime import (
    CORRECTION_NAMESPACE,
    DRAFT_ACTION_NAMESPACE,
    DRAFT_NAMESPACE,
    KEYCHAIN_SERVICE,
    LEARNING_NAMESPACE,
)
from .runtime_state import LedgerDistillationRepository, PersistentDailyCostLedger
from .sender import (
    ComputerUseSender,
    MacOSAccessibilitySender,
    SendRequest,
    Sender,
    SenderRouter,
    send_attempt_id,
)


def open_ledger(
    config: AgentConfig,
    secrets: Optional[SecretStore] = None,
) -> tuple[EncryptedLedger, SecretStore]:
    store = secrets or MacOSKeychain(KEYCHAIN_SERVICE)
    state_key = store.get_secret(config.state_key_ref)
    return EncryptedLedger(config.paths.ledger, state_key), store


def import_wechat_keys(
    config: AgentConfig,
    key_file: Path,
    *,
    secrets: Optional[SecretStore] = None,
) -> dict[str, JSONValue]:
    source = key_file.expanduser().absolute()
    if source.is_symlink():
        raise ValueError("Refusing symbolic-link WeChat key file")
    metadata = source.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("WeChat key file must be a regular file")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError("WeChat key file must be owned by the current user")
    if metadata.st_mode & 0o077:
        raise ValueError("WeChat key file permissions must be 0600")
    store = secrets or MacOSKeychain(KEYCHAIN_SERVICE)
    key_store = load_key_store(source)
    imported_salts: set[str] = set()
    for salt, key in key_store.salt_keys.items():
        store.set_secret(
            f"{config.reader.keychain_db_key_prefix}:{salt}",
            bytes.fromhex(key),
        )
        imported_salts.add(salt)

    matched_paths = 0
    if config.reader.db_dir is not None and config.reader.db_dir.is_dir():
        for database in collect_databases(config.reader.db_dir):
            key = key_store.key_for(database)
            if key is None:
                continue
            store.set_secret(
                f"{config.reader.keychain_db_key_prefix}:{database.salt}",
                bytes.fromhex(key),
            )
            imported_salts.add(database.salt)
            matched_paths += 1
    return {
        "schema": "ginger_key_import_v2",
        "imported_salts": len(imported_salts),
        "matched_database_paths": matched_paths,
        "source_deleted": False,
        "source_path_logged": False,
    }


def _configured_pricing(
    config: AgentConfig,
) -> dict[tuple[str, str], ModelPricing]:
    raw = config.cost.model_prices_per_million_tokens.get(config.model.model)
    if raw is None and config.model.provider == "local":
        raw = {"input": 0, "output": 0}
    if raw is None:
        return {}
    return {
        (config.model.provider, config.model.model): ModelPricing(
            input_per_million=Decimal(str(raw.get("input", 0))),
            output_per_million=Decimal(str(raw.get("output", 0))),
        )
    }


def cost_report(
    config: AgentConfig,
    *,
    secrets: Optional[SecretStore] = None,
) -> dict[str, JSONValue]:
    ledger, _ = open_ledger(config, secrets)
    try:
        costs = PersistentDailyCostLedger(
            ledger,
            timezone_name=config.timezone,
            limits=DailyLimits(
                max_calls=config.cost.daily_call_limit,
                max_cost=Decimal(str(config.cost.daily_usd_limit)),
            ),
            pricing=_configured_pricing(config),
        )
        usage = costs.snapshot()
        return {
            "schema": "ginger_cost_report_v2",
            "budget_date": usage.budget_date.isoformat(),
            "calls": usage.calls,
            "committed_calls": usage.committed_calls,
            "reserved_calls": usage.reserved_calls,
            "cost_usd": str(usage.total_cost),
            "committed_cost_usd": str(usage.committed_cost),
            "reserved_cost_usd": str(usage.reserved_cost),
            "calls_remaining": usage.calls_remaining,
            "cost_remaining_usd": str(usage.cost_remaining),
            "daily_call_limit": usage.max_calls,
            "daily_cost_limit_usd": str(usage.max_cost),
        }
    finally:
        ledger.close()


def distillation_service(ledger: EncryptedLedger) -> DistillationService:
    return DistillationService(LedgerDistillationRepository(ledger))


def list_distillations(
    ledger: EncryptedLedger,
    domain: str,
    contact_key: Optional[str] = None,
) -> list[dict[str, Any]]:
    service = distillation_service(ledger)
    active = service.active(domain, contact_key)
    return [
        {
            **version.to_dict(),
            "active": active is not None and version.version_id == active.version_id,
        }
        for version in service.repository.list_versions(domain, contact_key)
    ]


def list_drafts(
    ledger: EncryptedLedger,
    *,
    include_body: bool = False,
) -> list[dict[str, JSONValue]]:
    records = ledger.list_runtime_records(DRAFT_NAMESPACE, limit=10_000)
    result: list[dict[str, JSONValue]] = []
    for record in records:
        payload = dict(record.payload)
        body = str(payload.pop("body", ""))
        result.append(
            {
                "draft_id": record.record_id,
                "contact_key": record.scope,
                "event_id": cast(str, payload.get("event_id")),
                "status": cast(str, payload.get("status")),
                "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "body": body if include_body else None,
            }
        )
    return result


def _draft(ledger: EncryptedLedger, draft_id: str) -> RuntimeRecord:
    record = ledger.get_runtime_record(draft_id)
    if record is None or record.namespace != DRAFT_NAMESPACE:
        raise ValueError(f"Unknown draft_id: {draft_id}")
    return record


def _require_approval_gate(config: AgentConfig, draft: RuntimeRecord) -> None:
    if config.mode != "approve":
        raise ValueError("draft approval and typing require approve mode")
    gate = draft.payload.get("gate")
    if not isinstance(gate, Mapping):
        raise ValueError("draft has no authenticated approval gate")
    if (
        gate.get("mode") != "approve"
        or gate.get("action") != "approval_required"
        or draft.payload.get("status") != "approval_required"
    ):
        raise ValueError("draft is not eligible for approval or UI validation")


def _verified_draft_ui_identity(
    ledger: EncryptedLedger, draft: RuntimeRecord
) -> tuple[str, str]:
    if draft.payload.get("ui_identity_verified") is not True:
        raise ValueError("draft has no user-confirmed UI identity binding")
    label = draft.payload.get("contact_label")
    search_token = draft.payload.get("contact_search_token")
    version_id = draft.payload.get("ui_identity_version_id")
    if (
        not isinstance(label, str)
        or not label.strip()
        or not isinstance(search_token, str)
        or not search_token.strip()
        or label.strip() == search_token.strip()
        or not isinstance(version_id, str)
    ):
        raise ValueError("draft UI identity binding is invalid")

    service = distillation_service(ledger)
    active = service.active(RELATIONSHIP, draft.scope)
    if active is None or active.version_id != version_id:
        raise ValueError("draft UI identity binding is stale")
    payload = active.to_dict()["payload"]
    if (
        payload.get("display_name") != label
        or payload.get("ui_search_token") != search_token
    ):
        raise ValueError("draft UI identity binding no longer matches")
    cursor = active
    while cursor is not None:
        ancestor = cursor.to_dict()["payload"]
        if (
            cursor.correction_type == USER_CONFIRMED
            and ancestor.get("display_name") == label
            and ancestor.get("ui_search_token") == search_token
        ):
            return label.strip(), search_token.strip()
        cursor = (
            service.repository.get(cursor.parent_id)
            if cursor.parent_id is not None
            else None
        )
    raise ValueError("draft UI identity was not confirmed by the user")


def approve_draft(
    config: AgentConfig,
    ledger: EncryptedLedger,
    draft_id: str,
    *,
    expires_seconds: int = 600,
) -> dict[str, JSONValue]:
    if not 1 <= expires_seconds <= 600:
        raise ValueError("approval expiry must be between 1 and 600 seconds")
    draft = _draft(ledger, draft_id)
    _require_approval_gate(config, draft)
    body = str(draft.payload.get("body", ""))
    if not body:
        raise ValueError("draft has no body")
    action_id = f"approval_{uuid.uuid4().hex}"
    expires_at = int(time.time()) + expires_seconds
    ledger.append_runtime_record(
        action_id,
        DRAFT_ACTION_NAMESPACE,
        draft_id,
        "approved",
        {
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "context_hash": cast(str, draft.payload.get("context_hash", "")),
            "draft_id": draft_id,
            "expires_at": expires_at,
            "recipient": draft.scope,
        },
    )
    return {
        "schema": "ginger_draft_approval_v2",
        "approval_id": action_id,
        "draft_id": draft_id,
        "expires_at": expires_at,
        "send_allowed": False,
    }


def _latest_approval(ledger: EncryptedLedger, draft_id: str) -> RuntimeRecord:
    actions = ledger.list_runtime_records(
        DRAFT_ACTION_NAMESPACE,
        scope=draft_id,
        kind="approved",
        limit=100,
    )
    if not actions:
        raise ValueError("draft has no active approval")
    approval = actions[-1]
    consumed = ledger.list_runtime_records(
        DRAFT_ACTION_NAMESPACE,
        scope=draft_id,
        kind="typing_validation",
        limit=100,
    )
    if any(item.payload.get("approval_id") == approval.record_id for item in consumed):
        raise ValueError("draft approval was already consumed")
    if int(cast(Any, approval.payload.get("expires_at", 0))) < int(time.time()):
        raise ValueError("draft approval has expired")
    return approval


def _typing_sender(config: AgentConfig) -> Sender:
    def backend(name: str) -> Sender:
        if name == "accessibility":
            return MacOSAccessibilitySender(
                timeout_seconds=config.sender.ui_timeout_seconds
            )
        if config.sender.computer_use_helper is None:
            raise ValueError("computer_use_helper is not configured")
        return ComputerUseSender(
            config.sender.computer_use_helper,
            timeout_seconds=config.sender.ui_timeout_seconds,
        )

    primary = backend(config.sender.backend)
    fallback = (
        backend(config.sender.fallback_backend)
        if config.sender.fallback_backend
        else None
    )
    return SenderRouter(primary, fallback)


def typing_validate_draft(
    config: AgentConfig,
    ledger: EncryptedLedger,
    draft_id: str,
    *,
    sender: Optional[Sender] = None,
) -> dict[str, JSONValue]:
    draft = _draft(ledger, draft_id)
    _require_approval_gate(config, draft)
    approval = _latest_approval(ledger, draft_id)
    body = str(draft.payload.get("body", ""))
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if approval.payload.get("body_sha256") != body_hash:
        raise ValueError("approved draft body no longer matches")
    contact_label, search_token = _verified_draft_ui_identity(ledger, draft)
    request = SendRequest(
        attempt_id=f"typing_{uuid.uuid4().hex}",
        contact_key=draft.scope,
        contact_label=contact_label,
        body=body,
        search_token=search_token,
        action="typing_only",
    )
    result = (sender or _typing_sender(config)).execute(request)
    record_id = f"typing-result:{request.attempt_id}"
    ledger.append_runtime_record(
        record_id,
        DRAFT_ACTION_NAMESPACE,
        draft_id,
        "typing_validation",
        {
            "approval_id": approval.record_id,
            "backend": result.backend,
            "body_verified": result.body_verified,
            "clicked": result.clicked,
            "recipient_verified": result.recipient_verified,
        },
    )
    return {
        "schema": "ginger_typing_validation_v2",
        "draft_id": draft_id,
        "recipient_verified": result.recipient_verified,
        "body_verified": result.body_verified,
        "clicked": result.clicked,
        "real_send": False,
    }


def arm_send_canary(
    config: AgentConfig,
    ledger: EncryptedLedger,
    draft_id: str,
    *,
    confirmation: str,
    expires_seconds: int = 600,
    secrets: Optional[SecretStore] = None,
    now_epoch: Optional[int] = None,
) -> dict[str, JSONValue]:
    """Authorize one deterministic Accessibility click at the action point."""
    if confirmation != "SEND_ONCE":
        raise ValueError("real-send canary requires the exact confirmation SEND_ONCE")
    if config.mode != "autopilot" or not config.sender.real_send_enabled:
        raise ValueError("real-send canary requires enabled autopilot mode")
    if not 1 <= expires_seconds <= 600:
        raise ValueError("canary expiry must be between 1 and 600 seconds")
    draft = _draft(ledger, draft_id)
    if draft.scope not in config.allowlist:
        raise ValueError("draft contact is not in the active allowlist")
    gate = draft.payload.get("gate")
    if (
        not isinstance(gate, Mapping)
        or gate.get("mode") != "autopilot"
        or gate.get("action") != "autopilot_candidate"
        or draft.payload.get("status") != "autopilot_candidate"
    ):
        raise ValueError("draft is not an authenticated autopilot candidate")
    _verified_draft_ui_identity(ledger, draft)
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    not_before = draft.payload.get("not_before_epoch")
    if (
        isinstance(not_before, bool)
        or not isinstance(not_before, int)
        or not_before < 0
        or now < not_before
    ):
        raise ValueError("draft is not due for a real-send canary")
    if ledger.get_runtime_record(f"draft-send:{draft_id}") is not None:
        raise ValueError("draft already has a terminal send claim")
    body = draft.payload.get("body")
    event_id = draft.payload.get("event_id")
    if not isinstance(body, str) or not body.strip() or not isinstance(event_id, str):
        raise ValueError("draft send identity is invalid")
    attempt_id = send_attempt_id(draft_id, event_id, draft.scope, body)
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    expires_at = now + expires_seconds
    canary = {
        "schema": "ginger_one_time_canary_v1",
        "attempt_id": attempt_id,
        "contact_key": draft.scope,
        "body_sha256": body_hash,
        "expires_at_epoch": expires_at,
    }
    store = secrets or MacOSKeychain(KEYCHAIN_SERVICE)
    account = f"{config.sender.canary_ref}:{attempt_id}"
    store.set_secret(
        account,
        json.dumps(
            canary,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii"),
    )
    record_id = f"canary-arm:{uuid.uuid4().hex}"
    try:
        ledger.append_runtime_record(
            record_id,
            DRAFT_ACTION_NAMESPACE,
            draft_id,
            "real_send_canary_armed",
            {
                "attempt_id": attempt_id,
                "body_sha256": body_hash,
                "draft_id": draft_id,
                "expires_at": expires_at,
                "one_time": True,
                "send_executed": False,
            },
            occurred_at=now,
        )
    except BaseException:
        store.delete_secret(account)
        raise
    return {
        "schema": "ginger_real_send_canary_v2",
        "draft_id": draft_id,
        "attempt_id": attempt_id,
        "expires_at": expires_at,
        "one_time": True,
        "send_executed": False,
    }


def save_correction(
    ledger: EncryptedLedger,
    draft_id: str,
    *,
    user_edit: str,
    final_reply: str,
) -> dict[str, JSONValue]:
    draft = _draft(ledger, draft_id)
    correction = record_correction(
        contact_key=draft.scope,
        model_draft=str(draft.payload.get("body", "")),
        user_edit=user_edit,
        final_reply=final_reply,
    )
    ledger.append_runtime_record(
        correction.correction_id,
        CORRECTION_NAMESPACE,
        draft.scope,
        "correction",
        cast(Mapping[str, JSONValue], correction.to_dict()),
    )
    candidates = propose_distillation_candidates(correction)
    for candidate in candidates:
        ledger.append_runtime_record(
            candidate.candidate_id,
            LEARNING_NAMESPACE,
            candidate.contact_key or "global",
            "candidate",
            cast(Mapping[str, JSONValue], candidate.to_dict()),
        )
    return {
        "schema": "ginger_correction_result_v2",
        "correction_id": correction.correction_id,
        "draft_id": draft_id,
        "candidate_ids": [candidate.candidate_id for candidate in candidates],
        "stable_facts_changed": False,
        "relationship_boundaries_changed": False,
    }


__all__ = [
    "arm_send_canary",
    "approve_draft",
    "cost_report",
    "distillation_service",
    "import_wechat_keys",
    "list_distillations",
    "list_drafts",
    "open_ledger",
    "save_correction",
    "typing_validate_draft",
]
