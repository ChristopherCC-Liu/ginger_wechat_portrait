"""Single-pass Ginger Personal Agent v2 orchestration.

The runtime is intentionally invoked as a short-lived ``run-once`` process by
launchd. Database discovery and rule screening happen before model construction;
UI capabilities are constructed only for an already gated send attempt.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol, cast

from .config import AgentConfig
from .costs import DailyLimits, ModelPricing
from .crypto_store import MacOSKeychain, SecretNotFoundError, SecretStore
from .decision import (
    PERMANENT_MANUAL_RISKS,
    GateResult,
    RenderControls,
    ReplyDecision,
    detect_sensitive_risks,
    evaluate_gate,
    render_reply,
)
from .distillation import (
    DECISION_PREFERENCES,
    EMOTION_CYCLE,
    LANGUAGE_STYLE,
    RELATIONSHIP,
    STABLE_FACTS,
    USER_CONFIRMED,
    VALUES_BOUNDARIES,
    DistillationService,
)
from .ledger import DuplicateSendError, EncryptedLedger, JSONValue, LedgerEvent
from .learning import refresh_distillation
from .models import (
    ModelAdapter,
    ModelConfig as AdapterModelConfig,
    create_model_adapter,
)
from .runtime_state import (
    LedgerDistillationRepository,
    PersistentDailyCostLedger,
)
from .sender import (
    CanaryGuard,
    ComputerUseSender,
    MacOSAccessibilitySender,
    SendRequest,
    Sender,
    SenderRouter,
    send_attempt_id,
)
from .storage import state_lock
from .wechat_reader import (
    PlaintextSQLiteQuery,
    SQLCipherCLIQuery,
    WeChatReader,
)


KEYCHAIN_SERVICE = "com.christophercc.ginger-agent"
BOOTSTRAP_RECORD_ID = "runtime:bootstrap:v2"
PROCESS_NAMESPACE = "processing"
DRAFT_NAMESPACE = "draft"
DRAFT_ACTION_NAMESPACE = "draft_action"
CORRECTION_NAMESPACE = "correction"
LEARNING_NAMESPACE = "learning_candidate"
SEND_RESULT_NAMESPACE = "send_result"
SEND_DRAFT_NAMESPACE = "send_draft"
MAX_PROCESS_EVENTS = 500
MAX_BODY_CONTEXT_CHARS = 4_000

_REQUEST_MARKERS = (
    "?",
    "？",
    "请",
    "麻烦",
    "能不能",
    "可以吗",
    "方便吗",
    "告诉我",
    "回复",
    "确认",
    "什么时候",
    "怎么样",
    "how",
    "when",
    "could you",
    "can you",
    "please",
)
_NO_REPLY_EXACT = frozenset(
    {
        "好",
        "好的",
        "嗯",
        "收到",
        "ok",
        "okay",
        "谢谢",
        "哈哈",
        "行",
    }
)
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all prior",
    "忽略之前",
    "忽略以上",
    "system prompt",
    "developer message",
    "设置为 autopilot",
    "绕过规则",
    "调用工具",
)
_COMMITMENT_MARKERS = (
    "我会",
    "我保证",
    "我答应",
    "替你",
    "代你",
    "确认参加",
    "确认签署",
    "i will",
    "i promise",
    "on your behalf",
)
_AUTOPILOT_SAFE_STANCES = frozenset(
    {
        "好",
        "好的",
        "可以",
        "收到",
        "知道了",
        "明白",
        "谢谢",
        "没问题",
    }
)


class RuntimeErrorBase(RuntimeError):
    """Base runtime error without private data in its message."""


class RuntimeConfigurationError(RuntimeErrorBase):
    """Raised when a required runtime input is absent or unsafe."""


class ModelFactory(Protocol):
    def __call__(self) -> ModelAdapter: ...


class SendPreflight(Protocol):
    def __call__(self, request: SendRequest) -> bool: ...


@dataclass(frozen=True)
class RunReport:
    mode: str
    paused: bool
    bootstrapped: bool
    discovered_databases: int
    scanned_rows: int
    inserted_events: int
    processed_events: int
    rule_filtered: int
    manual_items: int
    drafts: int
    model_calls: int
    learning_versions: int
    send_attempts: int
    sends_confirmed: int
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, JSONValue]:
        return cast(
            dict[str, JSONValue],
            {
                "schema": "ginger_run_report_v2",
                "mode": self.mode,
                "paused": self.paused,
                "bootstrapped": self.bootstrapped,
                "discovered_databases": self.discovered_databases,
                "scanned_rows": self.scanned_rows,
                "inserted_events": self.inserted_events,
                "processed_events": self.processed_events,
                "rule_filtered": self.rule_filtered,
                "manual_items": self.manual_items,
                "drafts": self.drafts,
                "model_calls": self.model_calls,
                "learning_versions": self.learning_versions,
                "send_attempts": self.send_attempts,
                "sends_confirmed": self.sends_confirmed,
                "warnings": list(self.warnings),
            },
        )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _context_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _process_record_id(event_id: str) -> str:
    return f"process:{event_id}"


def _draft_id(event_id: str) -> str:
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:24]
    return f"draft_{digest}"


def _draft_send_id(draft_id: str) -> str:
    return f"draft-send:{draft_id}"


def rule_requires_reply(event: LedgerEvent) -> bool:
    """Cheap, conservative model-call prefilter with no model dependency."""
    if (
        event.direction != "inbound"
        or str(event.local_type) != "1"
        or not event.body.strip()
    ):
        return False
    text = event.body.strip()
    folded = text.casefold()
    if folded in _NO_REPLY_EXACT:
        return False
    if text.startswith("[") and text.endswith("]"):
        return False
    if detect_sensitive_risks(text):
        return True
    if any(marker.casefold() in folded for marker in _INJECTION_MARKERS):
        return True
    return any(marker.casefold() in folded for marker in _REQUEST_MARKERS)


def _manual_decision(risk: str, reason: str) -> ReplyDecision:
    selected = risk if risk in PERMANENT_MANUAL_RISKS else "privacy"
    return ReplyDecision(
        intent="human_review",
        stance="需要本人判断",
        facts=(),
        commitments=(),
        risk=selected,
        confidence=1.0,
        reply_required=True,
        context_sufficient=False,
        reasons=(reason,),
    )


def _facts_are_grounded(
    decision: ReplyDecision,
    context: Mapping[str, Any],
) -> bool:
    """Require every autopilot fact to be verbatim-grounded in local evidence."""
    if not decision.facts:
        return True
    evidence = _canonical_json(context).decode("utf-8").casefold()
    return all(fact.casefold() in evidence for fact in decision.facts)


def _has_commitment_language(text: str) -> bool:
    folded = text.casefold()
    return any(marker.casefold() in folded for marker in _COMMITMENT_MARKERS)


def _safe_acknowledgement(text: str) -> bool:
    normalized = text.strip().rstrip("。.!！?？~～")
    return normalized in _AUTOPILOT_SAFE_STANCES


def _post_render_gate(
    decision: ReplyDecision,
    gate: GateResult,
    body: str,
) -> GateResult:
    body_risks = detect_sensitive_risks(body)
    if body_risks or _has_commitment_language(body):
        risks = tuple(sorted(set(gate.detected_risks) | set(body_risks)))
        return GateResult(
            mode=gate.mode,
            action="manual_required",
            autopilot_candidate=False,
            manual_required=True,
            detected_risks=risks,
            render_controls=gate.render_controls,
            reasons=gate.reasons + ("rendered_body_requires_human",),
        )
    if gate.autopilot_candidate and (decision.facts or not _safe_acknowledgement(body)):
        return GateResult(
            mode=gate.mode,
            action="draft_only",
            autopilot_candidate=False,
            manual_required=False,
            detected_risks=gate.detected_risks,
            render_controls=gate.render_controls,
            reasons=gate.reasons + ("autopilot_body_not_canned_and_fact_free",),
        )
    return gate


def _relationship_controls(
    relationship: Optional[Mapping[str, Any]], base: RenderControls
) -> RenderControls:
    if not relationship:
        return base
    tone = base.tone
    length = base.length
    delay = base.delay_seconds
    preferred_length = relationship.get("length", relationship.get("preferred_length"))
    if preferred_length in {"short", "normal", "detailed"}:
        length = str(preferred_length)
    temperature = relationship.get("temperature", relationship.get("warmth"))
    if temperature in {"warm", "calm", "direct", "neutral"}:
        tone = str(temperature)
    raw_delay = relationship.get("reply_delay_seconds", 0)
    if isinstance(raw_delay, int) and not isinstance(raw_delay, bool):
        delay = max(delay, min(86_400, max(0, raw_delay)))
    return RenderControls(tone=tone, length=length, delay_seconds=delay)


def _bounded_style_text(value: Any, maximum: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(character in normalized for character in "\r\n\x00")
    ):
        return None
    return normalized


def _emoji_style_token(value: Any) -> Optional[str]:
    token = _bounded_style_text(value, 8)
    if token is None or any(character.isalnum() for character in token):
        return None
    if not any(ord(character) >= 0x2600 for character in token):
        return None
    return token


def _personal_style_render(
    body: str,
    relationship: Mapping[str, Any],
    language_style: Mapping[str, Any],
    controls: RenderControls,
) -> str:
    """Apply bounded current-contact style after semantic decision parsing."""
    rendered = body.strip()
    preferred_address = _bounded_style_text(
        relationship.get("preferred_address"),
        16,
    )
    if (
        controls.tone == "warm"
        and preferred_address is not None
        and not rendered.startswith(preferred_address)
    ):
        separator = (
            "，"
            if any("\u3400" <= character <= "\u9fff" for character in preferred_address)
            else ", "
        )
        rendered = f"{preferred_address}{separator}{rendered}"

    emoji_policy = relationship.get("emoji_policy")
    candidates = relationship.get("preferred_emoji")
    if not isinstance(candidates, (list, tuple)) or not candidates:
        candidates = language_style.get("preferred_emoji")
    emoji = (
        _emoji_style_token(candidates[0])
        if isinstance(candidates, (list, tuple)) and candidates
        else None
    )
    if controls.tone == "warm" and emoji_policy == "frequent" and emoji is not None:
        if emoji not in rendered:
            rendered += emoji

    sentence_ending = _bounded_style_text(
        language_style.get("sentence_ending"),
        2,
    )
    if sentence_ending in {"。", "！", "!", "～", "~"} and not rendered.endswith(
        ("。", "！", "!", "？", "?", "～", "~", emoji or "\x00")
    ):
        rendered += sentence_ending
    return rendered


class AgentRuntime:
    def __init__(
        self,
        config: AgentConfig,
        ledger: EncryptedLedger,
        reader: WeChatReader,
        cost_ledger: PersistentDailyCostLedger,
        *,
        model_factory: ModelFactory,
        sender_factory: Callable[[], Sender],
        send_preflight: Optional[SendPreflight] = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.ledger = ledger
        self.reader = reader
        self.cost_ledger = cost_ledger
        self._model_factory = model_factory
        self._sender_factory = sender_factory
        self._send_preflight = send_preflight or (lambda request: True)
        self._model: Optional[ModelAdapter] = None
        self._now = now
        self.distillation = DistillationService(LedgerDistillationRepository(ledger))

    def _active_payload(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Optional[Mapping[str, Any]]:
        version = self.distillation.active(domain, contact_key)
        return None if version is None else version.to_dict()["payload"]

    def _context(self, event: LedgerEvent) -> dict[str, Any]:
        history = list(
            self.ledger.iter_recent_events(
                limit=self.config.model.context_messages,
                contact_key=event.contact_key,
            )
        )
        self_model: dict[str, Any] = {}
        for domain in (
            STABLE_FACTS,
            VALUES_BOUNDARIES,
            DECISION_PREFERENCES,
            LANGUAGE_STYLE,
            EMOTION_CYCLE,
        ):
            payload = self._active_payload(domain)
            if payload is not None:
                self_model[domain] = dict(payload)
        relationship = self._active_payload(RELATIONSHIP, event.contact_key)
        return {
            "contact_key": event.contact_key,
            "event_id": event.event_id,
            "history": [
                {
                    "create_time": item.create_time,
                    "direction": item.direction,
                    "event_id": item.event_id,
                    "local_type": item.local_type,
                    "text": item.body[-MAX_BODY_CONTEXT_CHARS:],
                }
                for item in history
            ],
            "relationship": dict(relationship or {}),
            "self_model": self_model,
        }

    def _verified_ui_identity(self, contact_key: str) -> Optional[tuple[str, str, str]]:
        active = self.distillation.active(RELATIONSHIP, contact_key)
        if active is None:
            return None
        payload = active.to_dict()["payload"]
        label = payload.get("display_name")
        search_token = payload.get("ui_search_token")
        if (
            not isinstance(label, str)
            or not label.strip()
            or not isinstance(search_token, str)
            or not search_token.strip()
            or label.strip() == search_token.strip()
        ):
            return None
        required_protections = {"display_name", "ui_search_token"}
        if not required_protections.issubset(set(active.protected_fields)):
            return None

        cursor = active
        while cursor is not None:
            ancestor_payload = cursor.to_dict()["payload"]
            if (
                cursor.correction_type == USER_CONFIRMED
                and ancestor_payload.get("display_name") == label
                and ancestor_payload.get("ui_search_token") == search_token
            ):
                return label.strip(), search_token.strip(), active.version_id
            cursor = (
                self.distillation.repository.get(cursor.parent_id)
                if cursor.parent_id is not None
                else None
            )
        return None

    def _frequency_allowed(self, contact_key: str) -> bool:
        after = max(0, int(self._now()) - 3_600)
        records = self.ledger.list_runtime_records(
            SEND_RESULT_NAMESPACE,
            scope=contact_key,
            kind="confirmed",
            after_epoch=after,
            limit=100,
        )
        return len(records) < self.config.cost.per_contact_hourly_limit

    def _model_adapter(self) -> ModelAdapter:
        if self._model is None:
            self._model = self._model_factory()
        return self._model

    def _already_processed(self, event: LedgerEvent) -> bool:
        return (
            self.ledger.get_runtime_record(_process_record_id(event.event_id))
            is not None
        )

    def _record_processing(
        self,
        event: LedgerEvent,
        kind: str,
        payload: Mapping[str, JSONValue],
    ) -> None:
        self.ledger.append_runtime_record(
            _process_record_id(event.event_id),
            PROCESS_NAMESPACE,
            event.contact_key,
            kind,
            payload,
        )

    def _record_draft(
        self,
        event: LedgerEvent,
        decision: ReplyDecision,
        gate: GateResult,
        body: str,
        context: Mapping[str, Any],
        controls: RenderControls,
    ) -> str:
        draft_id = _draft_id(event.event_id)
        relationship = cast(Mapping[str, Any], context.get("relationship", {}))
        identity = self._verified_ui_identity(event.contact_key)
        contact_label = (
            identity[0]
            if identity is not None
            else relationship.get("display_name") or event.contact_display_name
        )
        self.ledger.append_runtime_record(
            draft_id,
            DRAFT_NAMESPACE,
            event.contact_key,
            "draft",
            cast(
                Mapping[str, JSONValue],
                {
                    "body": body,
                    "contact_key": event.contact_key,
                    "contact_label": contact_label,
                    "contact_search_token": identity[1] if identity else None,
                    "context_hash": _context_hash(context),
                    "decision": decision.to_dict(),
                    "event_id": event.event_id,
                    "gate": {
                        "action": gate.action,
                        "detected_risks": list(gate.detected_risks),
                        "mode": gate.mode,
                        "reasons": list(gate.reasons),
                    },
                    "not_before_epoch": max(0, event.create_time)
                    + controls.delay_seconds,
                    "render_controls": {
                        "delay_seconds": controls.delay_seconds,
                        "length": controls.length,
                        "tone": controls.tone,
                    },
                    "status": gate.action,
                    "ui_identity_verified": identity is not None,
                    "ui_identity_version_id": identity[2] if identity else None,
                },
            ),
        )
        return draft_id

    def _send_candidate(
        self,
        event: LedgerEvent,
        draft_id: str,
        body: str,
        context_hash: str,
    ) -> tuple[bool, bool]:
        if not self.config.sender.real_send_enabled:
            return False, False
        if (
            self.config.mode != "autopilot"
            or event.contact_key not in self.config.allowlist
        ):
            return False, False
        send_marker_id = _draft_send_id(draft_id)
        if self.ledger.get_runtime_record(send_marker_id) is not None:
            return False, False
        identity = self._verified_ui_identity(event.contact_key)
        if identity is None:
            return False, False
        contact_label, search_token, _ = identity

        # Re-read before any UI mutation and invalidate a stale context.
        self.reader.poll()
        latest = list(
            self.ledger.iter_recent_events(
                limit=1,
                contact_key=event.contact_key,
            )
        )
        if (
            not latest
            or latest[-1].direction != "inbound"
            or latest[-1].event_id != event.event_id
        ):
            return False, False

        attempt_id = send_attempt_id(
            draft_id,
            event.event_id,
            event.contact_key,
            body,
        )
        request = SendRequest(
            attempt_id=attempt_id,
            contact_key=event.contact_key,
            contact_label=contact_label,
            body=body,
            search_token=search_token,
            action="click_send",
        )
        try:
            authorized = self._send_preflight(request)
        except Exception:
            authorized = False
        if authorized is not True:
            return False, False

        self.ledger.append_runtime_record(
            send_marker_id,
            SEND_DRAFT_NAMESPACE,
            event.contact_key,
            "claimed",
            {
                "draft_id": draft_id,
                "event_id": event.event_id,
                "retry_allowed": False,
            },
        )

        try:
            self.ledger.reserve_send(
                attempt_id,
                event.contact_key,
                body,
                payload={
                    "context_hash": context_hash,
                    "draft_id": draft_id,
                    "event_id": event.event_id,
                },
            )
        except DuplicateSendError:
            return False, False
        self.ledger.transition_send(
            attempt_id,
            "sending",
            expected_status="reserved",
        )
        try:
            readback_baseline = self.reader.readback_baseline(
                event.contact_key,
                after_epoch=max(0, event.create_time),
            )
        except Exception as exc:
            self.ledger.transition_send(
                attempt_id,
                "failed",
                expected_status="sending",
                payload={
                    "error_type": f"readback_baseline_{type(exc).__name__}",
                    "retry_allowed": False,
                },
            )
            return True, False
        click_started = int(self._now())
        try:
            result = self._sender_factory().execute(request)
        except Exception as exc:
            self.ledger.transition_send(
                attempt_id,
                "failed",
                expected_status="sending",
                payload={"error_type": type(exc).__name__, "retry_allowed": False},
            )
            return True, False
        if not result.clicked:
            self.ledger.transition_send(
                attempt_id,
                "failed",
                expected_status="sending",
                payload={"error_type": "not_clicked", "retry_allowed": False},
            )
            return True, False
        self.ledger.transition_send(
            attempt_id,
            "sent",
            expected_status="sending",
            payload={"backend": result.backend},
        )
        try:
            confirmed = self.reader.readback_confirm(
                event.contact_key,
                body,
                click_started,
                baseline=readback_baseline,
            )
        except Exception as exc:
            self.ledger.transition_send(
                attempt_id,
                "failed",
                expected_status="sent",
                payload={
                    "error_type": f"readback_{type(exc).__name__}",
                    "retry_allowed": False,
                },
            )
            return True, False
        if not confirmed:
            self.ledger.transition_send(
                attempt_id,
                "failed",
                expected_status="sent",
                payload={"error_type": "readback_unconfirmed", "retry_allowed": False},
            )
            return True, False
        self.ledger.transition_send(
            attempt_id,
            "readback_confirmed",
            expected_status="sent",
        )
        self.ledger.append_runtime_record(
            f"send-result:{attempt_id}",
            SEND_RESULT_NAMESPACE,
            event.contact_key,
            "confirmed",
            {"attempt_id": attempt_id, "draft_id": draft_id},
        )
        return True, True

    def _due_autopilot_sends(
        self,
        events: list[LedgerEvent],
    ) -> tuple[int, int, tuple[str, ...]]:
        if not self.config.sender.real_send_enabled:
            return 0, 0, ()
        events_by_id = {event.event_id: event for event in events}
        attempted = 0
        confirmed = 0
        warnings: list[str] = []
        now = int(self._now())
        for record in self.ledger.list_runtime_records(
            DRAFT_NAMESPACE,
            kind="draft",
            limit=10_000,
        ):
            payload = record.payload
            if payload.get("status") != "autopilot_candidate":
                continue
            if self.ledger.get_runtime_record(_draft_send_id(record.record_id)):
                continue
            not_before = payload.get("not_before_epoch")
            if (
                isinstance(not_before, bool)
                or not isinstance(not_before, int)
                or not_before < 0
            ):
                self.ledger.append_runtime_record(
                    _draft_send_id(record.record_id),
                    SEND_DRAFT_NAMESPACE,
                    record.scope,
                    "blocked",
                    {
                        "draft_id": record.record_id,
                        "reason": "invalid_not_before",
                        "retry_allowed": False,
                    },
                )
                warnings.append("pending_send_invalid_not_before")
                continue
            if now < not_before:
                continue
            event_id = payload.get("event_id")
            body = payload.get("body")
            context_hash = payload.get("context_hash")
            raw_decision = payload.get("decision")
            event = events_by_id.get(event_id) if isinstance(event_id, str) else None
            try:
                decision = ReplyDecision.from_dict(raw_decision)
            except (TypeError, ValueError):
                decision = None
            valid_payload = (
                event is not None
                and isinstance(body, str)
                and bool(body.strip())
                and isinstance(context_hash, str)
                and len(context_hash) == 64
                and decision is not None
            )
            if not valid_payload:
                self.ledger.append_runtime_record(
                    _draft_send_id(record.record_id),
                    SEND_DRAFT_NAMESPACE,
                    record.scope,
                    "blocked",
                    {
                        "draft_id": record.record_id,
                        "reason": "invalid_or_missing_durable_draft_context",
                        "retry_allowed": False,
                    },
                )
                warnings.append("pending_send_invalid_draft")
                continue
            assert event is not None and decision is not None
            assert isinstance(body, str) and isinstance(context_hash, str)
            gate = evaluate_gate(
                decision,
                message_text=event.body,
                mode=self.config.mode,
                allowlisted=event.contact_key in self.config.allowlist,
                cost_allowed=self.cost_ledger.snapshot().calls
                <= self.config.cost.daily_call_limit,
                frequency_allowed=self._frequency_allowed(event.contact_key),
                emotion=None,
            )
            gate = _post_render_gate(decision, gate, body)
            if not gate.autopilot_candidate:
                self.ledger.append_runtime_record(
                    _draft_send_id(record.record_id),
                    SEND_DRAFT_NAMESPACE,
                    event.contact_key,
                    "blocked",
                    {
                        "draft_id": record.record_id,
                        "reason": "gate_revalidation_failed",
                        "retry_allowed": False,
                    },
                )
                continue
            send_attempted, send_confirmed = self._send_candidate(
                event,
                record.record_id,
                body,
                context_hash,
            )
            attempted += int(send_attempted)
            confirmed += int(send_confirmed)
        return attempted, confirmed, tuple(warnings)

    def run_once(self) -> RunReport:
        if (
            self.config.paths.kill_switch.exists()
            or self.config.paths.pause_marker.exists()
        ):
            return RunReport(
                mode=self.config.mode,
                paused=True,
                bootstrapped=False,
                discovered_databases=0,
                scanned_rows=0,
                inserted_events=0,
                processed_events=0,
                rule_filtered=0,
                manual_items=0,
                drafts=0,
                model_calls=0,
                learning_versions=0,
                send_attempts=0,
                sends_confirmed=0,
                warnings=(),
            )

        poll = self.reader.poll()
        self.cost_ledger.record_db_polling()
        first_run = self.ledger.get_runtime_record(BOOTSTRAP_RECORD_ID) is None
        events = list(self.ledger.iter_recent_events(limit=10_000))
        if first_run:
            baseline = 0
            for event in events:
                if event.direction == "inbound" and not self._already_processed(event):
                    self._record_processing(
                        event,
                        "bootstrap_observed",
                        {"event_id": event.event_id, "model_called": False},
                    )
                    baseline += 1
            self.ledger.append_runtime_record(
                BOOTSTRAP_RECORD_ID,
                "runtime_meta",
                "global",
                "bootstrap",
                {
                    "baseline_inbound_events": baseline,
                    "completed_at_epoch": int(self._now()),
                    "model_calls": 0,
                    "send_actions": 0,
                },
            )
            return RunReport(
                mode=self.config.mode,
                paused=False,
                bootstrapped=True,
                discovered_databases=poll.discovered_databases,
                scanned_rows=poll.scanned_rows,
                inserted_events=poll.inserted_events,
                processed_events=baseline,
                rule_filtered=baseline,
                manual_items=0,
                drafts=0,
                model_calls=0,
                learning_versions=0,
                send_attempts=0,
                sends_confirmed=0,
                warnings=poll.warnings,
            )

        warnings = list(poll.warnings)
        learning_versions = 0
        if self.config.learning.enabled:
            try:
                learning = refresh_distillation(
                    self.ledger,
                    timezone_name=self.config.timezone,
                    interval_seconds=self.config.learning.refresh_interval_seconds,
                    minimum_corrections=self.config.learning.minimum_corrections,
                    activate_safe=self.config.learning.auto_activate_safe,
                    now_epoch=int(self._now()),
                )
                learning_versions = int(learning.get("versions_created", 0))
            except Exception as exc:
                warnings.append(f"learning_refresh_failed:{type(exc).__name__}")

        latest_inbound: dict[str, tuple[int, int, str]] = {}
        latest_outbound: dict[str, tuple[int, int, str]] = {}
        for candidate in events:
            position = (
                candidate.create_time,
                candidate.local_id,
                candidate.event_id,
            )
            if candidate.direction == "inbound":
                latest_inbound[candidate.contact_key] = max(
                    latest_inbound.get(candidate.contact_key, position),
                    position,
                )
            elif candidate.direction == "outbound":
                latest_outbound[candidate.contact_key] = max(
                    latest_outbound.get(candidate.contact_key, position),
                    position,
                )

        processed = rule_filtered = manual_items = drafts = model_calls = 0
        send_attempts, sends_confirmed, pending_warnings = self._due_autopilot_sends(
            events
        )
        warnings.extend(pending_warnings)
        for event in events:
            if processed >= MAX_PROCESS_EVENTS:
                break
            if event.direction != "inbound" or self._already_processed(event):
                continue
            processed += 1
            event_position = (event.create_time, event.local_id, event.event_id)
            if (
                latest_inbound.get(event.contact_key, event_position) > event_position
                or latest_outbound.get(event.contact_key, event_position)
                > event_position
            ):
                self._record_processing(
                    event,
                    "superseded",
                    {
                        "event_id": event.event_id,
                        "model_called": False,
                        "reason": "newer_contact_event_exists",
                    },
                )
                rule_filtered += 1
                continue
            if self.config.mode == "observe":
                self._record_processing(
                    event,
                    "observed",
                    {"event_id": event.event_id, "model_called": False},
                )
                rule_filtered += 1
                continue
            if not rule_requires_reply(event):
                self._record_processing(
                    event,
                    "rule_no_reply",
                    {"event_id": event.event_id, "model_called": False},
                )
                rule_filtered += 1
                continue

            sensitive = detect_sensitive_risks(event.body)
            injection = any(
                marker.casefold() in event.body.casefold()
                for marker in _INJECTION_MARKERS
            )
            context = self._context(event)
            if sensitive or injection:
                decision = _manual_decision(
                    sensitive[0] if sensitive else "privacy",
                    "deterministic_sensitive_rule"
                    if sensitive
                    else "prompt_injection_suspected",
                )
            else:
                try:
                    decision = self._model_adapter().generate_reply_decision(
                        event.body,
                        context=context,
                    )
                    model_calls += 1
                except Exception as exc:
                    self._record_processing(
                        event,
                        "model_failed",
                        {
                            "error_type": type(exc).__name__,
                            "event_id": event.event_id,
                            "model_called": True,
                        },
                    )
                    continue

            if not _facts_are_grounded(decision, context):
                decision = replace(
                    decision,
                    context_sufficient=False,
                    reasons=decision.reasons + ("facts_not_verbatim_grounded",),
                )

            emotion = self._active_payload(EMOTION_CYCLE)
            gate = evaluate_gate(
                decision,
                message_text=event.body,
                mode=self.config.mode,
                allowlisted=event.contact_key in self.config.allowlist,
                cost_allowed=self.cost_ledger.snapshot().calls
                <= self.config.cost.daily_call_limit,
                frequency_allowed=self._frequency_allowed(event.contact_key),
                emotion=emotion,
            )
            if gate.action in {"manual_required", "approval_required"}:
                manual_items += 1
            if gate.action in {"no_reply", "observe"}:
                self._record_processing(
                    event,
                    gate.action,
                    {
                        "decision": decision.to_dict(),
                        "event_id": event.event_id,
                        "gate_action": gate.action,
                        "model_called": not (sensitive or injection),
                    },
                )
                continue

            relationship = cast(Mapping[str, Any], context.get("relationship", {}))
            controls = _relationship_controls(relationship, gate.render_controls)
            body = render_reply(decision, controls=controls)
            self_model = cast(Mapping[str, Any], context.get("self_model", {}))
            language_style = self_model.get(LANGUAGE_STYLE, {})
            if not isinstance(language_style, Mapping):
                language_style = {}
            body = _personal_style_render(
                body,
                relationship,
                cast(Mapping[str, Any], language_style),
                controls,
            )
            gate = _post_render_gate(decision, gate, body)
            if gate.action == "manual_required":
                manual_items += int("rendered_body_requires_human" in gate.reasons)
            draft_id = self._record_draft(
                event,
                decision,
                gate,
                body,
                context,
                controls,
            )
            drafts += 1
            self._record_processing(
                event,
                "drafted",
                {
                    "draft_id": draft_id,
                    "event_id": event.event_id,
                    "gate_action": gate.action,
                    "model_called": not (sensitive or injection),
                },
            )
            not_before = max(0, event.create_time) + controls.delay_seconds
            if (
                gate.autopilot_candidate
                and self.config.sender.real_send_enabled
                and int(self._now()) >= not_before
            ):
                send_attempted, send_confirmed = self._send_candidate(
                    event,
                    draft_id,
                    body,
                    _context_hash(context),
                )
                send_attempts += int(send_attempted)
                sends_confirmed += int(send_confirmed)

        return RunReport(
            mode=self.config.mode,
            paused=False,
            bootstrapped=False,
            discovered_databases=poll.discovered_databases,
            scanned_rows=poll.scanned_rows,
            inserted_events=poll.inserted_events,
            processed_events=processed,
            rule_filtered=rule_filtered,
            manual_items=manual_items,
            drafts=drafts,
            model_calls=model_calls,
            learning_versions=learning_versions,
            send_attempts=send_attempts,
            sends_confirmed=sends_confirmed,
            warnings=tuple(warnings),
        )


def _adapter_endpoint(config: AgentConfig) -> str:
    base = config.model.base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


def _pricing(config: AgentConfig) -> dict[tuple[str, str], ModelPricing]:
    raw = config.cost.model_prices_per_million_tokens.get(config.model.model)
    if raw is None and config.model.provider == "local":
        raw = {"input": 0.0, "output": 0.0}
    if raw is None:
        return {}
    return {
        (config.model.provider, config.model.model): ModelPricing(
            input_per_million=Decimal(str(raw.get("input", 0))),
            output_per_million=Decimal(str(raw.get("output", 0))),
        )
    }


def build_reader(
    config: AgentConfig,
    ledger: EncryptedLedger,
    secrets: SecretStore,
    identity_key: bytes,
    *,
    first_run: bool,
    bootstrap_after_epoch: Optional[int] = None,
) -> WeChatReader:
    if config.reader.db_dir is None:
        raise RuntimeConfigurationError("reader.db_dir is not configured")
    self_username: Optional[str] = None
    try:
        self_username = secrets.get_secret(config.reader.self_id_ref).decode("utf-8")
    except SecretNotFoundError:
        pass
    except UnicodeDecodeError as exc:
        raise RuntimeConfigurationError("wechat self id is not valid UTF-8") from exc
    if config.sender.real_send_enabled and self_username is None:
        raise RuntimeConfigurationError(
            "real sending requires reader.self_id_ref in Keychain for "
            "direction-safe database readback"
        )

    if config.reader.backend == "plaintext":
        query = PlaintextSQLiteQuery()
    else:
        root = config.reader.db_dir.resolve()

        def key_provider(database: Path) -> bytes:
            resolved = database.resolve(strict=True)
            if root not in resolved.parents:
                raise RuntimeConfigurationError("database escaped configured root")
            with resolved.open("rb") as handle:
                salt = handle.read(16).hex()
            return secrets.get_secret(f"{config.reader.keychain_db_key_prefix}:{salt}")

        query = SQLCipherCLIQuery(
            key_provider,
            executable=str(config.reader.sqlcipher_path),
        )
    initial_after: Optional[int] = None
    if first_run:
        initial_after = max(
            0,
            int(time.time()) - config.reader.bootstrap_lookback_seconds,
        )
    elif bootstrap_after_epoch is None:
        raise RuntimeConfigurationError(
            "existing runtime is missing its global database bootstrap cutoff"
        )
    return WeChatReader(
        config.reader.db_dir,
        ledger,
        identity_key,
        query=query,
        self_username=self_username,
        overlap_seconds=config.reader.overlap_seconds,
        batch_size=config.reader.batch_size,
        initial_after_epoch=initial_after,
        bootstrap_after_epoch=(initial_after if first_run else bootstrap_after_epoch),
    )


def build_runtime(
    config: AgentConfig,
    *,
    secrets: Optional[SecretStore] = None,
    ledger: Optional[EncryptedLedger] = None,
    reader: Optional[WeChatReader] = None,
    model_factory: Optional[ModelFactory] = None,
    sender_factory: Optional[Callable[[], Sender]] = None,
) -> tuple[AgentRuntime, EncryptedLedger]:
    secret_store = secrets or MacOSKeychain(KEYCHAIN_SERVICE)
    try:
        state_key = secret_store.get_secret(config.state_key_ref)
        identity_key = secret_store.get_secret(config.identity_key_ref)
    except SecretNotFoundError as exc:
        raise RuntimeConfigurationError(
            "required state or identity key is missing from Keychain"
        ) from exc
    owns_ledger = ledger is None
    active_ledger = ledger or EncryptedLedger(config.paths.ledger, state_key)
    try:
        bootstrap_record = active_ledger.get_runtime_record(BOOTSTRAP_RECORD_ID)
        first_run = bootstrap_record is None
        bootstrap_after_epoch: Optional[int] = None
        if bootstrap_record is not None:
            raw_cutoff = bootstrap_record.payload.get("completed_at_epoch")
            if (
                isinstance(raw_cutoff, bool)
                or not isinstance(raw_cutoff, int)
                or raw_cutoff < 0
            ):
                raise RuntimeConfigurationError(
                    "runtime bootstrap cutoff is missing or invalid"
                )
            bootstrap_after_epoch = raw_cutoff
        active_reader = reader or build_reader(
            config,
            active_ledger,
            secret_store,
            identity_key,
            first_run=first_run,
            bootstrap_after_epoch=bootstrap_after_epoch,
        )
        cost_ledger = PersistentDailyCostLedger(
            active_ledger,
            timezone_name=config.timezone,
            limits=DailyLimits(
                max_calls=config.cost.daily_call_limit,
                max_cost=Decimal(str(config.cost.daily_usd_limit)),
            ),
            pricing=_pricing(config),
        )
    except BaseException:
        if owns_ledger:
            active_ledger.close()
        raise

    def default_model_factory() -> ModelAdapter:
        api_key: Optional[str] = None
        if config.model.api_key_ref:
            api_key = secret_store.get_secret(config.model.api_key_ref).decode("utf-8")
        adapter_config = AdapterModelConfig(
            provider=config.model.provider,
            model=config.model.model,
            endpoint=_adapter_endpoint(config),
            timeout_seconds=config.model.timeout_seconds,
            max_response_bytes=config.model.max_response_bytes,
            max_request_bytes=config.model.max_request_bytes,
            max_output_tokens=config.model.max_output_tokens,
        )
        return create_model_adapter(
            adapter_config,
            api_key=api_key,
            cost_ledger=cast(Any, cost_ledger),
        )

    def make_backend(name: str) -> Sender:
        canary = CanaryGuard(secret_store, config.sender.canary_ref)
        if name == "accessibility":
            return MacOSAccessibilitySender(
                canary=canary,
                timeout_seconds=config.sender.ui_timeout_seconds,
            )
        if config.sender.computer_use_helper is None:
            raise RuntimeConfigurationError("computer_use_helper is not configured")
        return ComputerUseSender(
            config.sender.computer_use_helper,
            canary=canary,
            timeout_seconds=config.sender.ui_timeout_seconds,
        )

    def default_sender_factory() -> Sender:
        primary = make_backend(config.sender.backend)
        fallback = (
            make_backend(config.sender.fallback_backend)
            if config.sender.fallback_backend
            else None
        )
        return SenderRouter(primary, fallback)

    canary_preflight = CanaryGuard(secret_store, config.sender.canary_ref)

    return (
        AgentRuntime(
            config,
            active_ledger,
            active_reader,
            cost_ledger,
            model_factory=model_factory or default_model_factory,
            sender_factory=sender_factory or default_sender_factory,
            send_preflight=canary_preflight.is_authorized,
        ),
        active_ledger,
    )


def run_configured_once(
    config: AgentConfig,
    *,
    secrets: Optional[SecretStore] = None,
) -> dict[str, JSONValue]:
    with state_lock(config.paths.root / "state"):
        runtime, ledger = build_runtime(config, secrets=secrets)
        try:
            return runtime.run_once().to_dict()
        finally:
            ledger.close()


__all__ = [
    "AgentRuntime",
    "BOOTSTRAP_RECORD_ID",
    "KEYCHAIN_SERVICE",
    "RunReport",
    "RuntimeConfigurationError",
    "build_reader",
    "build_runtime",
    "rule_requires_reply",
    "run_configured_once",
]
