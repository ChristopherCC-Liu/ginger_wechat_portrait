"""Periodic, local-only distillation refresh from encrypted ledger evidence."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections import Counter
from datetime import datetime
from statistics import median
from typing import Any, Mapping, Optional, Sequence, cast
from zoneinfo import ZoneInfo

from .distillation import (
    AUTOMATIC,
    DECISION_PREFERENCES,
    EMOTION_CYCLE,
    LANGUAGE_STYLE,
    RELATIONSHIP,
    DistillationService,
    DistillationVersion,
    ProtectedFieldError,
    USER_CONFIRMED,
    payload_hash,
)
from .emotion_cycle import calculate_emotion_cycle
from .ledger import EncryptedLedger, JSONValue, LedgerEvent, RuntimeRecord
from .runtime_state import LedgerDistillationRepository
from .schema import MessageEvent


LEARNING_CANDIDATE_NAMESPACE = "learning_candidate"
LEARNING_MATERIALIZED_NAMESPACE = "learning_materialized"
LEARNING_REFRESH_NAMESPACE = "learning_refresh"
_SAFE_AUTOMATIC_DOMAINS = frozenset(
    {LANGUAGE_STYLE, DECISION_PREFERENCES, RELATIONSHIP}
)
_MAX_TERM_LENGTH = 64
_MAX_COUNTER_ITEMS = 50
_MIN_RELATIONSHIP_OUTBOUND_SAMPLES = 3
_CONVERSATION_GAP_SECONDS = 6 * 60 * 60
_RELATIONSHIP_PROTECTED_FIELDS = (
    "taboo",
    "taboos",
    "taboo_topics",
    "boundaries",
    "consent",
    "limits",
    "privacy_rules",
    "do_not_share",
    "never_do",
    "display_name",
    "ui_search_token",
)
_WARMTH_TERMS = (
    "谢谢",
    "辛苦",
    "想你",
    "爱你",
    "抱抱",
    "早安",
    "晚安",
    "保重",
    "注意安全",
    "哈哈",
    "❤",
    "🥰",
    "😘",
)
_ADDRESS_PATTERN = re.compile(
    r"^\s*(?P<address>[A-Za-z][A-Za-z0-9_-]{0,23}|[\u3400-\u9fff]{1,8})"
    r"(?:[，,:：、]\s*|\s+)"
)
_ADDRESS_STOPWORDS = frozenset(
    {
        "hi",
        "hello",
        "好",
        "好的",
        "你好",
        "您好",
        "早安",
        "晚安",
        "早上好",
        "晚上好",
        "谢谢",
        "收到",
        "可以",
        "麻烦",
        "没问题",
    }
)


def _plain(value: Mapping[str, Any]) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
            )
        ),
    )


def _bounded_term(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized[:_MAX_TERM_LENGTH]


def _counter(value: Any) -> Counter[str]:
    if not isinstance(value, Mapping):
        return Counter()
    result: Counter[str] = Counter()
    for key, count in value.items():
        term = _bounded_term(key)
        if term is None or isinstance(count, bool):
            continue
        try:
            parsed = int(count)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            result[term] += parsed
    return result


def _add_terms(counter: Counter[str], values: Any) -> None:
    if not isinstance(values, (list, tuple)):
        return
    for value in values:
        term = _bounded_term(value)
        if term is not None:
            counter[term] += 1


def _bounded_counts(counter: Counter[str]) -> dict[str, int]:
    return dict(counter.most_common(_MAX_COUNTER_ITEMS))


def _candidate_groups(
    ledger: EncryptedLedger,
) -> dict[tuple[str, Optional[str]], list[RuntimeRecord]]:
    groups: dict[tuple[str, Optional[str]], list[RuntimeRecord]] = {}
    records = ledger.list_runtime_records(
        LEARNING_CANDIDATE_NAMESPACE,
        kind="candidate",
        limit=10_000,
    )
    for record in records:
        if ledger.get_runtime_record(f"materialized:{record.record_id}") is not None:
            continue
        payload = record.payload
        domain = payload.get("domain")
        if domain not in _SAFE_AUTOMATIC_DOMAINS:
            continue
        if payload.get("status") != "candidate":
            continue
        if payload.get("requires_user_confirmation") is not False:
            continue
        contact_key: Optional[str] = None
        if domain == RELATIONSHIP:
            candidate_contact = payload.get("contact_key")
            if not isinstance(
                candidate_contact, str
            ) or not candidate_contact.startswith("contact_"):
                continue
            contact_key = candidate_contact
            if record.scope != candidate_contact:
                continue
        elif record.scope != "global":
            continue
        groups.setdefault((str(domain), contact_key), []).append(record)
    return groups


def _version_with_payload_hash(
    service: DistillationService,
    domain: str,
    payload_digest: str,
    contact_key: Optional[str] = None,
):
    versions = service.repository.list_versions(domain, contact_key)
    return next(
        (
            version
            for version in reversed(versions)
            if version.payload_hash == payload_digest
        ),
        None,
    )


def _version_covering_candidates(
    service: DistillationService,
    domain: str,
    contact_key: Optional[str],
    candidate_ids: set[str],
):
    versions = service.repository.list_versions(domain, contact_key)
    return next(
        (
            version
            for version in reversed(versions)
            if candidate_ids.issubset(set(version.evidence_ids))
        ),
        None,
    )


def _materialize_candidates(
    ledger: EncryptedLedger,
    records: Sequence[RuntimeRecord],
    version_id: str,
    now: int,
) -> None:
    for record in records:
        marker_id = f"materialized:{record.record_id}"
        if ledger.get_runtime_record(marker_id) is not None:
            continue
        ledger.append_runtime_record(
            marker_id,
            LEARNING_MATERIALIZED_NAMESPACE,
            record.scope,
            "materialized",
            {"candidate_id": record.record_id, "version_id": version_id},
            occurred_at=now,
        )


def _aggregate_candidates(
    domain: str,
    records: Sequence[RuntimeRecord],
    active_payload: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _plain(active_payload)
    previous = payload.get("correction_learning", {})
    if not isinstance(previous, Mapping):
        previous = {}
    previous_samples = int(previous.get("sample_count", 0) or 0)
    sample_count = previous_samples + len(records)

    length_total = int(previous.get("final_length_total", 0) or 0)
    emoji_total = int(previous.get("final_emoji_total", 0) or 0)
    length_delta_total = int(previous.get("length_delta_total", 0) or 0)
    emoji_delta_total = int(previous.get("emoji_delta_total", 0) or 0)
    added = _counter(previous.get("added_counts"))
    removed = _counter(previous.get("removed_counts"))
    replacements = _counter(previous.get("replacement_counts"))
    accepted_count = int(previous.get("accepted_without_changes_count", 0) or 0)
    substantial_rewrite_count = int(previous.get("substantial_rewrite_count", 0) or 0)
    shorter_count = int(previous.get("shorter_count", 0) or 0)
    longer_count = int(previous.get("longer_count", 0) or 0)
    emoji_added_count = int(previous.get("emoji_added_count", 0) or 0)
    emoji_removed_count = int(previous.get("emoji_removed_count", 0) or 0)

    for record in records:
        candidate_payload = record.payload.get("payload", {})
        if not isinstance(candidate_payload, Mapping):
            continue
        length_total += int(candidate_payload.get("final_length", 0) or 0)
        emoji_total += int(candidate_payload.get("final_emoji_count", 0) or 0)
        length_delta_total += int(
            candidate_payload.get("observed_length_delta", 0) or 0
        )
        emoji_delta_total += int(candidate_payload.get("observed_emoji_delta", 0) or 0)
        if domain != DECISION_PREFERENCES:
            _add_terms(added, candidate_payload.get("added_emoji"))
            _add_terms(removed, candidate_payload.get("removed_emoji"))
            _add_terms(added, candidate_payload.get("added_wording"))
            _add_terms(removed, candidate_payload.get("removed_wording"))
            raw_replacements = candidate_payload.get("replacements")
            if isinstance(raw_replacements, (list, tuple)):
                for item in raw_replacements:
                    if not isinstance(item, Mapping):
                        continue
                    before = _bounded_term(item.get("before"))
                    after = _bounded_term(item.get("after"))
                    if before is not None or after is not None:
                        replacements[f"{before or ''} -> {after or ''}"] += 1
        else:
            accepted_count += int(
                candidate_payload.get("accepted_without_changes") is True
            )
            substantial_rewrite_count += int(
                candidate_payload.get("substantial_rewrite") is True
            )
            length_direction = candidate_payload.get("length_direction")
            shorter_count += int(length_direction == -1)
            longer_count += int(length_direction == 1)
            emoji_direction = candidate_payload.get("emoji_direction")
            emoji_removed_count += int(emoji_direction == -1)
            emoji_added_count += int(emoji_direction == 1)

    learning = {
        "schema": "ginger_correction_learning_v2",
        "sample_count": sample_count,
        "final_length_total": length_total,
        "final_emoji_total": emoji_total,
        "length_delta_total": length_delta_total,
        "emoji_delta_total": emoji_delta_total,
        "added_counts": _bounded_counts(added),
        "removed_counts": _bounded_counts(removed),
        "replacement_counts": _bounded_counts(replacements),
        "accepted_without_changes_count": accepted_count,
        "substantial_rewrite_count": substantial_rewrite_count,
        "shorter_count": shorter_count,
        "longer_count": longer_count,
        "emoji_added_count": emoji_added_count,
        "emoji_removed_count": emoji_removed_count,
    }
    payload["correction_learning"] = learning

    if sample_count:
        average_length = length_total / sample_count
        average_emoji = emoji_total / sample_count
        if domain in {LANGUAGE_STYLE, RELATIONSHIP}:
            payload["length"] = (
                "short"
                if average_length < 24
                else "detailed"
                if average_length > 100
                else "normal"
            )
            payload["emoji_per_reply"] = round(average_emoji, 3)
            payload["preferred_emoji"] = [
                value
                for value, _ in added.most_common(5)
                if any(ord(character) >= 0x2600 for character in value)
            ]
        if domain == DECISION_PREFERENCES:
            payload["edit_preferences"] = {
                "accepted_without_changes_rate": round(
                    accepted_count / sample_count, 4
                ),
                "substantial_rewrite_rate": round(
                    substantial_rewrite_count / sample_count, 4
                ),
                "shorter_rate": round(shorter_count / sample_count, 4),
                "longer_rate": round(longer_count / sample_count, 4),
                "emoji_added_rate": round(emoji_added_count / sample_count, 4),
                "emoji_removed_rate": round(emoji_removed_count / sample_count, 4),
            }
    return payload


def _is_emoji_base(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x1F1E6 <= codepoint <= 0x1F1FF
        or 0x1F300 <= codepoint <= 0x1FAFF
        or 0x2600 <= codepoint <= 0x27BF
    )


def _emoji_tokens(text: str) -> tuple[str, ...]:
    result = []
    index = 0
    while index < len(text):
        character = text[index]
        if not _is_emoji_base(character):
            index += 1
            continue
        token = [character]
        regional_indicator = 0x1F1E6 <= ord(character) <= 0x1F1FF
        index += 1
        if (
            regional_indicator
            and index < len(text)
            and 0x1F1E6 <= ord(text[index]) <= 0x1F1FF
        ):
            token.append(text[index])
            index += 1
        while index < len(text) and (
            text[index] == "\ufe0f" or 0x1F3FB <= ord(text[index]) <= 0x1F3FF
        ):
            token.append(text[index])
            index += 1
        while (
            index + 1 < len(text)
            and text[index] == "\u200d"
            and _is_emoji_base(text[index + 1])
        ):
            token.extend((text[index], text[index + 1]))
            index += 2
            while index < len(text) and (
                text[index] == "\ufe0f" or 0x1F3FB <= ord(text[index]) <= 0x1F3FF
            ):
                token.append(text[index])
                index += 1
        result.append("".join(token))
    return tuple(result)


def _explicit_address(text: str) -> Optional[str]:
    match = _ADDRESS_PATTERN.match(text)
    if match is None:
        return None
    address = match.group("address").strip()
    if address.casefold() in _ADDRESS_STOPWORDS:
        return None
    return address


def _relationship_event_groups(
    events: Sequence[LedgerEvent],
) -> dict[str, list[LedgerEvent]]:
    groups: dict[str, list[LedgerEvent]] = {}
    for event in events:
        if (
            str(event.local_type) != "1"
            or event.direction not in {"inbound", "outbound"}
            or not event.body.strip()
            or not event.contact_key.startswith("contact_")
        ):
            continue
        groups.setdefault(event.contact_key, []).append(event)
    for contact_events in groups.values():
        contact_events.sort(
            key=lambda event: (event.create_time, event.local_id, event.event_id)
        )
    return groups


def _relationship_observation(
    events: Sequence[LedgerEvent],
) -> Optional[tuple[dict[str, Any], float]]:
    outbound = [event for event in events if event.direction == "outbound"]
    inbound = [event for event in events if event.direction == "inbound"]
    if len(outbound) < _MIN_RELATIONSHIP_OUTBOUND_SAMPLES or not inbound:
        return None

    reply_delays = []
    session_starts = []
    pending_inbound_at: Optional[int] = None
    previous_at: Optional[int] = None
    for event in events:
        if (
            previous_at is None
            or event.create_time - previous_at > _CONVERSATION_GAP_SECONDS
        ):
            session_starts.append(event.direction)
            pending_inbound_at = None
        if event.direction == "inbound":
            pending_inbound_at = event.create_time
        elif pending_inbound_at is not None:
            delay = event.create_time - pending_inbound_at
            if 0 <= delay <= _CONVERSATION_GAP_SECONDS:
                reply_delays.append(delay)
            pending_inbound_at = None
        previous_at = event.create_time
    if not reply_delays:
        return None

    lengths = [len("".join(event.body.split())) for event in outbound]
    average_length = round(sum(lengths) / len(lengths), 2)
    median_length = round(float(median(lengths)), 2)
    length_category = (
        "short"
        if average_length < 24
        else "detailed"
        if average_length > 100
        else "normal"
    )

    address_counts: Counter[str] = Counter()
    emoji_counts: Counter[str] = Counter()
    emoji_message_count = 0
    warm_message_count = 0
    warmth_marker_hits = 0
    for event in outbound:
        address = _explicit_address(event.body)
        if address is not None:
            address_counts[address] += 1
        emojis = _emoji_tokens(event.body)
        if emojis:
            emoji_message_count += 1
            emoji_counts.update(emojis)
        message_warmth_hits = sum(term in event.body for term in _WARMTH_TERMS)
        warmth_marker_hits += message_warmth_hits
        warm_message_count += int(message_warmth_hits > 0)

    address_samples = sum(address_counts.values())
    preferred_address: Optional[str] = None
    address_confidence = 0.0
    if address_samples:
        top_address, top_count = address_counts.most_common(1)[0]
        address_confidence = top_count / address_samples
        if top_count >= 2 and address_confidence >= 0.6:
            preferred_address = top_address

    warmth_score = warm_message_count / len(outbound)
    temperature = (
        "warm" if warm_message_count >= 2 and warmth_score >= 0.5 else "neutral"
    )
    outbound_started = sum(direction == "outbound" for direction in session_starts)
    initiative_rate = outbound_started / len(session_starts)
    initiative_level = (
        "high"
        if initiative_rate >= 2 / 3
        else "low"
        if initiative_rate <= 1 / 3
        else "balanced"
    )
    emoji_usage_rate = emoji_message_count / len(outbound)
    preferred_emoji = [value for value, _ in emoji_counts.most_common(5)]
    reply_delay = int(round(float(median(reply_delays))))
    event_ids = [event.event_id for event in events]

    profile = {
        "schema": "ginger_relationship_profile_v2",
        "method": "local_explainable_rules_v1",
        "evidence": {
            "event_set_hash": payload_hash({"event_ids": event_ids}),
            "text_event_count": len(events),
            "inbound_count": len(inbound),
            "outbound_count": len(outbound),
            "first_event_epoch": events[0].create_time,
            "last_event_epoch": events[-1].create_time,
        },
        "address_preference": {
            "sample_count": address_samples,
            "preferred": preferred_address,
            "confidence": round(address_confidence, 4),
            "counts": dict(address_counts.most_common(10)),
        },
        "reply_length": {
            "sample_count": len(lengths),
            "average_chars": average_length,
            "median_chars": median_length,
            "minimum_chars": min(lengths),
            "maximum_chars": max(lengths),
            "category": length_category,
        },
        "warmth": {
            "sample_count": len(outbound),
            "warm_message_count": warm_message_count,
            "marker_hit_count": warmth_marker_hits,
            "score": round(warmth_score, 4),
            "temperature": temperature,
        },
        "initiative": {
            "session_count": len(session_starts),
            "outbound_started_count": outbound_started,
            "outbound_start_rate": round(initiative_rate, 4),
            "level": initiative_level,
            "session_gap_seconds": _CONVERSATION_GAP_SECONDS,
        },
        "emoji_preference": {
            "sample_count": len(outbound),
            "messages_with_emoji": emoji_message_count,
            "usage_rate": round(emoji_usage_rate, 4),
            "preferred": preferred_emoji,
            "counts": dict(emoji_counts.most_common(10)),
        },
        "reply_latency": {
            "sample_count": len(reply_delays),
            "average_seconds": round(sum(reply_delays) / len(reply_delays), 2),
            "median_seconds": reply_delay,
            "minimum_seconds": min(reply_delays),
            "maximum_seconds": max(reply_delays),
        },
        "rules": {
            "minimum_outbound_messages": _MIN_RELATIONSHIP_OUTBOUND_SAMPLES,
            "address_minimum_occurrences": 2,
            "address_minimum_share": 0.6,
            "reply_pairing": "latest_inbound_to_first_outbound_within_session",
        },
    }
    confidence = min(
        0.95,
        0.4
        + min(len(outbound), 10) * 0.04
        + min(len(inbound), 10) * 0.02
        + min(len(reply_delays), 5) * 0.03,
    )
    return profile, round(confidence, 4)


def _nearest_user_confirmed_payload(
    service: DistillationService,
    active: DistillationVersion,
) -> Mapping[str, Any]:
    cursor: Optional[DistillationVersion] = active
    while cursor is not None:
        if cursor.correction_type == USER_CONFIRMED:
            payload = cursor.to_dict()["payload"]
            return cast(Mapping[str, Any], payload)
        cursor = (
            service.repository.get(cursor.parent_id)
            if cursor.parent_id is not None
            else None
        )
    return {}


def _relationship_base_payload(
    service: DistillationService,
    active: Optional[DistillationVersion],
) -> Optional[dict[str, Any]]:
    if active is None:
        return {}
    base = _plain(cast(Mapping[str, Any], active.to_dict()["payload"]))
    confirmed = _nearest_user_confirmed_payload(service, active)
    for field in _RELATIONSHIP_PROTECTED_FIELDS:
        if (field in base) != (field in confirmed):
            return None
        if field in base and base[field] != confirmed[field]:
            return None
    return base


def _merge_relationship_observation(
    base: Mapping[str, Any], profile: Mapping[str, Any]
) -> dict[str, Any]:
    payload = _plain(base)
    address = cast(Mapping[str, Any], profile["address_preference"])
    reply_length = cast(Mapping[str, Any], profile["reply_length"])
    warmth = cast(Mapping[str, Any], profile["warmth"])
    initiative = cast(Mapping[str, Any], profile["initiative"])
    emoji = cast(Mapping[str, Any], profile["emoji_preference"])
    latency = cast(Mapping[str, Any], profile["reply_latency"])

    payload["relationship_profile"] = _plain(profile)
    payload["preferred_address"] = address["preferred"]
    payload["length"] = reply_length["category"]
    payload["average_reply_length"] = reply_length["average_chars"]
    payload["temperature"] = warmth["temperature"]
    payload["warmth"] = warmth["temperature"]
    payload["warmth_score"] = warmth["score"]
    payload["initiative_level"] = initiative["level"]
    payload["initiative_rate"] = initiative["outbound_start_rate"]
    payload["preferred_emoji"] = list(cast(Sequence[str], emoji["preferred"]))
    payload["emoji_per_reply"] = round(
        sum(cast(Mapping[str, int], emoji["counts"]).values())
        / int(emoji["sample_count"]),
        3,
    )
    payload["emoji_usage_rate"] = emoji["usage_rate"]
    payload["emoji_policy"] = (
        "frequent"
        if float(emoji["usage_rate"]) >= 0.5
        else "occasional"
        if float(emoji["usage_rate"]) > 0
        else "none_observed"
    )
    payload["reply_delay_seconds"] = latency["median_seconds"]
    payload["response_latency_baseline"] = {
        "sample_count": latency["sample_count"],
        "median_seconds": latency["median_seconds"],
    }
    return payload


def _refresh_relationship_profiles(
    service: DistillationService,
    events: Sequence[LedgerEvent],
    *,
    activate_safe: bool,
) -> tuple[list[str], int]:
    created = []
    skipped_protected = 0
    groups = _relationship_event_groups(events)
    for contact_key, contact_events in sorted(groups.items()):
        observation = _relationship_observation(contact_events)
        if observation is None:
            continue
        profile, confidence = observation
        active = service.active(RELATIONSHIP, contact_key)
        base = _relationship_base_payload(service, active)
        if base is None:
            skipped_protected += 1
            continue
        aggregate = _merge_relationship_observation(base, profile)
        aggregate_hash = payload_hash(aggregate)
        if active is not None and active.payload_hash == aggregate_hash:
            continue
        existing = _version_with_payload_hash(
            service,
            RELATIONSHIP,
            aggregate_hash,
            contact_key,
        )
        if existing is not None:
            if activate_safe and active is None:
                service.activate(existing.version_id)
            continue
        try:
            version = service.create_version(
                RELATIONSHIP,
                aggregate,
                evidence_ids=[event.event_id for event in contact_events],
                confidence=confidence,
                contact_key=contact_key,
                correction_type=AUTOMATIC,
                protected_fields=_RELATIONSHIP_PROTECTED_FIELDS,
                activate=activate_safe,
            )
        except ProtectedFieldError:
            skipped_protected += 1
            continue
        created.append(version.version_id)
    return created, skipped_protected


def _message_events(
    events: Sequence[LedgerEvent],
    timezone_name: str,
) -> list[MessageEvent]:
    zone = ZoneInfo(timezone_name)
    result = []
    for sequence, event in enumerate(events):
        if event.direction != "outbound" or str(event.local_type) != "1":
            continue
        occurred = datetime.fromtimestamp(event.create_time, tz=zone)
        result.append(
            MessageEvent(
                event_id=event.event_id,
                occurred_at=occurred.isoformat(),
                epoch_seconds=event.create_time,
                epoch_microseconds=event.create_time * 1_000_000,
                contact_key=event.contact_key,
                contact_label="",
                direction="outbound",
                message_type="1",
                text=event.body,
                source_id="encrypted_ledger",
                source_sequence=sequence,
            )
        )
    return result


def _emotion_payload(
    events: Sequence[LedgerEvent], timezone_name: str
) -> dict[str, Any]:
    messages = _message_events(events, timezone_name)
    if not messages:
        return {}
    cycle = calculate_emotion_cycle(messages)
    daily = cycle.get("daily", [])
    latest = daily[-1] if isinstance(daily, list) and daily else {}
    metrics = latest.get("metrics", {}) if isinstance(latest, Mapping) else {}
    if not isinstance(metrics, Mapping):
        metrics = {}
    return {
        "schema": "ginger_emotion_distillation_v2",
        "scope": "outbound_text_only",
        "latest_date": latest.get("date") if isinstance(latest, Mapping) else None,
        "confidence": (
            float(latest.get("confidence", 0.0)) if isinstance(latest, Mapping) else 0.0
        ),
        "tension": float(metrics.get("tension", 0.0)),
        "activation": float(metrics.get("activation", 0.0)),
        "warmth": float(metrics.get("warmth", 0.0)),
        "uncertainty": float(metrics.get("uncertainty", 0.0)),
        "summary": cycle["summary"],
        "weekday_cycle": cycle["weekday_cycle"],
        "hourly_cycle": cycle["hourly_cycle"],
        "limitations": cycle["methodology"]["limitations"],
    }


def refresh_distillation(
    ledger: EncryptedLedger,
    *,
    timezone_name: str,
    interval_seconds: int = 86_400,
    minimum_corrections: int = 3,
    activate_safe: bool = True,
    force: bool = False,
    now_epoch: Optional[int] = None,
) -> dict[str, JSONValue]:
    """Refresh safe versions without a model or any sender access."""
    now = int(time.time()) if now_epoch is None else int(now_epoch)
    refresh_records = ledger.list_runtime_records(
        LEARNING_REFRESH_NAMESPACE,
        scope="global",
        kind="complete",
        limit=10_000,
    )
    if (
        not force
        and refresh_records
        and now - refresh_records[-1].occurred_at < max(300, interval_seconds)
    ):
        return {
            "schema": "ginger_distillation_refresh_v2",
            "due": False,
            "versions_created": 0,
            "model_calls": 0,
            "send_actions": 0,
        }

    service = DistillationService(LedgerDistillationRepository(ledger))
    created = []
    skipped_protected = 0
    events = list(ledger.iter_recent_events(limit=10_000))
    emotion_payload = _emotion_payload(events, timezone_name)
    if emotion_payload:
        active_emotion = service.active(EMOTION_CYCLE)
        emotion_hash = payload_hash(emotion_payload)
        if active_emotion is None or active_emotion.payload_hash != emotion_hash:
            outbound = [event for event in events if event.direction == "outbound"]
            confidence = float(emotion_payload.get("confidence", 0.0))
            evidence = (outbound[0].event_id, outbound[-1].event_id) if outbound else ()
            existing = _version_with_payload_hash(service, EMOTION_CYCLE, emotion_hash)
            if existing is not None:
                if activate_safe and (
                    active_emotion is None
                    or active_emotion.version_id == existing.parent_id
                ):
                    service.activate(existing.version_id)
            else:
                version = service.create_version(
                    EMOTION_CYCLE,
                    emotion_payload,
                    evidence_ids=evidence,
                    confidence=max(0.0, min(1.0, confidence)),
                    correction_type=AUTOMATIC,
                    activate=activate_safe,
                )
                created.append(version.version_id)

    groups = _candidate_groups(ledger)
    for (domain, contact_key), records in sorted(
        groups.items(), key=lambda item: (item[0][0], item[0][1] or "")
    ):
        if len(records) < max(1, minimum_corrections):
            continue
        candidate_ids = {record.record_id for record in records}
        active = service.active(domain, contact_key)
        existing = _version_covering_candidates(
            service,
            domain,
            contact_key,
            candidate_ids,
        )
        if existing is not None:
            if activate_safe and (
                active is None or active.version_id == existing.parent_id
            ):
                service.activate(existing.version_id)
            _materialize_candidates(ledger, records, existing.version_id, now)
            continue
        base_payload = active.to_dict()["payload"] if active is not None else {}
        aggregate = _aggregate_candidates(domain, records, base_payload)
        confidence_values = [
            float(record.payload.get("confidence", 0.0)) for record in records
        ]
        try:
            version = service.create_version(
                domain,
                aggregate,
                evidence_ids=[record.record_id for record in records],
                confidence=sum(confidence_values) / len(confidence_values),
                contact_key=contact_key,
                correction_type=AUTOMATIC,
                activate=activate_safe,
            )
        except ProtectedFieldError:
            skipped_protected += len(records)
            continue
        created.append(version.version_id)
        _materialize_candidates(ledger, records, version.version_id, now)

    relationship_versions, relationship_skipped = _refresh_relationship_profiles(
        service,
        events,
        activate_safe=activate_safe,
    )
    created.extend(relationship_versions)
    skipped_protected += relationship_skipped

    refresh_id = f"learning-refresh:{uuid.uuid4().hex}"
    ledger.append_runtime_record(
        refresh_id,
        LEARNING_REFRESH_NAMESPACE,
        "global",
        "complete",
        {
            "activate_safe": activate_safe,
            "model_calls": 0,
            "send_actions": 0,
            "skipped_protected": skipped_protected,
            "version_ids": created,
        },
        occurred_at=now,
    )
    return {
        "schema": "ginger_distillation_refresh_v2",
        "due": True,
        "versions_created": len(created),
        "version_ids": created,
        "skipped_protected": skipped_protected,
        "model_calls": 0,
        "send_actions": 0,
        "refresh_id": refresh_id,
    }


__all__ = [
    "LEARNING_CANDIDATE_NAMESPACE",
    "LEARNING_MATERIALIZED_NAMESPACE",
    "LEARNING_REFRESH_NAMESPACE",
    "refresh_distillation",
]
