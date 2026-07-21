"""Plaintext-before-encryption correction events and distillation candidates.

No function in this module writes files, encrypts data, or activates a version.
The returned payload is intended to be handed to an encrypted storage boundary.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from .distillation import (
    DECISION_PREFERENCES,
    DISTILLATION_DOMAINS,
    LANGUAGE_STYLE,
    RELATIONSHIP,
    STABLE_FACTS,
    VALUES_BOUNDARIES,
)


CORRECTION_SCHEMA = "ginger_correction_v2"
CANDIDATE_SCHEMA = "ginger_distillation_candidate_v2"
_TOKEN_PATTERN = re.compile(r"[\u3400-\u9fff]+|[A-Za-z0-9_]+|[^\w\s]", re.UNICODE)


class CorrectionError(ValueError):
    """Raised for malformed correction payloads or candidates."""


def _emoji_characters(text: str) -> Tuple[str, ...]:
    result = []
    for character in text:
        codepoint = ord(character)
        if (
            0x1F1E6 <= codepoint <= 0x1F1FF
            or 0x1F300 <= codepoint <= 0x1FAFF
            or 0x2600 <= codepoint <= 0x27BF
        ):
            result.append(character)
    return tuple(result)


def _tokens(text: str) -> Tuple[str, ...]:
    return tuple(_TOKEN_PATTERN.findall(text))


@dataclass(frozen=True)
class TextDiff:
    before_length: int
    after_length: int
    length_delta: int
    before_emoji_count: int
    after_emoji_count: int
    emoji_delta: int
    added_emoji: Tuple[str, ...]
    removed_emoji: Tuple[str, ...]
    added_terms: Tuple[str, ...]
    removed_terms: Tuple[str, ...]
    replacements: Tuple[Tuple[str, str], ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "before_length": self.before_length,
            "after_length": self.after_length,
            "length_delta": self.length_delta,
            "before_emoji_count": self.before_emoji_count,
            "after_emoji_count": self.after_emoji_count,
            "emoji_delta": self.emoji_delta,
            "added_emoji": list(self.added_emoji),
            "removed_emoji": list(self.removed_emoji),
            "added_terms": list(self.added_terms),
            "removed_terms": list(self.removed_terms),
            "replacements": [
                {"before": before, "after": after}
                for before, after in self.replacements
            ],
        }


def structured_text_diff(before: str, after: str) -> TextDiff:
    if not isinstance(before, str) or not isinstance(after, str):
        raise CorrectionError("diff inputs must be strings")
    before_tokens = _tokens(before)
    after_tokens = _tokens(after)
    matcher = difflib.SequenceMatcher(a=before_tokens, b=after_tokens, autojunk=False)
    added_terms = []
    removed_terms = []
    replacements = []
    for (
        operation,
        before_start,
        before_end,
        after_start,
        after_end,
    ) in matcher.get_opcodes():
        old = "".join(before_tokens[before_start:before_end])
        new = "".join(after_tokens[after_start:after_end])
        if operation == "insert":
            added_terms.append(new)
        elif operation == "delete":
            removed_terms.append(old)
        elif operation == "replace":
            removed_terms.append(old)
            added_terms.append(new)
            replacements.append((old, new))

    before_emoji = _emoji_characters(before)
    after_emoji = _emoji_characters(after)
    emoji_matcher = difflib.SequenceMatcher(
        a=before_emoji, b=after_emoji, autojunk=False
    )
    added_emoji = []
    removed_emoji = []
    for (
        operation,
        before_start,
        before_end,
        after_start,
        after_end,
    ) in emoji_matcher.get_opcodes():
        if operation in {"insert", "replace"}:
            added_emoji.extend(after_emoji[after_start:after_end])
        if operation in {"delete", "replace"}:
            removed_emoji.extend(before_emoji[before_start:before_end])

    return TextDiff(
        before_length=len(before),
        after_length=len(after),
        length_delta=len(after) - len(before),
        before_emoji_count=len(before_emoji),
        after_emoji_count=len(after_emoji),
        emoji_delta=len(after_emoji) - len(before_emoji),
        added_emoji=tuple(added_emoji),
        removed_emoji=tuple(removed_emoji),
        added_terms=tuple(value for value in added_terms if value),
        removed_terms=tuple(value for value in removed_terms if value),
        replacements=tuple(replacements),
    )


@dataclass(frozen=True)
class CorrectionDiff:
    model_to_user: TextDiff
    user_to_final: TextDiff
    model_to_final: TextDiff

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_to_user": self.model_to_user.to_dict(),
            "user_to_final": self.user_to_final.to_dict(),
            "model_to_final": self.model_to_final.to_dict(),
        }


@dataclass(frozen=True)
class CorrectionPayload:
    correction_id: str
    created_at: str
    contact_key: str
    model_draft: str
    user_edit: str
    final_reply: str
    diff: CorrectionDiff
    schema: str = CORRECTION_SCHEMA

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "correction_id": self.correction_id,
            "created_at": self.created_at,
            "contact_key": self.contact_key,
            "model_draft": self.model_draft,
            "user_edit": self.user_edit,
            "final_reply": self.final_reply,
            "diff": self.diff.to_dict(),
        }

    def plaintext_payload(self) -> Dict[str, Any]:
        """Return the object that an external encryption layer should consume."""
        return self.to_dict()

    def to_encryption_payload(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def _aware_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CorrectionError("created_at must be timezone-aware")
    return value.isoformat(timespec="microseconds")


def record_correction(
    *,
    contact_key: str,
    model_draft: str,
    user_edit: str,
    final_reply: str,
    created_at: Optional[datetime] = None,
    id_factory: Optional[Callable[[], str]] = None,
) -> CorrectionPayload:
    """Build, but do not store, a plaintext-before-encryption correction event."""
    if not isinstance(contact_key, str) or not contact_key.strip():
        raise CorrectionError("contact_key must be a non-empty string")
    for name, value in (
        ("model_draft", model_draft),
        ("user_edit", user_edit),
        ("final_reply", final_reply),
    ):
        if not isinstance(value, str):
            raise CorrectionError(f"{name} must be a string")
    if not any((model_draft, user_edit, final_reply)):
        raise CorrectionError("correction text must not be entirely empty")
    timestamp = created_at or datetime.now(timezone.utc)
    factory = id_factory or (lambda: f"corr_{uuid.uuid4().hex}")
    return CorrectionPayload(
        correction_id=factory(),
        created_at=_aware_iso(timestamp),
        contact_key=contact_key,
        model_draft=model_draft,
        user_edit=user_edit,
        final_reply=final_reply,
        diff=CorrectionDiff(
            model_to_user=structured_text_diff(model_draft, user_edit),
            user_to_final=structured_text_diff(user_edit, final_reply),
            model_to_final=structured_text_diff(model_draft, final_reply),
        ),
    )


@dataclass(frozen=True)
class DistillationCandidate:
    candidate_id: str
    domain: str
    contact_key: Optional[str]
    evidence_ids: Tuple[str, ...]
    confidence: float
    payload: Mapping[str, Any]
    requires_user_confirmation: bool
    status: str = "candidate"
    schema: str = CANDIDATE_SCHEMA

    def __post_init__(self) -> None:
        if self.domain not in DISTILLATION_DOMAINS:
            raise CorrectionError(f"Unsupported candidate domain: {self.domain!r}")
        if self.domain == RELATIONSHIP and not self.contact_key:
            raise CorrectionError("relationship candidates require contact_key")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise CorrectionError("candidate confidence must be between 0 and 1")
        object.__setattr__(self, "confidence", float(self.confidence))
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "candidate_id": self.candidate_id,
            "domain": self.domain,
            "contact_key": self.contact_key,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "payload": dict(self.payload),
            "requires_user_confirmation": self.requires_user_confirmation,
            "status": self.status,
        }


def make_distillation_candidate(
    correction: CorrectionPayload,
    *,
    domain: str,
    payload: Mapping[str, Any],
    confidence: float,
) -> DistillationCandidate:
    """Create an auditable proposal without calling any activation API."""
    if domain not in DISTILLATION_DOMAINS:
        raise CorrectionError(f"Unsupported candidate domain: {domain!r}")
    protected = domain in {STABLE_FACTS, VALUES_BOUNDARIES} or (
        domain == RELATIONSHIP
        and any(
            marker in str(key).casefold()
            for key in payload
            for marker in (
                "boundary",
                "boundaries",
                "forbidden",
                "never",
                "禁区",
                "边界",
            )
        )
    )
    material = json.dumps(
        {
            "correction_id": correction.correction_id,
            "domain": domain,
            "payload": payload,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return DistillationCandidate(
        candidate_id=f"candidate_{hashlib.sha256(material).hexdigest()[:24]}",
        domain=domain,
        contact_key=correction.contact_key if domain == RELATIONSHIP else None,
        evidence_ids=(correction.correction_id,),
        confidence=confidence,
        payload=payload,
        requires_user_confirmation=protected,
    )


def propose_distillation_candidates(
    correction: CorrectionPayload,
) -> Tuple[DistillationCandidate, ...]:
    """Propose only safe learning domains from edit behavior.

    Stable facts and boundary-bearing domains require semantic review and are
    therefore never inferred by this convenience function.
    """
    change = correction.diff.model_to_final
    if not (
        change.length_delta
        or change.emoji_delta
        or change.added_terms
        or change.removed_terms
    ):
        return ()
    style_payload = {
        "observed_length_delta": change.length_delta,
        "observed_emoji_delta": change.emoji_delta,
        "final_length": change.after_length,
        "final_emoji_count": change.after_emoji_count,
        "added_emoji": list(change.added_emoji),
        "removed_emoji": list(change.removed_emoji),
    }
    contact_preference_payload = {
        "added_wording": list(change.added_terms),
        "removed_wording": list(change.removed_terms),
        "replacements": [
            {"before": before, "after": after} for before, after in change.replacements
        ],
    }
    # Global decision learning must not carry contact-specific wording.  Only
    # irreversible edit-direction statistics may cross contact scopes.
    global_preference_payload = {
        "accepted_without_changes": correction.model_draft == correction.final_reply,
        "substantial_rewrite": (
            change.before_length > 0
            and abs(change.length_delta) >= max(8, change.before_length // 2)
        ),
        "length_direction": (change.length_delta > 0) - (change.length_delta < 0),
        "emoji_direction": (change.emoji_delta > 0) - (change.emoji_delta < 0),
    }
    return (
        make_distillation_candidate(
            correction,
            domain=LANGUAGE_STYLE,
            payload=style_payload,
            confidence=0.65,
        ),
        make_distillation_candidate(
            correction,
            domain=DECISION_PREFERENCES,
            payload=global_preference_payload,
            confidence=0.55,
        ),
        make_distillation_candidate(
            correction,
            domain=RELATIONSHIP,
            payload={**style_payload, **contact_preference_payload},
            confidence=0.6,
        ),
    )


build_correction_payload = record_correction
