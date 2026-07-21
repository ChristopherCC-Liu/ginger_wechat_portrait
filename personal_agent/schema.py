"""Versioned schema objects shared by the personal-agent pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


EVENT_SCHEMA = "ginger_message_event_v1"
STYLE_SCHEMA = "ginger_style_profile_v1"
BUNDLE_SCHEMA = "ginger_personal_agent_bundle_v1"
POLICY_VERSION = "ginger_manual_approval_v1"


@dataclass(frozen=True)
class MessageEvent:
    event_id: str
    occurred_at: str
    epoch_seconds: int
    epoch_microseconds: int
    contact_key: str
    contact_label: str
    direction: str
    message_type: str
    text: str
    source_id: str
    source_sequence: int
    schema: str = EVENT_SCHEMA

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceSummary:
    source_id: str
    format: str
    contact_key: str
    contact_label: str
    message_count: int
    declared_message_count: Optional[int]
    first_at: Optional[str]
    last_at: Optional[str]
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
