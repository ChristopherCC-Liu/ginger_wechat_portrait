"""Immutable, domain-isolated distillation state for Personal Agent v2.

This module contains no persistence or private-file access.  Callers may inject a
repository; :class:`InMemoryDistillationRepository` is the safe default for tests
and ephemeral runtime use.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)


STABLE_FACTS = "stable_facts"
VALUES_BOUNDARIES = "values_boundaries"
RELATIONSHIP = "relationship"
DECISION_PREFERENCES = "decision_preferences"
LANGUAGE_STYLE = "language_style"
EMOTION_CYCLE = "emotion_cycle"

DISTILLATION_DOMAINS = frozenset(
    {
        STABLE_FACTS,
        VALUES_BOUNDARIES,
        RELATIONSHIP,
        DECISION_PREFERENCES,
        LANGUAGE_STYLE,
        EMOTION_CYCLE,
    }
)

AUTOMATIC = "automatic"
USER_CONFIRMED = "user_confirmed"
CORRECTION_TYPES = frozenset({AUTOMATIC, USER_CONFIRMED})
GLOBAL_NAMESPACE = "__global__"


class DistillationError(ValueError):
    """Base error for invalid or unsafe distillation operations."""


class ProtectedFieldError(DistillationError):
    """Raised when automatic learning attempts to change protected knowledge."""


class VersionConflictError(DistillationError):
    """Raised when a version would cross a domain or contact boundary."""


JsonScalar = Optional[object]
JsonValue = Any


def _validate_domain(domain: str) -> str:
    if domain not in DISTILLATION_DOMAINS:
        raise DistillationError(f"Unsupported distillation domain: {domain!r}")
    return domain


def _validate_contact_key(domain: str, contact_key: Optional[str]) -> Optional[str]:
    if contact_key is not None:
        if not isinstance(contact_key, str) or not contact_key.strip():
            raise DistillationError("contact_key must be a non-empty string")
        if contact_key == GLOBAL_NAMESPACE:
            raise DistillationError("contact_key uses a reserved namespace")
    if domain == RELATIONSHIP and contact_key is None:
        raise DistillationError("relationship versions require a contact_key namespace")
    return contact_key


def _scope(domain: str, contact_key: Optional[str]) -> Tuple[str, str]:
    _validate_domain(domain)
    _validate_contact_key(domain, contact_key)
    return domain, contact_key or GLOBAL_NAMESPACE


def _validate_json_value(value: Any, path: str = "payload") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DistillationError(f"{path} contains a non-finite number")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise DistillationError(f"{path} keys must be strings")
            _validate_json_value(child, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_json_value(child, f"{path}[{index}]")
        return
    raise DistillationError(f"{path} contains unsupported type {type(value).__name__}")


def _freeze(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


def _thaw(value: JsonValue) -> JsonValue:
    if isinstance(value, Mapping):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    _validate_json_value(payload)
    return json.dumps(
        _thaw(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def payload_hash(payload: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 for a JSON-compatible payload."""
    return hashlib.sha256(_canonical_payload(payload)).hexdigest()


def _aware_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DistillationError("created_at must be timezone-aware")
    return value.isoformat(timespec="microseconds")


def _parse_aware_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DistillationError("created_at must be an ISO-8601 datetime") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DistillationError("created_at must include a timezone")
    return parsed


def _unique_strings(values: Iterable[str], field_name: str) -> Tuple[str, ...]:
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise DistillationError(f"{field_name} values must be non-empty strings")
        if value not in seen:
            result.append(value)
            seen.add(value)
    return tuple(result)


def _mandatory_protected_fields(domain: str) -> Tuple[str, ...]:
    if domain in {STABLE_FACTS, VALUES_BOUNDARIES}:
        return ("*",)
    if domain == RELATIONSHIP:
        return ("boundaries", "display_name", "ui_search_token")
    return ()


def _merge_protected_fields(
    domain: str,
    inherited: Sequence[str],
    requested: Sequence[str],
) -> Tuple[str, ...]:
    values = (
        list(_mandatory_protected_fields(domain)) + list(inherited) + list(requested)
    )
    result = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise DistillationError("protected_fields values must be non-empty strings")
        normalized = value.strip(".")
        if not normalized:
            raise DistillationError("protected_fields contains an invalid path")
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return tuple(result)


def _changed_paths(before: Any, after: Any, prefix: str = "") -> Tuple[str, ...]:
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        paths = []
        for key in sorted(set(before) | set(after)):
            child_path = f"{prefix}.{key}" if prefix else key
            if key not in before or key not in after:
                paths.append(child_path)
            else:
                paths.extend(_changed_paths(before[key], after[key], child_path))
        return tuple(paths)
    if _thaw(before) != _thaw(after):
        return (prefix or "*",)
    return ()


def _looks_like_boundary(path: str) -> bool:
    parts = {part.lower() for part in path.replace("[", ".").split(".") if part}
    return any("boundar" in part for part in parts) or bool(
        parts & {"consent", "limits", "privacy_rules", "do_not_share", "never_do"}
    )


def _path_is_protected(path: str, protected_fields: Sequence[str]) -> bool:
    for protected in protected_fields:
        if protected == "*":
            return True
        if path == protected or path.startswith(f"{protected}."):
            return True
        if protected.startswith(f"{path}."):
            return True
    return False


@dataclass(frozen=True)
class DistillationVersion:
    """An immutable snapshot in exactly one domain and contact namespace."""

    version_id: str
    parent_id: Optional[str]
    created_at: str
    evidence_ids: Tuple[str, ...]
    confidence: float
    payload_hash: str
    protected_fields: Tuple[str, ...]
    domain: str
    contact_key: Optional[str]
    correction_type: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        _validate_domain(self.domain)
        _validate_contact_key(self.domain, self.contact_key)
        if not isinstance(self.version_id, str) or not self.version_id:
            raise DistillationError("version_id must be a non-empty string")
        if self.parent_id is not None and (
            not isinstance(self.parent_id, str) or not self.parent_id
        ):
            raise DistillationError("parent_id must be null or a non-empty string")
        _parse_aware_iso(self.created_at)
        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise DistillationError("confidence must be numeric")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise DistillationError("confidence must be between 0 and 1")
        if self.correction_type not in CORRECTION_TYPES:
            raise DistillationError(
                f"Unsupported correction_type: {self.correction_type!r}"
            )
        if not isinstance(self.payload, Mapping):
            raise DistillationError("payload must be an object")

        evidence_ids = _unique_strings(self.evidence_ids, "evidence_ids")
        protected_fields = _merge_protected_fields(
            self.domain, (), self.protected_fields
        )
        immutable_payload = _freeze(dict(self.payload))
        actual_hash = payload_hash(immutable_payload)
        if self.payload_hash != actual_hash:
            raise DistillationError("payload_hash does not match payload")

        object.__setattr__(self, "evidence_ids", evidence_ids)
        object.__setattr__(self, "protected_fields", protected_fields)
        object.__setattr__(self, "confidence", float(self.confidence))
        object.__setattr__(self, "payload", immutable_payload)

    @property
    def scope(self) -> Tuple[str, str]:
        return _scope(self.domain, self.contact_key)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_id": self.version_id,
            "parent_id": self.parent_id,
            "created_at": self.created_at,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence,
            "payload_hash": self.payload_hash,
            "protected_fields": list(self.protected_fields),
            "domain": self.domain,
            "contact_key": self.contact_key,
            "correction_type": self.correction_type,
            "payload": _thaw(self.payload),
        }


class DistillationRepository(Protocol):
    """Minimal injectable repository contract; implementations must preserve scope."""

    def add(self, version: DistillationVersion) -> None: ...

    def get(self, version_id: str) -> DistillationVersion: ...

    def list_versions(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Tuple[DistillationVersion, ...]: ...

    def get_active(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Optional[DistillationVersion]: ...

    def set_active(self, version_id: str) -> DistillationVersion: ...


class InMemoryDistillationRepository:
    """Thread-safe in-memory repository with domain/contact isolation."""

    def __init__(self) -> None:
        self._versions: Dict[str, DistillationVersion] = {}
        self._by_scope: Dict[Tuple[str, str], list[str]] = {}
        self._active: Dict[Tuple[str, str], str] = {}
        self._lock = threading.RLock()

    def add(self, version: DistillationVersion) -> None:
        with self._lock:
            if version.version_id in self._versions:
                raise VersionConflictError(
                    f"Duplicate version_id: {version.version_id}"
                )
            if version.parent_id is not None:
                parent = self._versions.get(version.parent_id)
                if parent is None:
                    raise VersionConflictError(
                        f"Unknown parent version: {version.parent_id}"
                    )
                if parent.scope != version.scope:
                    raise VersionConflictError(
                        "Parent version crosses a domain or contact namespace"
                    )
            self._versions[version.version_id] = version
            self._by_scope.setdefault(version.scope, []).append(version.version_id)

    def get(self, version_id: str) -> DistillationVersion:
        with self._lock:
            try:
                return self._versions[version_id]
            except KeyError as exc:
                raise DistillationError(
                    f"Unknown distillation version: {version_id}"
                ) from exc

    def list_versions(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Tuple[DistillationVersion, ...]:
        scope = _scope(domain, contact_key)
        with self._lock:
            return tuple(self._versions[item] for item in self._by_scope.get(scope, ()))

    def get_active(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Optional[DistillationVersion]:
        scope = _scope(domain, contact_key)
        with self._lock:
            version_id = self._active.get(scope)
            return self._versions.get(version_id) if version_id is not None else None

    def set_active(self, version_id: str) -> DistillationVersion:
        with self._lock:
            version = self.get(version_id)
            self._active[version.scope] = version_id
            return version


class DistillationService:
    """Creates, activates, and rolls back immutable distillation versions."""

    def __init__(
        self,
        repository: Optional[DistillationRepository] = None,
        *,
        clock: Optional[Callable[[], datetime]] = None,
        id_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        self.repository = (
            repository if repository is not None else InMemoryDistillationRepository()
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: f"dist_{uuid.uuid4().hex}")

    def create_version(
        self,
        domain: str,
        payload: Mapping[str, Any],
        *,
        evidence_ids: Iterable[str] = (),
        confidence: float,
        contact_key: Optional[str] = None,
        correction_type: str = AUTOMATIC,
        protected_fields: Iterable[str] = (),
        parent_id: Optional[str] = None,
        created_at: Optional[datetime] = None,
        activate: bool = False,
    ) -> DistillationVersion:
        _validate_domain(domain)
        _validate_contact_key(domain, contact_key)
        if correction_type not in CORRECTION_TYPES:
            raise DistillationError(f"Unsupported correction_type: {correction_type!r}")
        if not isinstance(payload, Mapping):
            raise DistillationError("payload must be an object")

        active = self.repository.get_active(domain, contact_key)
        parent = None
        if parent_id is not None:
            parent = self.repository.get(parent_id)
            if parent.scope != _scope(domain, contact_key):
                raise VersionConflictError(
                    "Parent version crosses a domain or contact namespace"
                )
        elif active is not None:
            parent = active
            parent_id = active.version_id

        inherited = parent.protected_fields if parent is not None else ()
        protections = _merge_protected_fields(
            domain, inherited, tuple(protected_fields)
        )
        previous_payload: Mapping[str, Any] = (
            parent.payload if parent is not None else {}
        )
        changes = _changed_paths(previous_payload, payload)
        protected_changes = tuple(
            path
            for path in changes
            if _path_is_protected(path, protections)
            or (
                domain in {VALUES_BOUNDARIES, RELATIONSHIP}
                and _looks_like_boundary(path)
            )
        )
        if domain == STABLE_FACTS and changes:
            protected_changes = changes
        if protected_changes and correction_type != USER_CONFIRMED:
            fields = ", ".join(protected_changes)
            raise ProtectedFieldError(
                "Protected knowledge requires an explicit user_confirmed correction: "
                f"{fields}"
            )

        immutable_payload = _freeze(dict(payload))
        timestamp = created_at or self._clock()
        version = DistillationVersion(
            version_id=self._id_factory(),
            parent_id=parent_id,
            created_at=_aware_iso(timestamp),
            evidence_ids=_unique_strings(evidence_ids, "evidence_ids"),
            confidence=confidence,
            payload_hash=payload_hash(immutable_payload),
            protected_fields=protections,
            domain=domain,
            contact_key=contact_key,
            correction_type=correction_type,
            payload=immutable_payload,
        )
        self.repository.add(version)
        if activate:
            self.activate(version.version_id)
        return version

    def activate(self, version_id: str) -> DistillationVersion:
        version = self.repository.get(version_id)
        if version.correction_type != USER_CONFIRMED:
            parent_payload: Mapping[str, Any] = {}
            if version.parent_id is not None:
                parent_payload = self.repository.get(version.parent_id).payload
            changes = _changed_paths(parent_payload, version.payload)
            if any(
                _path_is_protected(path, version.protected_fields)
                or (
                    version.domain in {VALUES_BOUNDARIES, RELATIONSHIP}
                    and _looks_like_boundary(path)
                )
                for path in changes
            ):
                raise ProtectedFieldError(
                    "Automatic versions that change protected knowledge cannot be activated"
                )
        return self.repository.set_active(version_id)

    def active(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Optional[DistillationVersion]:
        return self.repository.get_active(domain, contact_key)

    def rollback(
        self,
        domain: str,
        target_version_id: str,
        *,
        contact_key: Optional[str] = None,
    ) -> DistillationVersion:
        current = self.repository.get_active(domain, contact_key)
        if current is None:
            raise DistillationError("Cannot roll back a scope with no active version")
        target = self.repository.get(target_version_id)
        if target.scope != current.scope:
            raise VersionConflictError(
                "Rollback target crosses a domain or contact namespace"
            )

        cursor: Optional[DistillationVersion] = current
        while cursor is not None and cursor.version_id != target.version_id:
            cursor = (
                self.repository.get(cursor.parent_id)
                if cursor.parent_id is not None
                else None
            )
        if cursor is None:
            raise VersionConflictError(
                "Rollback target is not an ancestor of the active version"
            )
        return self.repository.set_active(target.version_id)


# Short aliases keep the public API readable without creating a second implementation.
InMemoryRepository = InMemoryDistillationRepository
VersionedDistillation = DistillationService
