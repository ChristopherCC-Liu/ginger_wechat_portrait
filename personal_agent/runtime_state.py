"""Persistent adapters built on the encrypted v2 ledger."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone, tzinfo
from decimal import Decimal
from typing import Any, Callable, Mapping, Optional, Tuple, cast
from zoneinfo import ZoneInfo

from .costs import (
    BudgetExceededError,
    CommittedUsage,
    CostError,
    CostReservation,
    DailyLimits,
    DailyUsage,
    ModelPricing,
    UnknownPricingError,
)
from .distillation import (
    DistillationVersion,
    VersionConflictError,
)
from .ledger import EncryptedLedger, JSONValue, RuntimeRecord


DISTILLATION_NAMESPACE = "distillation"
COST_NAMESPACE = "model_cost"
GLOBAL_SCOPE = "global"


def _scope(domain: str, contact_key: Optional[str]) -> str:
    return f"{domain}:{contact_key or GLOBAL_SCOPE}"


def _version_from_record(record: RuntimeRecord) -> DistillationVersion:
    return DistillationVersion(**cast(dict[str, Any], dict(record.payload)))


class LedgerDistillationRepository:
    """Immutable distillation versions with an encrypted active pointer."""

    def __init__(self, ledger: EncryptedLedger) -> None:
        self._ledger = ledger

    def add(self, version: DistillationVersion) -> None:
        if self._ledger.get_runtime_record(version.version_id) is not None:
            raise VersionConflictError(f"Duplicate version_id: {version.version_id}")
        if version.parent_id is not None:
            parent = self.get(version.parent_id)
            if parent.scope != version.scope:
                raise VersionConflictError(
                    "Parent version crosses a domain or contact namespace"
                )
        self._ledger.append_runtime_record(
            version.version_id,
            DISTILLATION_NAMESPACE,
            _scope(version.domain, version.contact_key),
            "version",
            cast(Mapping[str, JSONValue], version.to_dict()),
        )

    def get(self, version_id: str) -> DistillationVersion:
        record = self._ledger.get_runtime_record(version_id)
        if record is None or record.namespace != DISTILLATION_NAMESPACE:
            raise VersionConflictError(f"Unknown version_id: {version_id}")
        return _version_from_record(record)

    def list_versions(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Tuple[DistillationVersion, ...]:
        records = self._ledger.list_runtime_records(
            DISTILLATION_NAMESPACE,
            scope=_scope(domain, contact_key),
            kind="version",
            limit=10_000,
        )
        return tuple(_version_from_record(record) for record in records)

    def get_active(
        self, domain: str, contact_key: Optional[str] = None
    ) -> Optional[DistillationVersion]:
        record = self._ledger.get_active_runtime_record(
            DISTILLATION_NAMESPACE,
            _scope(domain, contact_key),
        )
        return None if record is None else _version_from_record(record)

    def set_active(self, version_id: str) -> DistillationVersion:
        version = self.get(version_id)
        self._ledger.set_active_runtime_record(
            DISTILLATION_NAMESPACE,
            _scope(version.domain, version.contact_key),
            version.version_id,
        )
        return version


def _timezone(value: str | tzinfo) -> tzinfo:
    if isinstance(value, tzinfo):
        return value
    try:
        return ZoneInfo(value)
    except Exception as exc:  # pragma: no cover - platform timezone data varies
        raise CostError(f"Unknown timezone: {value}") from exc


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CostError("budget timestamps must be timezone-aware")
    return value


class PersistentDailyCostLedger:
    """Append-only encrypted model budget journal that survives restarts.

    Callers must hold the runtime state lock around a complete model operation;
    this keeps the budget check and append sequence single-writer across launchd
    invocations.
    """

    def __init__(
        self,
        ledger: EncryptedLedger,
        *,
        timezone_name: str | tzinfo,
        limits: DailyLimits,
        pricing: Mapping[tuple[str, str], ModelPricing],
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self._ledger = ledger
        self.timezone = _timezone(timezone_name)
        self.limits = limits
        self.pricing = dict(pricing)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _date(self, now: Optional[datetime] = None) -> date:
        return _aware(now or self._clock()).astimezone(self.timezone).date()

    def _pricing(self, provider: str, model: str) -> ModelPricing:
        try:
            return self.pricing[(provider, model)]
        except KeyError as exc:
            raise UnknownPricingError(
                f"No pricing configured for provider={provider!r}, model={model!r}"
            ) from exc

    def estimate(
        self, provider: str, model: str, input_tokens: int, output_tokens: int
    ) -> Decimal:
        return self._pricing(provider, model).estimate(input_tokens, output_tokens)

    def _records(self, budget_date: date) -> tuple[RuntimeRecord, ...]:
        return self._ledger.list_runtime_records(
            COST_NAMESPACE,
            scope=budget_date.isoformat(),
            limit=10_000,
        )

    def _state(
        self, budget_date: date
    ) -> tuple[dict[str, CostReservation], dict[str, CommittedUsage]]:
        reserved: dict[str, CostReservation] = {}
        committed: dict[str, CommittedUsage] = {}
        for record in self._records(budget_date):
            payload = record.payload
            reservation_id = str(payload.get("reservation_id", ""))
            if record.kind == "reserve":
                reserved[reservation_id] = CostReservation(
                    reservation_id=reservation_id,
                    budget_date=budget_date,
                    provider=str(payload["provider"]),
                    model=str(payload["model"]),
                    input_tokens=int(cast(Any, payload["input_tokens"])),
                    output_tokens=int(cast(Any, payload["output_tokens"])),
                    estimated_cost=Decimal(str(payload["estimated_cost"])),
                )
            elif record.kind == "commit" and reservation_id in reserved:
                source = reserved.pop(reservation_id)
                committed[reservation_id] = CommittedUsage(
                    reservation_id=reservation_id,
                    budget_date=budget_date,
                    provider=source.provider,
                    model=source.model,
                    input_tokens=int(cast(Any, payload["input_tokens"])),
                    output_tokens=int(cast(Any, payload["output_tokens"])),
                    actual_cost=Decimal(str(payload["actual_cost"])),
                )
            elif record.kind == "failed" and reservation_id in reserved:
                source = reserved.pop(reservation_id)
                committed[reservation_id] = CommittedUsage(
                    reservation_id=reservation_id,
                    budget_date=budget_date,
                    provider=source.provider,
                    model=source.model,
                    input_tokens=source.input_tokens,
                    output_tokens=source.output_tokens,
                    actual_cost=source.estimated_cost,
                )
        return reserved, committed

    def reserve(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        now: Optional[datetime] = None,
    ) -> CostReservation:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (input_tokens, output_tokens)
        ):
            raise CostError("token counts must be non-negative integers")
        budget_date = self._date(now)
        estimated = self.estimate(provider, model, input_tokens, output_tokens)
        usage = self.snapshot(now=now)
        if usage.calls + 1 > self.limits.max_calls:
            raise BudgetExceededError("Daily model call limit would be exceeded")
        if usage.total_cost + estimated > self.limits.max_cost:
            raise BudgetExceededError("Daily model cost limit would be exceeded")
        reservation = CostReservation(
            reservation_id=f"cost_{uuid.uuid4().hex}",
            budget_date=budget_date,
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost=estimated,
        )
        self._ledger.append_runtime_record(
            reservation.reservation_id,
            COST_NAMESPACE,
            budget_date.isoformat(),
            "reserve",
            {
                "estimated_cost": str(estimated),
                "input_tokens": input_tokens,
                "model": model,
                "output_tokens": output_tokens,
                "provider": provider,
                "reservation_id": reservation.reservation_id,
            },
        )
        return reservation

    def has_active_reservation(self, reservation_id: str) -> bool:
        record = self._ledger.get_runtime_record(reservation_id)
        if record is None or record.namespace != COST_NAMESPACE:
            return False
        budget_date = date.fromisoformat(record.scope)
        reserved, _ = self._state(budget_date)
        return reservation_id in reserved

    def _active(self, reservation_id: str) -> CostReservation:
        record = self._ledger.get_runtime_record(reservation_id)
        if record is None or record.namespace != COST_NAMESPACE:
            raise CostError(f"Unknown active reservation: {reservation_id}")
        reserved, committed = self._state(date.fromisoformat(record.scope))
        if reservation_id in committed:
            raise CostError("Reservation is already committed")
        try:
            return reserved[reservation_id]
        except KeyError as exc:
            raise CostError(f"Unknown active reservation: {reservation_id}") from exc

    def commit(
        self,
        reservation_id: str,
        *,
        actual_input_tokens: int,
        actual_output_tokens: int,
    ) -> CommittedUsage:
        reservation = self._active(reservation_id)
        if actual_input_tokens > reservation.input_tokens:
            raise CostError("actual_input_tokens exceeds the reserved upper bound")
        if actual_output_tokens > reservation.output_tokens:
            raise CostError("actual_output_tokens exceeds the reserved upper bound")
        actual = self.estimate(
            reservation.provider,
            reservation.model,
            actual_input_tokens,
            actual_output_tokens,
        )
        usage = CommittedUsage(
            reservation_id=reservation_id,
            budget_date=reservation.budget_date,
            provider=reservation.provider,
            model=reservation.model,
            input_tokens=actual_input_tokens,
            output_tokens=actual_output_tokens,
            actual_cost=actual,
        )
        self._ledger.append_runtime_record(
            f"{reservation_id}:commit",
            COST_NAMESPACE,
            reservation.budget_date.isoformat(),
            "commit",
            {
                "actual_cost": str(actual),
                "input_tokens": actual_input_tokens,
                "output_tokens": actual_output_tokens,
                "reservation_id": reservation_id,
            },
        )
        return usage

    def refund(self, reservation_id: str) -> CostReservation:
        """Close a failed call conservatively against the daily budget.

        The transport cannot prove that a timed-out or malformed request was
        unbilled, so a failed attempt consumes one call and its reserved maximum.
        """
        reservation = self._active(reservation_id)
        self._ledger.append_runtime_record(
            f"{reservation_id}:failed",
            COST_NAMESPACE,
            reservation.budget_date.isoformat(),
            "failed",
            {"reservation_id": reservation_id},
        )
        return reservation

    def snapshot(self, *, now: Optional[datetime] = None) -> DailyUsage:
        budget_date = self._date(now)
        reserved, committed = self._state(budget_date)
        reserved_cost = sum(
            (item.estimated_cost for item in reserved.values()), Decimal("0")
        )
        committed_cost = sum(
            (item.actual_cost for item in committed.values()), Decimal("0")
        )
        return DailyUsage(
            budget_date=budget_date,
            calls=len(reserved) + len(committed),
            reserved_calls=len(reserved),
            committed_calls=len(committed),
            total_cost=reserved_cost + committed_cost,
            reserved_cost=reserved_cost,
            committed_cost=committed_cost,
            max_calls=self.limits.max_calls,
            max_cost=self.limits.max_cost,
        )

    def record_zero_call_operation(
        self, operation: str, *, now: Optional[datetime] = None
    ) -> DailyUsage:
        if operation not in {"rule_screening", "db_polling"}:
            raise CostError(f"Unsupported zero-call operation: {operation!r}")
        return self.snapshot(now=now)

    def record_rule_screening(self, *, now: Optional[datetime] = None) -> DailyUsage:
        return self.record_zero_call_operation("rule_screening", now=now)

    def record_db_polling(self, *, now: Optional[datetime] = None) -> DailyUsage:
        return self.record_zero_call_operation("db_polling", now=now)


__all__ = [
    "COST_NAMESPACE",
    "DISTILLATION_NAMESPACE",
    "LedgerDistillationRepository",
    "PersistentDailyCostLedger",
]
