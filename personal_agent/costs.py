"""Timezone-aware, pre-call model budget accounting."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone, tzinfo
from decimal import Decimal, InvalidOperation
from typing import Callable, Dict, Mapping, Optional, Tuple
from zoneinfo import ZoneInfo


MILLION = Decimal("1000000")
ZERO_COST_OPERATIONS = frozenset({"rule_screening", "db_polling"})


class CostError(ValueError):
    """Base error for invalid cost accounting operations."""


class BudgetExceededError(CostError):
    """Raised before a model call when a daily limit would be exceeded."""


class UnknownPricingError(CostError):
    """Raised when no configured price exists for a provider/model pair."""


def _decimal(value: object, field_name: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise CostError(f"{field_name} must be numeric") from exc
    if not result.is_finite() or result < 0:
        raise CostError(f"{field_name} must be a finite non-negative number")
    return result


def _tokens(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CostError(f"{field_name} must be a non-negative integer")
    return value


def _timezone(value: object) -> tzinfo:
    if isinstance(value, str):
        try:
            return ZoneInfo(value)
        except Exception as exc:  # pragma: no cover - platform zoneinfo details vary
            raise CostError(f"Unknown timezone: {value}") from exc
    if isinstance(value, tzinfo):
        return value
    raise CostError("timezone must be a zone name or tzinfo")


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CostError("budget timestamps must be timezone-aware")
    return value


@dataclass(frozen=True)
class ModelPricing:
    input_per_million: Decimal
    output_per_million: Decimal

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "input_per_million",
            _decimal(self.input_per_million, "input_per_million"),
        )
        object.__setattr__(
            self,
            "output_per_million",
            _decimal(self.output_per_million, "output_per_million"),
        )

    def estimate(self, input_tokens: int, output_tokens: int) -> Decimal:
        input_count = _tokens(input_tokens, "input_tokens")
        output_count = _tokens(output_tokens, "output_tokens")
        return (
            Decimal(input_count) * self.input_per_million
            + Decimal(output_count) * self.output_per_million
        ) / MILLION


@dataclass(frozen=True)
class DailyLimits:
    max_calls: int
    max_cost: Decimal

    def __post_init__(self) -> None:
        if isinstance(self.max_calls, bool) or not isinstance(self.max_calls, int):
            raise CostError("max_calls must be an integer")
        if self.max_calls < 0:
            raise CostError("max_calls must be non-negative")
        object.__setattr__(self, "max_cost", _decimal(self.max_cost, "max_cost"))


@dataclass(frozen=True)
class CostReservation:
    reservation_id: str
    budget_date: date
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    estimated_cost: Decimal


@dataclass(frozen=True)
class CommittedUsage:
    reservation_id: str
    budget_date: date
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    actual_cost: Decimal


@dataclass(frozen=True)
class DailyUsage:
    budget_date: date
    calls: int
    reserved_calls: int
    committed_calls: int
    total_cost: Decimal
    reserved_cost: Decimal
    committed_cost: Decimal
    max_calls: int
    max_cost: Decimal

    @property
    def calls_remaining(self) -> int:
        return max(0, self.max_calls - self.calls)

    @property
    def cost_remaining(self) -> Decimal:
        return max(Decimal("0"), self.max_cost - self.total_cost)


@dataclass
class _DayState:
    reserved_calls: int = 0
    committed_calls: int = 0
    reserved_cost: Decimal = Decimal("0")
    committed_cost: Decimal = Decimal("0")


class DailyCostLedger:
    """Reserve model budget before transport, then commit or refund it."""

    def __init__(
        self,
        *,
        timezone_name: object,
        limits: DailyLimits,
        pricing: Mapping[Tuple[str, str], ModelPricing],
        clock: Optional[Callable[[], datetime]] = None,
        id_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        self.timezone = _timezone(timezone_name)
        self.limits = limits
        self.pricing = dict(pricing)
        for key, value in self.pricing.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not all(isinstance(part, str) and part for part in key)
            ):
                raise CostError("pricing keys must be (provider, model) strings")
            if not isinstance(value, ModelPricing):
                raise CostError("pricing values must be ModelPricing")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: f"cost_{uuid.uuid4().hex}")
        self._days: Dict[date, _DayState] = {}
        self._reservations: Dict[str, CostReservation] = {}
        self._committed: Dict[str, CommittedUsage] = {}
        self._lock = threading.RLock()

    def _date(self, now: Optional[datetime]) -> date:
        value = _aware(now or self._clock())
        return value.astimezone(self.timezone).date()

    def _price(self, provider: str, model: str) -> ModelPricing:
        try:
            return self.pricing[(provider, model)]
        except KeyError as exc:
            raise UnknownPricingError(
                f"No pricing configured for provider={provider!r}, model={model!r}"
            ) from exc

    def estimate(
        self, provider: str, model: str, input_tokens: int, output_tokens: int
    ) -> Decimal:
        return self._price(provider, model).estimate(input_tokens, output_tokens)

    def reserve(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        now: Optional[datetime] = None,
    ) -> CostReservation:
        input_count = _tokens(input_tokens, "input_tokens")
        output_count = _tokens(output_tokens, "output_tokens")
        cost = self.estimate(provider, model, input_count, output_count)
        budget_date = self._date(now)
        with self._lock:
            state = self._days.setdefault(budget_date, _DayState())
            calls = state.reserved_calls + state.committed_calls
            total_cost = state.reserved_cost + state.committed_cost
            if calls + 1 > self.limits.max_calls:
                raise BudgetExceededError("Daily model call limit would be exceeded")
            if total_cost + cost > self.limits.max_cost:
                raise BudgetExceededError("Daily model cost limit would be exceeded")
            reservation = CostReservation(
                reservation_id=self._id_factory(),
                budget_date=budget_date,
                provider=provider,
                model=model,
                input_tokens=input_count,
                output_tokens=output_count,
                estimated_cost=cost,
            )
            if reservation.reservation_id in self._reservations or (
                reservation.reservation_id in self._committed
            ):
                raise CostError(
                    f"Duplicate reservation id: {reservation.reservation_id}"
                )
            self._reservations[reservation.reservation_id] = reservation
            state.reserved_calls += 1
            state.reserved_cost += cost
            return reservation

    def commit(
        self,
        reservation_id: str,
        *,
        actual_input_tokens: int,
        actual_output_tokens: int,
    ) -> CommittedUsage:
        input_count = _tokens(actual_input_tokens, "actual_input_tokens")
        output_count = _tokens(actual_output_tokens, "actual_output_tokens")
        with self._lock:
            try:
                reservation = self._reservations[reservation_id]
            except KeyError as exc:
                if reservation_id in self._committed:
                    raise CostError("Reservation is already committed") from exc
                raise CostError(
                    f"Unknown active reservation: {reservation_id}"
                ) from exc
            if input_count > reservation.input_tokens:
                raise CostError("actual_input_tokens exceeds the reserved upper bound")
            if output_count > reservation.output_tokens:
                raise CostError("actual_output_tokens exceeds the reserved upper bound")
            actual_cost = self.estimate(
                reservation.provider, reservation.model, input_count, output_count
            )
            del self._reservations[reservation_id]
            state = self._days[reservation.budget_date]
            state.reserved_calls -= 1
            state.reserved_cost -= reservation.estimated_cost
            state.committed_calls += 1
            state.committed_cost += actual_cost
            usage = CommittedUsage(
                reservation_id=reservation.reservation_id,
                budget_date=reservation.budget_date,
                provider=reservation.provider,
                model=reservation.model,
                input_tokens=input_count,
                output_tokens=output_count,
                actual_cost=actual_cost,
            )
            self._committed[reservation_id] = usage
            return usage

    def refund(self, reservation_id: str) -> CostReservation:
        with self._lock:
            try:
                reservation = self._reservations.pop(reservation_id)
            except KeyError as exc:
                if reservation_id in self._committed:
                    raise CostError(
                        "Committed usage cannot be refunded as a reservation"
                    ) from exc
                raise CostError(
                    f"Unknown active reservation: {reservation_id}"
                ) from exc
            state = self._days[reservation.budget_date]
            state.reserved_calls -= 1
            state.reserved_cost -= reservation.estimated_cost
            return reservation

    def has_active_reservation(self, reservation_id: str) -> bool:
        with self._lock:
            return reservation_id in self._reservations

    def snapshot(self, *, now: Optional[datetime] = None) -> DailyUsage:
        budget_date = self._date(now)
        with self._lock:
            state = self._days.get(budget_date, _DayState())
            return DailyUsage(
                budget_date=budget_date,
                calls=state.reserved_calls + state.committed_calls,
                reserved_calls=state.reserved_calls,
                committed_calls=state.committed_calls,
                total_cost=state.reserved_cost + state.committed_cost,
                reserved_cost=state.reserved_cost,
                committed_cost=state.committed_cost,
                max_calls=self.limits.max_calls,
                max_cost=self.limits.max_cost,
            )

    def record_zero_call_operation(
        self, operation: str, *, now: Optional[datetime] = None
    ) -> DailyUsage:
        if operation not in ZERO_COST_OPERATIONS:
            raise CostError(f"Unsupported zero-call operation: {operation!r}")
        return self.snapshot(now=now)

    def record_rule_screening(self, *, now: Optional[datetime] = None) -> DailyUsage:
        return self.record_zero_call_operation("rule_screening", now=now)

    def record_db_polling(self, *, now: Optional[datetime] = None) -> DailyUsage:
        return self.record_zero_call_operation("db_polling", now=now)


CostManager = DailyCostLedger
DailyBudget = DailyCostLedger
