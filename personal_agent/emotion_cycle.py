"""Transparent, non-clinical language-emotion proxy metrics."""

from __future__ import annotations

import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Sequence

from .schema import MessageEvent


POSITIVE = (
    "开心",
    "高兴",
    "快乐",
    "喜欢",
    "爱",
    "棒",
    "不错",
    "满意",
    "幸福",
    "兴奋",
    "哈哈",
    "嘿嘿",
    "谢谢",
    "❤️",
    "❤",
    "😊",
    "😄",
    "🥰",
)
NEGATIVE = (
    "难过",
    "伤心",
    "生气",
    "烦",
    "焦虑",
    "担心",
    "害怕",
    "失望",
    "委屈",
    "崩溃",
    "累死",
    "痛苦",
    "烦死",
    "😢",
    "😭",
    "😡",
    "😞",
)
ACTIVATION = ("马上", "立刻", "赶紧", "急", "冲", "太", "真的", "一定", "必须", "快点")
TENSION = (
    "压力",
    "焦虑",
    "担心",
    "害怕",
    "生气",
    "烦",
    "崩溃",
    "失眠",
    "糟糕",
    "受不了",
    "来不及",
)
WARMTH = (
    "谢谢",
    "辛苦",
    "想你",
    "爱你",
    "抱抱",
    "晚安",
    "早安",
    "保重",
    "注意安全",
    "哈哈",
    "❤️",
    "❤",
    "🥰",
    "😘",
)
UNCERTAINTY = (
    "可能",
    "也许",
    "大概",
    "应该",
    "或许",
    "不确定",
    "不知道",
    "说不准",
    "看情况",
    "再说",
)
METRIC_NAMES = (
    "valence",
    "activation",
    "tension",
    "warmth",
    "uncertainty",
    "late_night_share",
)
WEEKDAYS = ("周一", "周二", "周三", "周四", "周五", "周六", "周日")


def _term_count(text: str, terms: Sequence[str]) -> int:
    return sum(text.count(term) for term in terms)


def _message_metrics(text: str, hour: int) -> Dict[str, float]:
    positive = _term_count(text, POSITIVE)
    negative = _term_count(text, NEGATIVE)
    activation_words = _term_count(text, ACTIVATION)
    tension_words = _term_count(text, TENSION)
    warmth_words = _term_count(text, WARMTH)
    uncertainty_words = _term_count(text, UNCERTAINTY)
    emotion_total = positive + negative
    punctuation_energy = min(3, text.count("!") + text.count("！"))
    repeated_punctuation = int(
        "!!" in text or "！！" in text or "??" in text or "？？" in text
    )
    return {
        "valence": (positive - negative) / max(1, emotion_total),
        "activation": min(
            1.0,
            activation_words * 0.25
            + punctuation_energy * 0.12
            + repeated_punctuation * 0.18,
        ),
        "tension": min(1.0, (negative + tension_words) * 0.28),
        "warmth": min(1.0, warmth_words * 0.3),
        "uncertainty": min(1.0, uncertainty_words * 0.3),
        "late_night_share": 1.0 if 0 <= hour < 5 else 0.0,
        "has_signal": float(
            positive
            + negative
            + activation_words
            + tension_words
            + warmth_words
            + uncertainty_words
            > 0
        ),
    }


def _mean(rows: Iterable[Dict[str, float]], key: str) -> float:
    values = [row[key] for row in rows]
    return sum(values) / len(values) if values else 0.0


def _confidence(message_count: int, character_count: int, signal_count: int) -> float:
    volume = min(1.0, message_count / 20.0)
    text_volume = min(1.0, character_count / 240.0)
    signal_coverage = min(1.0, signal_count / max(1.0, message_count / 3.0))
    return round(0.55 * volume + 0.25 * text_volume + 0.20 * signal_coverage, 4)


def _confidence_label(value: float) -> str:
    if value >= 0.75:
        return "high"
    if value >= 0.45:
        return "medium"
    return "low"


def _robust_z(current: float, history: List[float]) -> Any:
    if len(history) < 7:
        return None
    center = statistics.median(history)
    deviations = [abs(value - center) for value in history]
    mad = statistics.median(deviations)
    scale = 1.4826 * mad
    if scale < 0.03:
        return None
    return round(max(-5.0, min(5.0, (current - center) / scale)), 3)


def _is_text(event: MessageEvent) -> bool:
    return event.message_type.lower() in {"1", "text"} and bool(event.text.strip())


def calculate_emotion_cycle(
    events: Sequence[MessageEvent],
    baseline_days: int = 28,
    min_messages_per_day: int = 5,
    min_characters_per_day: int = 40,
    min_confidence_for_trend: float = 0.45,
) -> Dict[str, Any]:
    """Calculate descriptive proxies from the user's own text messages only."""
    outbound = [
        event for event in events if event.direction == "outbound" and _is_text(event)
    ]
    by_date: Dict[str, List[MessageEvent]] = defaultdict(list)
    message_scores: List[Dict[str, Any]] = []

    for event in outbound:
        occurred = datetime.fromisoformat(event.occurred_at)
        by_date[occurred.date().isoformat()].append(event)
        message_scores.append(
            {
                "date": occurred.date().isoformat(),
                "hour": occurred.hour,
                "metrics": _message_metrics(event.text, occurred.hour),
            }
        )

    daily: List[Dict[str, Any]] = []
    for date_key in sorted(by_date):
        day_events = by_date[date_key]
        scores = [
            _message_metrics(event.text, datetime.fromisoformat(event.occurred_at).hour)
            for event in day_events
        ]
        character_count = sum(len(event.text) for event in day_events)
        signal_count = sum(int(score["has_signal"]) for score in scores)
        confidence = _confidence(len(day_events), character_count, signal_count)
        metrics = {name: round(_mean(scores, name), 4) for name in METRIC_NAMES}
        daily.append(
            {
                "date": date_key,
                "weekday": WEEKDAYS[datetime.fromisoformat(date_key).weekday()],
                "message_count": len(day_events),
                "character_count": character_count,
                "signal_message_count": signal_count,
                "confidence": confidence,
                "confidence_label": _confidence_label(confidence),
                "valid_for_trend": (
                    len(day_events) >= min_messages_per_day
                    and character_count >= min_characters_per_day
                    and confidence >= min_confidence_for_trend
                ),
                "metrics": metrics,
                "baseline_z": {},
                "anomaly_flags": [],
            }
        )

    history_window = deque()
    for current in daily:
        current_date = datetime.fromisoformat(current["date"]).date()
        earliest = current_date - timedelta(days=baseline_days)
        while history_window and history_window[0][0] < earliest:
            history_window.popleft()
        if not current["valid_for_trend"]:
            current["baseline_z"] = {metric: None for metric in METRIC_NAMES}
            continue
        history_rows = [row for _, row in history_window]
        for metric in METRIC_NAMES:
            z_score = _robust_z(
                current["metrics"][metric],
                [row["metrics"][metric] for row in history_rows],
            )
            current["baseline_z"][metric] = z_score
            if z_score is not None and abs(z_score) >= 2.5:
                current["anomaly_flags"].append(
                    {
                        "metric": metric,
                        "direction": "high" if z_score > 0 else "low",
                        "z": z_score,
                    }
                )
        history_window.append((current_date, current))

    weekday_cycle = []
    for weekday in WEEKDAYS:
        rows = [
            row for row in daily if row["weekday"] == weekday and row["valid_for_trend"]
        ]
        if not rows:
            continue
        weekday_cycle.append(
            {
                "weekday": weekday,
                "valid_day_count": len(rows),
                "confidence": round(
                    sum(row["confidence"] for row in rows) / len(rows), 4
                ),
                "metrics": {
                    name: round(
                        sum(row["metrics"][name] for row in rows) / len(rows), 4
                    )
                    for name in METRIC_NAMES
                },
            }
        )

    hourly_cycle = []
    for hour in range(24):
        rows = [row["metrics"] for row in message_scores if row["hour"] == hour]
        if not rows:
            continue
        hourly_cycle.append(
            {
                "hour": hour,
                "message_count": len(rows),
                "message_share": round(len(rows) / max(1, len(message_scores)), 4),
                "metrics": {
                    name: round(_mean(rows, name), 4)
                    for name in (
                        "valence",
                        "activation",
                        "tension",
                        "warmth",
                        "uncertainty",
                    )
                },
            }
        )

    return {
        "schema": "ginger_language_emotion_cycle_v1",
        "scope": "outbound_text_only",
        "summary": {
            "first_date": daily[0]["date"] if daily else None,
            "last_date": daily[-1]["date"] if daily else None,
            "outbound_text_messages": len(outbound),
            "observed_days": len(daily),
            "valid_trend_days": sum(1 for row in daily if row["valid_for_trend"]),
        },
        "daily": daily,
        "weekday_cycle": weekday_cycle,
        "hourly_cycle": hourly_cycle,
        "methodology": {
            "baseline_days": baseline_days,
            "minimum_messages_per_day": min_messages_per_day,
            "minimum_characters_per_day": min_characters_per_day,
            "minimum_confidence_for_trend": min_confidence_for_trend,
            "anomaly_threshold": "absolute robust z >= 2.5 with at least 7 valid baseline days",
            "confidence": "weighted sample volume, text volume, and lexical-signal coverage",
            "limitations": [
                "These are language-use proxies, not a measurement of internal mood.",
                "No clinical, diagnostic, or treatment conclusion is permitted.",
                "Context, sarcasm, quoted text, and relationship-specific language can distort scores.",
                "Low-confidence days must not be used for trend or anomaly decisions.",
            ],
        },
    }
