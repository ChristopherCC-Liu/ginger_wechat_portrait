"""Structured reply planning and deterministic decision firewall."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Tuple


PERMANENT_MANUAL_RISKS = frozenset(
    {
        "money",
        "contract",
        "medical",
        "legal",
        "verification_code",
        "credentials",
        "privacy",
        "conflict",
        "major_relationship_decision",
    }
)
RISK_LEVELS = frozenset({"low"}) | PERMANENT_MANUAL_RISKS
GATE_MODES = frozenset({"observe", "shadow", "approve", "autopilot"})
GATE_ACTIONS = frozenset(
    {
        "observe",
        "no_reply",
        "draft_only",
        "approval_required",
        "manual_required",
        "autopilot_candidate",
    }
)

NO_REPLY_THRESHOLD = 0.70
AUTOPILOT_THRESHOLD = 0.92


class DecisionValidationError(ValueError):
    """Raised when a structured model decision violates its schema."""


def _strict_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _string_tuple(value: Any, field_name: str) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise DecisionValidationError(f"{field_name} must be an array of strings")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise DecisionValidationError(
                f"{field_name} must contain only non-empty strings"
            )
        result.append(item.strip())
    return tuple(result)


@dataclass(frozen=True)
class ReplyDecision:
    """The only model-produced object accepted by the decision firewall."""

    intent: str
    stance: str
    facts: Tuple[str, ...]
    commitments: Tuple[str, ...]
    risk: str
    confidence: float
    reply_required: bool
    context_sufficient: bool
    reasons: Tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "intent", _strict_string(self.intent, "intent"))
        object.__setattr__(self, "stance", _strict_string(self.stance, "stance"))
        object.__setattr__(self, "facts", _string_tuple(self.facts, "facts"))
        object.__setattr__(
            self, "commitments", _string_tuple(self.commitments, "commitments")
        )
        object.__setattr__(self, "reasons", _string_tuple(self.reasons, "reasons"))
        if not isinstance(self.risk, str) or self.risk not in RISK_LEVELS:
            raise DecisionValidationError(
                f"risk must be one of: {', '.join(sorted(RISK_LEVELS))}"
            )
        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise DecisionValidationError("confidence must be a number")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise DecisionValidationError("confidence must be between 0 and 1")
        object.__setattr__(self, "confidence", float(self.confidence))
        if type(self.reply_required) is not bool:
            raise DecisionValidationError("reply_required must be a boolean")
        if type(self.context_sufficient) is not bool:
            raise DecisionValidationError("context_sufficient must be a boolean")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ReplyDecision":
        if not isinstance(value, Mapping):
            raise DecisionValidationError("ReplyDecision must be a JSON object")
        expected = {
            "intent",
            "stance",
            "facts",
            "commitments",
            "risk",
            "confidence",
            "reply_required",
            "context_sufficient",
            "reasons",
        }
        actual = set(value)
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            details = []
            if missing:
                details.append(f"missing={missing}")
            if extra:
                details.append(f"extra={extra}")
            raise DecisionValidationError(
                "ReplyDecision fields do not match schema: " + ", ".join(details)
            )
        return cls(
            intent=value["intent"],
            stance=value["stance"],
            facts=value["facts"],
            commitments=value["commitments"],
            risk=value["risk"],
            confidence=value["confidence"],
            reply_required=value["reply_required"],
            context_sufficient=value["context_sufficient"],
            reasons=value["reasons"],
        )

    from_mapping = from_dict

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intent": self.intent,
            "stance": self.stance,
            "facts": list(self.facts),
            "commitments": list(self.commitments),
            "risk": self.risk,
            "confidence": self.confidence,
            "reply_required": self.reply_required,
            "context_sufficient": self.context_sufficient,
            "reasons": list(self.reasons),
        }


REPLY_DECISION_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "intent",
        "stance",
        "facts",
        "commitments",
        "risk",
        "confidence",
        "reply_required",
        "context_sufficient",
        "reasons",
    ],
    "properties": {
        "intent": {"type": "string", "minLength": 1},
        "stance": {"type": "string", "minLength": 1},
        "facts": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "commitments": {
            "type": "array",
            "items": {"type": "string", "minLength": 1},
        },
        "risk": {"type": "string", "enum": sorted(RISK_LEVELS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reply_required": {"type": "boolean"},
        "context_sufficient": {"type": "boolean"},
        "reasons": {"type": "array", "items": {"type": "string", "minLength": 1}},
    },
}


_RISK_TERMS: Dict[str, Tuple[str, ...]] = {
    "money": (
        "转账",
        "付款",
        "收款",
        "借钱",
        "还钱",
        "汇款",
        "打款",
        "银行卡",
        "红包",
        "多少钱",
        "bank transfer",
        "wire transfer",
        "payment",
        "loan",
    ),
    "contract": (
        "合同",
        "签约",
        "签字",
        "协议条款",
        "签协议",
        "contract",
        "sign the agreement",
    ),
    "medical": (
        "诊断",
        "处方",
        "吃药",
        "用药",
        "手术",
        "急诊",
        "怀孕",
        "医生",
        "医院",
        "治疗",
        "medical",
        "diagnosis",
        "prescription",
        "dosage",
    ),
    "legal": (
        "律师",
        "法院",
        "起诉",
        "报警",
        "仲裁",
        "赔偿",
        "法律",
        "警察",
        "legal advice",
        "lawsuit",
        "attorney",
    ),
    "verification_code": (
        "验证码",
        "短信码",
        "动态码",
        "一次性密码",
        "verification code",
        "one-time code",
        "otp",
        "2fa code",
        "login code",
    ),
    "credentials": (
        "密码",
        "口令",
        "api key",
        "密钥",
        "助记词",
        "私钥",
        "password",
        "credential",
        "secret key",
        "seed phrase",
        "登录账号",
        "access token",
    ),
    "privacy": (
        "身份证号",
        "住址",
        "家庭住址",
        "隐私",
        "聊天记录",
        "病历",
        "social security number",
        "home address",
        "private data",
        "medical record",
        "手机号码",
        "护照号码",
        "personal information",
    ),
    "conflict": (
        "吵架",
        "冲突",
        "威胁",
        "报复",
        "投诉你",
        "争执",
        "conflict",
        "threaten",
        "retaliate",
    ),
    "major_relationship_decision": (
        "分手",
        "离婚",
        "复合",
        "结婚",
        "绝交",
        "断绝关系",
        "break up",
        "divorce",
        "get married",
        "end our relationship",
    ),
}


def detect_sensitive_risks(text: str) -> Tuple[str, ...]:
    """Deterministically recall permanent-manual risks from untrusted text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    normalized = text.casefold()
    matched = []
    for category in sorted(PERMANENT_MANUAL_RISKS):
        terms = _RISK_TERMS[category]
        if any(term.casefold() in normalized for term in terms):
            matched.append(category)
    return tuple(matched)


@dataclass(frozen=True)
class RenderControls:
    tone: str = "neutral"
    length: str = "normal"
    delay_seconds: int = 0

    def __post_init__(self) -> None:
        if self.tone not in {"neutral", "warm", "calm", "direct"}:
            raise ValueError("Unsupported tone")
        if self.length not in {"short", "normal", "detailed"}:
            raise ValueError("Unsupported length")
        if isinstance(self.delay_seconds, bool) or not isinstance(
            self.delay_seconds, int
        ):
            raise ValueError("delay_seconds must be an integer")
        if not 0 <= self.delay_seconds <= 86_400:
            raise ValueError("delay_seconds must be between 0 and 86400")


def emotion_render_controls(
    emotion: Optional[Mapping[str, Any]],
    base: Optional[RenderControls] = None,
) -> RenderControls:
    """Translate emotion proxies into tone/length/delay only.

    Unknown keys, including mode, risk, confidence, and permission-like values,
    are deliberately ignored.
    """
    controls = base or RenderControls()
    if not emotion:
        return controls
    tension = emotion.get("tension", 0.0)
    activation = emotion.get("activation", 0.0)
    warmth = emotion.get("warmth", 0.0)
    try:
        tension_value = float(tension)
        activation_value = float(activation)
        warmth_value = float(warmth)
    except (TypeError, ValueError):
        return controls

    tone = controls.tone
    length = controls.length
    delay = controls.delay_seconds
    if tension_value >= 0.7 or activation_value >= 0.8:
        tone = "calm"
        length = "short"
        delay = max(delay, 900)
    elif warmth_value >= 0.7:
        tone = "warm"
    return RenderControls(tone=tone, length=length, delay_seconds=delay)


@dataclass(frozen=True)
class GateResult:
    mode: str
    action: str
    autopilot_candidate: bool
    manual_required: bool
    detected_risks: Tuple[str, ...]
    render_controls: RenderControls
    reasons: Tuple[str, ...]

    def __post_init__(self) -> None:
        if self.mode not in GATE_MODES:
            raise ValueError(f"Unsupported gate mode: {self.mode!r}")
        if self.action not in GATE_ACTIONS:
            raise ValueError(f"Unsupported gate action: {self.action!r}")
        if self.autopilot_candidate and self.action != "autopilot_candidate":
            raise ValueError("autopilot_candidate conflicts with action")


def evaluate_gate(
    decision: ReplyDecision,
    *,
    message_text: str = "",
    mode: str = "shadow",
    allowlisted: bool = False,
    cost_allowed: bool = True,
    frequency_allowed: bool = True,
    emotion: Optional[Mapping[str, Any]] = None,
) -> GateResult:
    """Apply the deterministic firewall after a ReplyDecision has been parsed."""
    if not isinstance(decision, ReplyDecision):
        raise TypeError("decision must be a ReplyDecision")
    if mode not in GATE_MODES:
        raise ValueError(f"Unsupported gate mode: {mode!r}")
    for name, value in (
        ("allowlisted", allowlisted),
        ("cost_allowed", cost_allowed),
        ("frequency_allowed", frequency_allowed),
    ):
        if type(value) is not bool:
            raise TypeError(f"{name} must be a boolean")

    # Message content is untrusted data.  It may add risk, never mode or authority.
    detected = set(detect_sensitive_risks(message_text))
    if decision.risk != "low":
        detected.add(decision.risk)
    risks = tuple(sorted(detected))
    controls = emotion_render_controls(emotion)
    reasons = list(decision.reasons)

    if risks:
        reasons.append("permanent_manual_risk")
        return GateResult(
            mode=mode,
            action="manual_required",
            autopilot_candidate=False,
            manual_required=True,
            detected_risks=risks,
            render_controls=controls,
            reasons=tuple(reasons),
        )
    if decision.commitments:
        reasons.append("commitments_require_human")
        return GateResult(
            mode=mode,
            action="manual_required",
            autopilot_candidate=False,
            manual_required=True,
            detected_risks=(),
            render_controls=controls,
            reasons=tuple(reasons),
        )
    if not decision.context_sufficient:
        reasons.append("context_insufficient")
        return GateResult(
            mode=mode,
            action="manual_required",
            autopilot_candidate=False,
            manual_required=True,
            detected_risks=(),
            render_controls=controls,
            reasons=tuple(reasons),
        )
    if not decision.reply_required:
        reasons.append("reply_not_required")
        return GateResult(
            mode=mode,
            action="no_reply",
            autopilot_candidate=False,
            manual_required=False,
            detected_risks=(),
            render_controls=controls,
            reasons=tuple(reasons),
        )
    if decision.confidence < NO_REPLY_THRESHOLD:
        reasons.append("confidence_below_no_reply_threshold")
        return GateResult(
            mode=mode,
            action="no_reply",
            autopilot_candidate=False,
            manual_required=False,
            detected_risks=(),
            render_controls=controls,
            reasons=tuple(reasons),
        )

    eligible = (
        decision.confidence >= AUTOPILOT_THRESHOLD
        and allowlisted
        and cost_allowed
        and frequency_allowed
    )
    if not eligible:
        if decision.confidence < AUTOPILOT_THRESHOLD:
            reasons.append("confidence_in_draft_band")
        if not allowlisted:
            reasons.append("not_allowlisted")
        if not cost_allowed:
            reasons.append("cost_limit")
        if not frequency_allowed:
            reasons.append("frequency_limit")
        action = "observe" if mode == "observe" else "draft_only"
        return GateResult(
            mode=mode,
            action=action,
            autopilot_candidate=False,
            manual_required=False,
            detected_risks=(),
            render_controls=controls,
            reasons=tuple(reasons),
        )

    if mode == "observe":
        action = "observe"
    elif mode == "shadow":
        action = "draft_only"
    elif mode == "approve":
        action = "approval_required"
    else:
        action = "autopilot_candidate"
    return GateResult(
        mode=mode,
        action=action,
        autopilot_candidate=action == "autopilot_candidate",
        manual_required=action == "approval_required",
        detected_risks=(),
        render_controls=controls,
        reasons=tuple(reasons),
    )


gate_reply = evaluate_gate


def render_reply(
    decision: ReplyDecision,
    *,
    controls: Optional[RenderControls] = None,
    renderer: Optional[Callable[[ReplyDecision, RenderControls], str]] = None,
) -> str:
    """Render only an already-validated decision; this function never sends it."""
    if not isinstance(decision, ReplyDecision):
        raise TypeError("decision must be a ReplyDecision")
    selected = controls or RenderControls()
    if renderer is not None:
        rendered = renderer(decision, selected)
        if not isinstance(rendered, str) or not rendered.strip():
            raise ValueError("renderer must return non-empty text")
        return rendered.strip()

    pieces = [decision.stance]
    pieces.extend(decision.facts)
    if selected.length == "short":
        pieces = pieces[:1]
    elif selected.length == "normal":
        pieces = pieces[:3]
    return " ".join(piece.strip() for piece in pieces if piece.strip())
