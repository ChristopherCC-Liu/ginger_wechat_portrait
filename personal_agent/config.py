"""Validated runtime configuration and macOS application paths."""

from __future__ import annotations

import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

try:
    import tomllib
except ImportError as exc:  # pragma: no cover - Python 3.10 uses tomli fallback.
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        raise RuntimeError("Python 3.10 requires the tomli package") from exc


CONFIG_SCHEMA = 2
MAX_DAILY_MODEL_CALLS = 1_000
VALID_MODES = frozenset({"observe", "shadow", "approve", "autopilot"})
VALID_PROVIDERS = frozenset({"openai", "glm", "local"})
VALID_READER_BACKENDS = frozenset({"plaintext", "sqlcipher"})
VALID_SENDER_BACKENDS = frozenset({"accessibility", "computer_use"})
DEFAULT_APP_ROOT = Path.home() / "Library/Application Support/GingerAgent"
DEFAULT_CONFIG_PATH = DEFAULT_APP_ROOT / "config.toml"
_SECRET_FIELD = re.compile(r"(^|_)(api_?key|password|token|secret)($|_)", re.I)
_SECRET_VALUE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{16,}|[A-Fa-f0-9]{48,}|Bearer\s+[A-Za-z0-9._-]{12,})"
)
_KEYCHAIN_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _expanded_path(value: str | Path) -> Path:
    return Path(value).expanduser().absolute()


def _table(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, Mapping):
        raise ValueError(f"[{name}] must be a TOML table")
    return value


def _positive_int(value: Any, label: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum:
        raise ValueError(f"{label} must be >= {minimum}")
    return value


def _nonnegative_float(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{label} must be >= 0")
    return result


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _reject_embedded_secrets(value: Any, prefix: str = "") -> None:
    """Reject raw credentials while allowing explicit Keychain reference fields."""
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            qualified = f"{prefix}.{key_text}" if prefix else key_text
            if _SECRET_FIELD.search(key_text) and not key_text.endswith("_ref"):
                raise ValueError(
                    f"Raw secret field is forbidden in config: {qualified}; use a *_ref"
                )
            _reject_embedded_secrets(child, qualified)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_embedded_secrets(child, f"{prefix}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ValueError(f"Possible raw credential is forbidden in config: {prefix}")


@dataclass(frozen=True)
class AgentPaths:
    root: Path = DEFAULT_APP_ROOT

    @property
    def config(self) -> Path:
        return self.root / "config.toml"

    @property
    def ledger(self) -> Path:
        return self.root / "state" / "ledger.sqlite3"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def launch_agent(self) -> Path:
        return Path.home() / "Library/LaunchAgents/com.christophercc.ginger-agent.plist"

    @property
    def pause_marker(self) -> Path:
        return self.root / "PAUSED"

    @property
    def kill_switch(self) -> Path:
        return self.root / "KILL_SWITCH"


@dataclass(frozen=True)
class ReaderConfig:
    backend: str = "plaintext"
    db_dir: Optional[Path] = None
    sqlcipher_path: Path = Path("/opt/homebrew/bin/sqlcipher")
    keychain_db_key_prefix: str = "wechat-db-key"
    self_id_ref: str = "wechat-self-id"
    overlap_seconds: int = 300
    batch_size: int = 500
    bootstrap_lookback_seconds: int = 86_400


@dataclass(frozen=True)
class ModelConfig:
    provider: str = "local"
    model: str = ""
    base_url: str = "http://127.0.0.1:11434/v1"
    api_key_ref: Optional[str] = None
    timeout_seconds: int = 30
    max_response_bytes: int = 1_000_000
    max_request_bytes: int = 524_288
    max_output_tokens: int = 900
    context_messages: int = 12


@dataclass(frozen=True)
class CostConfig:
    daily_usd_limit: float = 1.0
    daily_call_limit: int = 20
    per_contact_hourly_limit: int = 3
    model_prices_per_million_tokens: Dict[str, Dict[str, float]] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class LearningConfig:
    enabled: bool = True
    refresh_interval_seconds: int = 86_400
    minimum_corrections: int = 3
    auto_activate_safe: bool = True


@dataclass(frozen=True)
class SenderConfig:
    backend: str = "accessibility"
    fallback_backend: Optional[str] = None
    computer_use_helper: Optional[Path] = None
    typing_only: bool = True
    real_send_enabled: bool = False
    canary_ref: str = "real-send-canary"
    ui_timeout_seconds: int = 12


@dataclass(frozen=True)
class AgentConfig:
    schema_version: int = CONFIG_SCHEMA
    mode: str = "shadow"
    timezone: str = "Asia/Shanghai"
    poll_interval_seconds: int = 30
    identity_key_ref: str = "identity-key"
    state_key_ref: str = "state-key"
    allowlist: frozenset[str] = frozenset()
    paths: AgentPaths = field(default_factory=AgentPaths)
    reader: ReaderConfig = field(default_factory=ReaderConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    cost: CostConfig = field(default_factory=CostConfig)
    learning: LearningConfig = field(default_factory=LearningConfig)
    sender: SenderConfig = field(default_factory=SenderConfig)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AgentConfig":
        _reject_embedded_secrets(data)
        schema_version = _positive_int(
            data.get("schema_version", CONFIG_SCHEMA), "schema_version"
        )
        if schema_version != CONFIG_SCHEMA:
            raise ValueError(
                f"Unsupported config schema {schema_version}; expected {CONFIG_SCHEMA}"
            )
        mode = str(data.get("mode", "shadow")).strip().lower()
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(VALID_MODES))}")

        root_value = data.get("state_root", str(DEFAULT_APP_ROOT))
        if not isinstance(root_value, (str, Path)):
            raise ValueError("state_root must be a path string")
        paths = AgentPaths(_expanded_path(root_value))

        reader_data = _table(data, "reader")
        reader_backend = str(reader_data.get("backend", "plaintext")).lower()
        if reader_backend not in VALID_READER_BACKENDS:
            raise ValueError("reader.backend must be plaintext or sqlcipher")
        db_value = reader_data.get("db_dir")
        db_dir = (
            _expanded_path(db_value) if isinstance(db_value, str) and db_value else None
        )
        reader = ReaderConfig(
            backend=reader_backend,
            db_dir=db_dir,
            sqlcipher_path=_expanded_path(
                str(reader_data.get("sqlcipher_path", "/opt/homebrew/bin/sqlcipher"))
            ),
            keychain_db_key_prefix=str(
                reader_data.get("keychain_db_key_prefix", "wechat-db-key")
            ),
            self_id_ref=str(reader_data.get("self_id_ref", "wechat-self-id")),
            overlap_seconds=_positive_int(
                reader_data.get("overlap_seconds", 300), "reader.overlap_seconds", 0
            ),
            batch_size=_positive_int(
                reader_data.get("batch_size", 500), "reader.batch_size"
            ),
            bootstrap_lookback_seconds=_positive_int(
                reader_data.get("bootstrap_lookback_seconds", 86_400),
                "reader.bootstrap_lookback_seconds",
                0,
            ),
        )

        model_data = _table(data, "model")
        provider = str(model_data.get("provider", "local")).lower()
        if provider not in VALID_PROVIDERS:
            raise ValueError("model.provider must be openai, glm, or local")
        api_key_ref = model_data.get("api_key_ref")
        if api_key_ref is not None and not isinstance(api_key_ref, str):
            raise ValueError("model.api_key_ref must be a Keychain account name")
        if api_key_ref == "":
            api_key_ref = None
        model = ModelConfig(
            provider=provider,
            model=str(model_data.get("model", "")),
            base_url=str(
                model_data.get("base_url", "http://127.0.0.1:11434/v1")
            ).rstrip("/"),
            api_key_ref=api_key_ref,
            timeout_seconds=_positive_int(
                model_data.get("timeout_seconds", 30), "model.timeout_seconds"
            ),
            max_response_bytes=_positive_int(
                model_data.get("max_response_bytes", 1_000_000),
                "model.max_response_bytes",
            ),
            max_request_bytes=_positive_int(
                model_data.get("max_request_bytes", 524_288),
                "model.max_request_bytes",
            ),
            max_output_tokens=_positive_int(
                model_data.get("max_output_tokens", 900),
                "model.max_output_tokens",
            ),
            context_messages=_positive_int(
                model_data.get("context_messages", 12),
                "model.context_messages",
            ),
        )

        cost_data = _table(data, "cost")
        raw_prices = cost_data.get("model_prices_per_million_tokens", {})
        if not isinstance(raw_prices, Mapping):
            raise ValueError("cost.model_prices_per_million_tokens must be a table")
        prices: Dict[str, Dict[str, float]] = {}
        for model_name, price in raw_prices.items():
            if not isinstance(price, Mapping):
                raise ValueError(f"Cost price for {model_name} must be a table")
            prices[str(model_name)] = {
                "input": _nonnegative_float(price.get("input", 0), "input price"),
                "output": _nonnegative_float(price.get("output", 0), "output price"),
            }
        cost = CostConfig(
            daily_usd_limit=_nonnegative_float(
                cost_data.get("daily_usd_limit", 1.0), "cost.daily_usd_limit"
            ),
            daily_call_limit=_positive_int(
                cost_data.get("daily_call_limit", 20), "cost.daily_call_limit"
            ),
            per_contact_hourly_limit=_positive_int(
                cost_data.get("per_contact_hourly_limit", 3),
                "cost.per_contact_hourly_limit",
            ),
            model_prices_per_million_tokens=prices,
        )
        if cost.daily_call_limit > MAX_DAILY_MODEL_CALLS:
            raise ValueError(
                "cost.daily_call_limit must be <= "
                f"{MAX_DAILY_MODEL_CALLS} so the persistent budget journal "
                "cannot truncate same-day usage"
            )

        learning_data = _table(data, "learning")
        learning = LearningConfig(
            enabled=_boolean(learning_data.get("enabled", True), "learning.enabled"),
            refresh_interval_seconds=_positive_int(
                learning_data.get("refresh_interval_seconds", 86_400),
                "learning.refresh_interval_seconds",
                300,
            ),
            minimum_corrections=_positive_int(
                learning_data.get("minimum_corrections", 3),
                "learning.minimum_corrections",
            ),
            auto_activate_safe=_boolean(
                learning_data.get("auto_activate_safe", True),
                "learning.auto_activate_safe",
            ),
        )

        sender_data = _table(data, "sender")
        sender_backend = str(sender_data.get("backend", "accessibility")).lower()
        fallback_value = sender_data.get("fallback_backend")
        fallback = str(fallback_value).lower() if fallback_value else None
        for label, value in (
            ("backend", sender_backend),
            ("fallback_backend", fallback),
        ):
            if value is not None and value not in VALID_SENDER_BACKENDS:
                raise ValueError(f"sender.{label} has unsupported value: {value}")
        helper_value = sender_data.get("computer_use_helper")
        helper = (
            _expanded_path(helper_value)
            if isinstance(helper_value, str) and helper_value
            else None
        )
        sender = SenderConfig(
            backend=sender_backend,
            fallback_backend=fallback,
            computer_use_helper=helper,
            typing_only=_boolean(
                sender_data.get("typing_only", True), "sender.typing_only"
            ),
            real_send_enabled=_boolean(
                sender_data.get("real_send_enabled", False),
                "sender.real_send_enabled",
            ),
            canary_ref=str(sender_data.get("canary_ref", "real-send-canary")),
            ui_timeout_seconds=_positive_int(
                sender_data.get("ui_timeout_seconds", 12),
                "sender.ui_timeout_seconds",
            ),
        )

        allowlist_value = data.get("allowlist", [])
        if not isinstance(allowlist_value, list) or not all(
            isinstance(item, str) and item.startswith("contact_")
            for item in allowlist_value
        ):
            raise ValueError("allowlist must contain only hashed contact_ keys")

        config = cls(
            schema_version=schema_version,
            mode=mode,
            timezone=str(data.get("timezone", "Asia/Shanghai")),
            poll_interval_seconds=_positive_int(
                data.get("poll_interval_seconds", 30), "poll_interval_seconds", 5
            ),
            identity_key_ref=str(data.get("identity_key_ref", "identity-key")),
            state_key_ref=str(data.get("state_key_ref", "state-key")),
            allowlist=frozenset(allowlist_value),
            paths=paths,
            reader=reader,
            model=model,
            cost=cost,
            learning=learning,
            sender=sender,
        )
        config.validate_safety()
        return config

    def validate_safety(self) -> None:
        keychain_references = (
            ("identity_key_ref", self.identity_key_ref),
            ("state_key_ref", self.state_key_ref),
            ("reader.keychain_db_key_prefix", self.reader.keychain_db_key_prefix),
            ("reader.self_id_ref", self.reader.self_id_ref),
            ("sender.canary_ref", self.sender.canary_ref),
        )
        if self.model.api_key_ref is not None:
            keychain_references += (("model.api_key_ref", self.model.api_key_ref),)
        for label, value in keychain_references:
            if not isinstance(value, str) or _KEYCHAIN_REF.fullmatch(value) is None:
                raise ValueError(f"{label} must be a bounded Keychain account name")
        if self.mode != "autopilot" and self.sender.real_send_enabled:
            raise ValueError("real_send_enabled is only valid in autopilot mode")
        if self.sender.real_send_enabled and self.sender.typing_only:
            raise ValueError("real_send_enabled and typing_only cannot both be true")
        if self.sender.real_send_enabled and not self.allowlist:
            raise ValueError("real sending requires a non-empty hashed allowlist")
        if self.sender.real_send_enabled and self.sender.backend != "accessibility":
            raise ValueError(
                "real sending requires Accessibility as the primary backend"
            )
        if (
            self.reader.backend == "sqlcipher"
            and not self.reader.sqlcipher_path.is_absolute()
        ):
            raise ValueError("reader.sqlcipher_path must be absolute")


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AgentConfig:
    resolved = _expanded_path(path)
    if resolved.is_symlink():
        raise ValueError(f"Refusing symbolic-link config: {resolved}")
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Config is not a regular file: {resolved}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError(f"Config is not owned by the current user: {resolved}")
    if metadata.st_mode & 0o077:
        raise ValueError(f"Config permissions must be 0600: {resolved}")
    with resolved.open("rb") as handle:
        raw = tomllib.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("Config root must be a TOML table")
    return AgentConfig.from_mapping(raw)
