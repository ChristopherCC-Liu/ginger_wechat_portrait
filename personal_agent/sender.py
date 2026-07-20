"""Isolated macOS sender ports with fail-closed recipient/body verification."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol


CONTACT_KEY_RE = re.compile(r"^contact_[0-9a-f]{16,64}$")
MAX_BODY_CHARACTERS = 20_000
MAX_CONTACT_CHARACTERS = 256


def send_attempt_id(
    draft_id: str,
    event_id: str,
    contact_key: str,
    body: str,
) -> str:
    """Derive the stable id needed to authorize exactly one draft click."""
    values = (draft_id, event_id, contact_key, body)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("send attempt identity fields must be non-empty strings")
    if not CONTACT_KEY_RE.fullmatch(contact_key):
        raise ValueError("contact_key must be a pseudonymous contact_ key")
    if len(draft_id) > 160 or len(event_id) > 512 or len(body) > MAX_BODY_CHARACTERS:
        raise ValueError("send attempt identity field is too long")
    encoded = json.dumps(
        values,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"send_{hashlib.sha256(encoded).hexdigest()[:40]}"


class SenderError(RuntimeError):
    """Base class for sender failures."""


class UIAutomationUnavailable(SenderError):
    """Accessibility is unavailable or denied."""


class UIDriftDetected(SenderError):
    """Expected recipient/editor elements did not match the current UI."""


class UIStateUncertain(SenderError):
    """The composer may have changed; automatic fallback or retry is forbidden."""


class CanaryRequired(SenderError):
    """A real click was requested without a separately approved canary."""


class SecretReader(Protocol):
    def get_secret(self, name: str) -> bytes:
        """Return a secret by Keychain-style account name."""

    def delete_secret(self, name: str) -> None:
        """Delete one secret so a canary cannot be replayed."""


@dataclass(frozen=True)
class SendRequest:
    attempt_id: str
    contact_key: str
    contact_label: str
    body: str
    search_token: Optional[str] = None
    action: str = "dry_run"

    def __post_init__(self) -> None:
        if not self.attempt_id or len(self.attempt_id) > 160:
            raise ValueError("attempt_id is required and must be <= 160 characters")
        if not CONTACT_KEY_RE.fullmatch(self.contact_key):
            raise ValueError("contact_key must be a pseudonymous contact_ key")
        if not self.contact_label or len(self.contact_label) > MAX_CONTACT_CHARACTERS:
            raise ValueError("contact_label is required and is too long")
        if any(character in self.contact_label for character in "\r\n\x00"):
            raise ValueError("contact_label contains a forbidden control character")
        if self.action != "dry_run":
            if (
                not isinstance(self.search_token, str)
                or not self.search_token.strip()
                or len(self.search_token) > MAX_CONTACT_CHARACTERS
            ):
                raise ValueError("non-dry-run requests require a bounded search_token")
            if any(character in self.search_token for character in "\r\n\x00"):
                raise ValueError("search_token contains a forbidden control character")
        if not self.body.strip() or len(self.body) > MAX_BODY_CHARACTERS:
            raise ValueError("body is empty or too long")
        if "\x00" in self.body:
            raise ValueError("body contains a NUL character")
        if self.action not in {"dry_run", "typing_only", "click_send"}:
            raise ValueError("action must be dry_run, typing_only, or click_send")

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SendResult:
    attempt_id: str
    backend: str
    action: str
    recipient_verified: bool
    body_verified: bool
    clicked: bool
    detail: str


class Sender(Protocol):
    def execute(self, request: SendRequest) -> SendResult:
        """Execute one already-gated send request."""


class CanaryGuard:
    """Consume an attempt-bound Keychain token before a Return-key click."""

    def __init__(self, secrets: SecretReader, account: str) -> None:
        self._secrets = secrets
        self._account = account

    def _validate(self, request: SendRequest) -> str:
        account = f"{self._account}:{request.attempt_id}"
        try:
            raw = self._secrets.get_secret(account)
        except (KeyError, OSError, RuntimeError) as exc:
            raise CanaryRequired("real-send canary is absent") from exc
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CanaryRequired("real-send canary is invalid") from exc
        expected = {
            "schema": "ginger_one_time_canary_v1",
            "attempt_id": request.attempt_id,
            "contact_key": request.contact_key,
            "body_sha256": request.body_sha256,
        }
        if not isinstance(value, dict) or any(
            value.get(key) != expected_value for key, expected_value in expected.items()
        ):
            raise CanaryRequired("real-send canary is invalid")
        expires_at = value.get("expires_at_epoch")
        now = time.time()
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, (int, float))
            or not now < float(expires_at) <= now + 600
        ):
            raise CanaryRequired("real-send canary is expired or too long-lived")
        return account

    def is_authorized(self, request: SendRequest) -> bool:
        """Check action-point authorization without consuming it or touching UI."""
        try:
            self._validate(request)
        except CanaryRequired:
            return False
        return True

    def consume(self, request: SendRequest) -> None:
        account = self._validate(request)
        self._secrets.delete_secret(account)


class DryRunSender:
    def execute(self, request: SendRequest) -> SendResult:
        return SendResult(
            attempt_id=request.attempt_id,
            backend="dry_run",
            action="dry_run",
            recipient_verified=False,
            body_verified=False,
            clicked=False,
            detail="No UI action was performed",
        )


def _apple_string(value: str) -> str:
    """Encode the bounded contact label as an AppleScript string literal."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _accessibility_script(contact_label: str, search_token: str, click: bool) -> str:
    click_block = (
        'key code 36\nreturn "GINGER_CLICKED"'
        if click
        else 'return "GINGER_TYPING_ONLY_OK"'
    )
    return f"""
set targetContact to {_apple_string(contact_label)}
set targetSearchToken to {_apple_string(search_token)}
set messageBody to the clipboard as text
tell application "WeChat" to activate
delay 0.5
tell application "System Events"
    if UI elements enabled is false then error "GINGER_ACCESSIBILITY_DENIED"
    if not (exists process "WeChat") then error "GINGER_WECHAT_NOT_RUNNING"
    tell process "WeChat"
        set frontmost to true
        keystroke "f" using {{command down}}
        delay 0.3
        set the clipboard to targetSearchToken
        keystroke "v" using {{command down}}
        delay 0.8
        set searchMatchingLabels to 0
        try
            set searchTexts to value of every static text of entire contents of front window
            repeat with candidate in searchTexts
                try
                    if (candidate as text) is targetContact then set searchMatchingLabels to searchMatchingLabels + 1
                end try
            end repeat
        end try
        if searchMatchingLabels is not 1 then error "GINGER_SEARCH_RESULT_MISMATCH"
        key code 36
        delay 0.8
        set matchingLabels to 0
        try
            set visibleTexts to value of every static text of entire contents of front window
            repeat with candidate in visibleTexts
                try
                    if (candidate as text) is targetContact then set matchingLabels to matchingLabels + 1
                end try
            end repeat
        end try
        if matchingLabels is not 1 then error "GINGER_RECIPIENT_MISMATCH"
        set existingEditorValue to ""
        try
            set existingEditorValue to value of focused UI element as text
        end try
        if existingEditorValue is not "" then error "GINGER_COMPOSER_NOT_EMPTY"
        set the clipboard to messageBody
        keystroke "v" using {{command down}}
        delay 0.4
        set editorValue to ""
        try
            set editorValue to value of focused UI element as text
        end try
        if editorValue is not messageBody then error "GINGER_BODY_MISMATCH"
        {click_block}
    end tell
end tell
""".strip()


class MacOSAccessibilitySender:
    """Use deterministic Accessibility keystrokes; fail on any UI mismatch."""

    def __init__(
        self,
        *,
        canary: Optional[CanaryGuard] = None,
        timeout_seconds: int = 12,
        runner: Any = subprocess.run,
    ) -> None:
        self._canary = canary
        self._timeout = max(1, timeout_seconds)
        self._runner = runner

    def _clipboard(self, command: str, payload: Optional[bytes] = None) -> bytes:
        result = self._runner(
            [f"/usr/bin/{command}"],
            input=payload,
            capture_output=True,
            timeout=self._timeout,
            check=False,
        )
        if result.returncode != 0:
            raise UIAutomationUnavailable(f"{command} failed")
        return bytes(result.stdout or b"")

    def execute(self, request: SendRequest) -> SendResult:
        if request.action == "dry_run":
            return DryRunSender().execute(request)
        if platform.system() != "Darwin":
            raise UIAutomationUnavailable("Accessibility sender requires macOS")
        click = request.action == "click_send"
        if click:
            if self._canary is None:
                raise CanaryRequired("real-send canary guard is not configured")
            self._canary.consume(request)

        old_clipboard = self._clipboard("pbpaste")
        try:
            self._clipboard("pbcopy", request.body.encode("utf-8"))
            result = self._runner(
                ["/usr/bin/osascript", "-"],
                input=_accessibility_script(
                    request.contact_label,
                    request.search_token or "",
                    click,
                ).encode("utf-8"),
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise UIStateUncertain(
                "Accessibility sender timed out after UI mutation"
            ) from exc
        finally:
            try:
                self._clipboard("pbcopy", old_clipboard)
            except SenderError:
                pass

        output = bytes(result.stdout or b"").decode("utf-8", errors="replace").strip()
        error = bytes(result.stderr or b"").decode("utf-8", errors="replace")
        if result.returncode != 0:
            if "ACCESSIBILITY_DENIED" in error:
                raise UIAutomationUnavailable(
                    "macOS Accessibility permission is denied"
                )
            if click or "BODY_MISMATCH" in error or "COMPOSER_NOT_EMPTY" in error:
                raise UIStateUncertain(
                    "WeChat composer or send state is uncertain; retry is forbidden"
                )
            raise UIDriftDetected("WeChat recipient or editor verification failed")
        expected = "GINGER_CLICKED" if click else "GINGER_TYPING_ONLY_OK"
        if expected not in output:
            raise UIStateUncertain(
                "Accessibility helper returned no final marker; retry is forbidden"
            )
        return SendResult(
            attempt_id=request.attempt_id,
            backend="accessibility",
            action=request.action,
            recipient_verified=True,
            body_verified=True,
            clicked=click,
            detail=expected,
        )


class ComputerUseSender:
    """Narrow JSON-stdin adapter for an independently installed UI helper."""

    def __init__(
        self,
        helper: Path,
        *,
        canary: Optional[CanaryGuard] = None,
        timeout_seconds: int = 30,
        runner: Any = subprocess.run,
    ) -> None:
        self._helper = helper.expanduser().absolute()
        self._canary = canary
        self._timeout = max(1, timeout_seconds)
        self._runner = runner
        self._validate_helper()

    def _validate_helper(self) -> None:
        if not self._helper.is_absolute() or self._helper.is_symlink():
            raise ValueError("Computer Use helper must be an absolute regular file")
        metadata = self._helper.stat()
        if not stat.S_ISREG(metadata.st_mode) or not os.access(self._helper, os.X_OK):
            raise ValueError("Computer Use helper must be executable")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("Computer Use helper must be owned by the current user")
        if metadata.st_mode & 0o022:
            raise ValueError("Computer Use helper must not be group/world writable")

    def execute(self, request: SendRequest) -> SendResult:
        if request.action == "dry_run":
            return DryRunSender().execute(request)
        click = request.action == "click_send"
        if click:
            raise CanaryRequired(
                "Computer Use real sending is forbidden; use human-confirmed "
                "Accessibility canary execution"
            )
        payload = {
            "schema": "ginger_computer_use_request_v1",
            "attempt_id": request.attempt_id,
            "contact_key": request.contact_key,
            "contact_label": request.contact_label,
            "search_token": request.search_token,
            "body": request.body,
            "body_sha256": request.body_sha256,
            "action": request.action,
            "require_exact_recipient": True,
            "require_exact_body": True,
        }
        try:
            result = self._runner(
                [str(self._helper)],
                input=(json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"),
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            if click:
                raise UIStateUncertain(
                    "Computer Use helper timed out after a click-capable request"
                ) from exc
            raise UIDriftDetected("Computer Use helper timed out") from exc
        if result.returncode != 0:
            if click:
                raise UIStateUncertain(
                    "Computer Use helper failed after a click-capable request"
                )
            raise UIDriftDetected("Computer Use helper failed closed")
        try:
            response = json.loads(bytes(result.stdout).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UIDriftDetected("Computer Use helper returned invalid JSON") from exc
        if not isinstance(response, dict):
            raise UIDriftDetected("Computer Use helper returned an invalid result")
        verified = (
            response.get("attempt_id") == request.attempt_id
            and response.get("contact_key") == request.contact_key
            and response.get("body_sha256") == request.body_sha256
            and response.get("recipient_verified") is True
            and response.get("body_verified") is True
            and bool(response.get("clicked")) is click
        )
        if not verified:
            raise UIDriftDetected("Computer Use helper verification mismatch")
        return SendResult(
            attempt_id=request.attempt_id,
            backend="computer_use",
            action=request.action,
            recipient_verified=True,
            body_verified=True,
            clicked=click,
            detail="helper verification passed",
        )


class SenderRouter:
    """Try Accessibility first and use Computer Use only for detected UI drift."""

    def __init__(self, primary: Sender, fallback: Optional[Sender] = None) -> None:
        self._primary = primary
        self._fallback = fallback

    def execute(self, request: SendRequest) -> SendResult:
        try:
            return self._primary.execute(request)
        except UIDriftDetected:
            # A click-capable attempt may already have mutated the composer.  It
            # is never replayed through a second UI backend.
            if self._fallback is None or request.action == "click_send":
                raise
            return self._fallback.execute(request)
