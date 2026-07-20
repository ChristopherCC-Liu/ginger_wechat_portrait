"""Small cryptographic primitives and local secret-store adapters.

The module deliberately keeps the envelope format independent from SQLite so
encrypted values can be migrated without changing the ledger schema.
"""

from __future__ import annotations

import base64
import binascii
import json
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol, TypeAlias, cast

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:  # pragma: no cover - exercised only in broken installs
    raise RuntimeError("Personal Agent v2 requires the 'cryptography' package") from exc


AES_256_KEY_BYTES: Final = 32
GCM_NONCE_BYTES: Final = 12
GCM_TAG_BYTES: Final = 16
ENVELOPE_VERSION: Final = 1
ENVELOPE_ALGORITHM: Final = "AES-256-GCM"
MAX_ENVELOPE_BYTES: Final = 64 * 1024 * 1024
DEFAULT_SECRET_NAME: Final = "default"
_HEADER_AAD: Final = b"ginger-personal-agent:aes-gcm-envelope:v1\x00"

RunResult: TypeAlias = subprocess.CompletedProcess[bytes]
Runner: TypeAlias = Callable[..., RunResult]


class CryptoStoreError(RuntimeError):
    """Base error that intentionally carries no secret-bearing detail."""


class InvalidEnvelopeError(CryptoStoreError):
    """Raised for malformed, unsupported, or unauthentic envelopes."""


class SecretStoreError(CryptoStoreError):
    """Raised when a secret backend cannot complete an operation."""


class SecretNotFoundError(SecretStoreError):
    """Raised when a requested secret is absent."""


class SecretStore(Protocol):
    def get_secret(self, name: str = DEFAULT_SECRET_NAME) -> bytes:
        """Return one secret or raise ``SecretNotFoundError``."""

    def set_secret(self, name: str, secret: bytes) -> None:
        """Store one secret."""

    def delete_secret(self, name: str = DEFAULT_SECRET_NAME) -> None:
        """Delete one secret if present."""


def require_aes256_key(key: bytes | bytearray | memoryview) -> bytes:
    """Return an immutable AES-256 key after an exact-length check."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("AES-256 key must be bytes-like")
    normalized = bytes(key)
    if len(normalized) != AES_256_KEY_BYTES:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    return normalized


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise InvalidEnvelopeError("encrypted envelope is invalid")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise InvalidEnvelopeError("encrypted envelope is invalid") from exc


@dataclass(frozen=True)
class AESGCMEnvelope:
    """Versioned AES-256-GCM envelope codec.

    ``encrypt`` returns canonical UTF-8 JSON bytes. The authenticated data binds
    the envelope version and algorithm in addition to caller-provided context.
    """

    key: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", require_aes256_key(self.key))

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("associated data must be bytes")

        nonce = __import__("secrets").token_bytes(GCM_NONCE_BYTES)
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, _HEADER_AAD + aad)
        envelope = {
            "alg": ENVELOPE_ALGORITHM,
            "ct": _b64encode(ciphertext),
            "nonce": _b64encode(nonce),
            "v": ENVELOPE_VERSION,
        }
        return json.dumps(
            envelope,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    def decrypt(self, envelope: bytes, *, aad: bytes = b"") -> bytes:
        if not isinstance(envelope, bytes):
            raise TypeError("encrypted envelope must be bytes")
        if not isinstance(aad, bytes):
            raise TypeError("associated data must be bytes")
        if not envelope or len(envelope) > MAX_ENVELOPE_BYTES:
            raise InvalidEnvelopeError("encrypted envelope is invalid")

        try:
            decoded = json.loads(envelope.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidEnvelopeError("encrypted envelope is invalid") from exc
        if not isinstance(decoded, dict) or set(decoded) != {"alg", "ct", "nonce", "v"}:
            raise InvalidEnvelopeError("encrypted envelope is invalid")
        if decoded["v"] != ENVELOPE_VERSION or decoded["alg"] != ENVELOPE_ALGORITHM:
            raise InvalidEnvelopeError("encrypted envelope is unsupported")

        nonce = _b64decode(decoded["nonce"])
        ciphertext = _b64decode(decoded["ct"])
        if len(nonce) != GCM_NONCE_BYTES or len(ciphertext) < GCM_TAG_BYTES:
            raise InvalidEnvelopeError("encrypted envelope is invalid")
        try:
            return AESGCM(self.key).decrypt(
                nonce,
                ciphertext,
                _HEADER_AAD + aad,
            )
        except InvalidTag as exc:
            raise InvalidEnvelopeError(
                "encrypted envelope authentication failed"
            ) from exc


def encrypt_envelope(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """Encrypt bytes using the current versioned envelope format."""
    return AESGCMEnvelope(key).encrypt(plaintext, aad=aad)


def decrypt_envelope(key: bytes, envelope: bytes, *, aad: bytes = b"") -> bytes:
    """Decrypt bytes from the current versioned envelope format."""
    return AESGCMEnvelope(key).decrypt(envelope, aad=aad)


class MemorySecretStore:
    """In-memory secret backend intended for tests and ephemeral processes."""

    def __init__(
        self,
        initial: Mapping[str, bytes] | bytes | None = None,
    ) -> None:
        self._secrets: dict[str, bytes] = {}
        if isinstance(initial, bytes):
            self._secrets[DEFAULT_SECRET_NAME] = bytes(initial)
        elif initial is not None:
            for name, value in initial.items():
                self.set_secret(name, value)

    def set_secret(
        self,
        name: str | bytes,
        secret: bytes | None = None,
    ) -> None:
        """Store a named secret; ``set_secret(value)`` uses ``default``."""
        if secret is None:
            if not isinstance(name, bytes):
                raise TypeError("secret must be bytes")
            secret_name = DEFAULT_SECRET_NAME
            value = name
        else:
            if not isinstance(name, str) or not name:
                raise ValueError("secret name must be a non-empty string")
            secret_name = name
            value = secret
        if not isinstance(value, bytes):
            raise TypeError("secret must be bytes")
        self._secrets[secret_name] = bytes(value)

    def get_secret(self, name: str = DEFAULT_SECRET_NAME) -> bytes:
        if not isinstance(name, str) or not name:
            raise ValueError("secret name must be a non-empty string")
        try:
            return bytes(self._secrets[name])
        except KeyError as exc:
            raise SecretNotFoundError("secret was not found") from exc

    def delete_secret(self, name: str = DEFAULT_SECRET_NAME) -> None:
        self._secrets.pop(name, None)


class MacOSKeychain:
    """Minimal ``/usr/bin/security`` adapter with secret-safe subprocess use.

    Each logical name is stored as a separate generic-password account under
    ``service``. Values are base64 encoded so arbitrary secret bytes round-trip
    through the command-line tool. The encoded secret is supplied only on
    stdin; ``-w`` is deliberately the final argv element.
    """

    def __init__(
        self,
        service: str,
        *,
        account: str = DEFAULT_SECRET_NAME,
        timeout_seconds: float = 5.0,
        runner: Runner = subprocess.run,
    ) -> None:
        if not service or "\x00" in service:
            raise ValueError("keychain service must be a non-empty string")
        if not account or "\x00" in account:
            raise ValueError("keychain account must be a non-empty string")
        if not 0 < timeout_seconds <= 60:
            raise ValueError("keychain timeout must be between 0 and 60 seconds")
        self._service = service
        self._default_account = account
        self._timeout_seconds = float(timeout_seconds)
        self._runner = runner

    @staticmethod
    def _account_for(name: str) -> str:
        if not isinstance(name, str) or not name or "\x00" in name:
            raise ValueError("secret name must be a non-empty string")
        return name

    def _run(
        self,
        argv: list[str],
        *,
        stdin: bytes | None = None,
        operation: str,
    ) -> RunResult:
        try:
            result = self._runner(
                argv,
                input=stdin,
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise SecretStoreError(f"keychain {operation} timed out") from exc
        except OSError as exc:
            raise SecretStoreError(f"keychain {operation} failed") from exc
        return cast(RunResult, result)

    def set_secret(
        self,
        name: str | bytes,
        secret: bytes | None = None,
    ) -> None:
        """Store a secret without putting any representation of it in argv."""
        if secret is None:
            if not isinstance(name, bytes):
                raise TypeError("secret must be bytes")
            account = self._default_account
            value = name
        else:
            account = self._account_for(cast(str, name))
            value = secret
        if not isinstance(value, bytes):
            raise TypeError("secret must be bytes")

        argv = [
            "/usr/bin/security",
            "add-generic-password",
            "-a",
            account,
            "-s",
            self._service,
            "-U",
            "-w",
        ]
        stdin = b"base64:" + base64.b64encode(value) + b"\n"
        result = self._run(argv, stdin=stdin, operation="write")
        if result.returncode != 0:
            raise SecretStoreError("keychain write failed")

    def get_secret(self, name: str | None = None) -> bytes:
        account = self._account_for(name or self._default_account)
        argv = [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            account,
            "-s",
            self._service,
            "-w",
        ]
        result = self._run(argv, operation="read")
        if result.returncode == 44:
            raise SecretNotFoundError("secret was not found")
        if result.returncode != 0:
            raise SecretStoreError("keychain read failed")

        encoded = bytes(result.stdout).strip()
        if not encoded.startswith(b"base64:"):
            raise SecretStoreError("keychain secret has an unsupported format")
        try:
            return base64.b64decode(encoded[7:], validate=True)
        except binascii.Error as exc:
            raise SecretStoreError("keychain secret has an unsupported format") from exc

    def delete_secret(self, name: str | None = None) -> None:
        account = self._account_for(name or self._default_account)
        argv = [
            "/usr/bin/security",
            "delete-generic-password",
            "-a",
            account,
            "-s",
            self._service,
        ]
        result = self._run(argv, operation="delete")
        if result.returncode not in {0, 44}:
            raise SecretStoreError("keychain delete failed")


MacOSKeychainSecretStore = MacOSKeychain


__all__ = [
    "AES_256_KEY_BYTES",
    "AESGCMEnvelope",
    "CryptoStoreError",
    "InvalidEnvelopeError",
    "MacOSKeychain",
    "MacOSKeychainSecretStore",
    "MemorySecretStore",
    "SecretNotFoundError",
    "SecretStore",
    "SecretStoreError",
    "decrypt_envelope",
    "encrypt_envelope",
    "require_aes256_key",
]
