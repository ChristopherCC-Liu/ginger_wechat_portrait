from __future__ import annotations

import json
import threading
import unittest
from contextlib import contextmanager
from datetime import date
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator, Optional

from personal_agent.costs import CostReservation
from personal_agent.models import (
    ModelConfig,
    ModelConfigurationError,
    ModelTransportError,
    create_model_adapter,
)


def _provider_body() -> bytes:
    content = {
        "intent": "acknowledge",
        "stance": "Message received.",
        "facts": ["A fixture message was received."],
        "commitments": [],
        "risk": "low",
        "confidence": 0.96,
        "reply_required": True,
        "context_sufficient": True,
        "reasons": ["security fixture"],
    }
    return json.dumps(
        {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(content),
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10},
        }
    ).encode("utf-8")


class _Response:
    def __init__(
        self,
        *,
        status_error: Optional[BaseException] = None,
        read_error: Optional[BaseException] = None,
        close_error: Optional[BaseException] = None,
    ) -> None:
        self._status_error = status_error
        self._read_error = read_error
        self._close_error = close_error
        self.headers = {}
        self.close_attempts = 0

    @property
    def status(self) -> int:
        if self._status_error is not None:
            raise self._status_error
        return 200

    def read(self, limit: int) -> bytes:
        if self._read_error is not None:
            raise self._read_error
        return _provider_body()[:limit]

    def close(self) -> None:
        self.close_attempts += 1
        if self._close_error is not None:
            raise self._close_error


class _StaticOpener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def __call__(self, request: object, *, timeout: float) -> _Response:
        return self.response


class _ConservativeLedger:
    """Minimal ledger double whose failed settlement consumes the reservation."""

    def __init__(self) -> None:
        self.active: Optional[CostReservation] = None
        self.failed_reservation_ids: list[str] = []

    def reserve(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> CostReservation:
        reservation = CostReservation(
            reservation_id="security-cost-reservation",
            budget_date=date(2026, 7, 21),
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost=Decimal("1"),
        )
        self.active = reservation
        return reservation

    def has_active_reservation(self, reservation_id: str) -> bool:
        return self.active is not None and self.active.reservation_id == reservation_id

    def refund(self, reservation_id: str) -> CostReservation:
        if self.active is None or self.active.reservation_id != reservation_id:
            raise AssertionError("unexpected failed reservation")
        reservation = self.active
        self.active = None
        self.failed_reservation_ids.append(reservation_id)
        return reservation

    def commit(
        self,
        reservation_id: str,
        *,
        actual_input_tokens: int,
        actual_output_tokens: int,
    ) -> None:
        raise AssertionError("a failed transport must not commit actual usage")


@contextmanager
def _serve(
    handler: type[BaseHTTPRequestHandler],
) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _sink_handler(authorizations: list[Optional[str]]) -> type[BaseHTTPRequestHandler]:
    class SinkHandler(BaseHTTPRequestHandler):
        def _respond(self) -> None:
            authorizations.append(self.headers.get("Authorization"))
            body = _provider_body()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _respond
        do_POST = _respond

        def log_message(self, format: str, *args: object) -> None:
            return

    return SinkHandler


def _redirect_handler(
    status: int,
    location: str,
    authorizations: list[Optional[str]],
) -> type[BaseHTTPRequestHandler]:
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            authorizations.append(self.headers.get("Authorization"))
            self.send_response(status)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    return RedirectHandler


class EndpointSecurityTests(unittest.TestCase):
    def test_local_http_and_https_require_literal_loopback(self) -> None:
        for scheme in ("http", "https"):
            for host in ("localhost", "127.0.0.1", "[::1]"):
                with self.subTest(scheme=scheme, host=host):
                    config = ModelConfig(
                        provider="local",
                        model="fixture-model",
                        endpoint=f"{scheme}://{host}:11434/v1/chat/completions",
                    )
                    self.assertEqual(config.provider, "local")

            for host in ("example.test", "192.0.2.10", "localhost.example.test"):
                with self.subTest(scheme=scheme, host=host):
                    with self.assertRaises(ModelConfigurationError):
                        ModelConfig(
                            provider="local",
                            model="fixture-model",
                            endpoint=(f"{scheme}://{host}:11434/v1/chat/completions"),
                        )

    def test_remote_providers_still_require_https(self) -> None:
        for provider in ("openai", "glm"):
            with self.subTest(provider=provider):
                with self.assertRaises(ModelConfigurationError):
                    ModelConfig(
                        provider=provider,
                        model="fixture-model",
                        endpoint="http://127.0.0.1/v1/chat/completions",
                    )
                config = ModelConfig(
                    provider=provider,
                    model="fixture-model",
                    endpoint="https://example.test/v1/chat/completions",
                )
                self.assertEqual(config.provider, provider)


class RedirectSecurityTests(unittest.TestCase):
    def test_302_and_307_are_not_followed_or_sent_authorization(self) -> None:
        fixture_token = "security-test-token-not-a-secret"
        for status in (302, 307):
            source_authorizations: list[Optional[str]] = []
            sink_authorizations: list[Optional[str]] = []
            with self.subTest(status=status):
                with _serve(_sink_handler(sink_authorizations)) as sink:
                    sink_port = sink.server_address[1]
                    location = f"http://localhost:{sink_port}/redirect-target"
                    handler = _redirect_handler(
                        status,
                        location,
                        source_authorizations,
                    )
                    with _serve(handler) as source:
                        source_port = source.server_address[1]
                        adapter = create_model_adapter(
                            ModelConfig(
                                provider="local",
                                model="fixture-model",
                                endpoint=(
                                    "http://127.0.0.1:"
                                    f"{source_port}/v1/chat/completions"
                                ),
                            ),
                            api_key=fixture_token,
                        )
                        with self.assertRaises(ModelTransportError):
                            adapter.decide("fixture message")

            self.assertEqual(
                source_authorizations,
                [f"Bearer {fixture_token}"],
            )
            self.assertEqual(sink_authorizations, [])


class ResponseFailureTests(unittest.TestCase):
    def _adapter(self, response: _Response, *, ledger: object = None):
        return create_model_adapter(
            ModelConfig(
                provider="local",
                model="fixture-model",
                endpoint="http://127.0.0.1:11434/v1/chat/completions",
            ),
            cost_ledger=ledger,
            opener=_StaticOpener(response),
        )

    def test_status_read_and_close_io_errors_are_transport_errors(self) -> None:
        cases = (
            ("status", OSError("status I/O failure"), "status"),
            ("read", TimeoutError("read timeout"), "read"),
            ("close", OSError("close I/O failure"), "close"),
        )
        for stage, source_error, message in cases:
            with self.subTest(stage=stage):
                response = _Response(**{f"{stage}_error": source_error})
                with self.assertRaisesRegex(ModelTransportError, message) as caught:
                    self._adapter(response).decide("fixture message")
                self.assertIs(caught.exception.__cause__, source_error)
                self.assertEqual(response.close_attempts, 1)

    def test_close_failure_does_not_mask_primary_exception(self) -> None:
        read_error = TimeoutError("primary read timeout")
        response = _Response(
            read_error=read_error,
            close_error=RuntimeError("secondary close failure"),
        )

        with self.assertRaisesRegex(ModelTransportError, "read") as caught:
            self._adapter(response).decide("fixture message")

        self.assertIs(caught.exception.__cause__, read_error)
        self.assertEqual(response.close_attempts, 1)

    def test_close_transport_failure_uses_failed_cost_settlement(self) -> None:
        ledger = _ConservativeLedger()
        response = _Response(close_error=OSError("close I/O failure"))

        with self.assertRaisesRegex(ModelTransportError, "close"):
            self._adapter(response, ledger=ledger).decide("fixture message")

        self.assertIsNone(ledger.active)
        self.assertEqual(
            ledger.failed_reservation_ids,
            ["security-cost-reservation"],
        )


if __name__ == "__main__":
    unittest.main()
