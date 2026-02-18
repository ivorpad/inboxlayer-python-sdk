"""SDK-specific exceptions."""

from __future__ import annotations

from typing import Mapping


class InboxLayerError(Exception):
    """Base exception for all Inbox Layer SDK failures."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
        body: object = None,
        headers: Mapping[str, str] | None = None,
        request_id: str | None = None,
        retry_after: float | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.body = body
        self.headers = dict(headers) if headers is not None else {}
        self.request_id = request_id
        self.retry_after = retry_after
        self.cause = cause

    def __str__(self) -> str:  # pragma: no cover - simple formatting
        if self.status_code is None:
            return str(self.args[0])
        parts = [f"{self.status_code}"]
        if self.error_code:
            parts.append(self.error_code)
        return " ".join(parts) + f": {self.args[0]}"


class InboxLayerValidationError(InboxLayerError):
    """Raised when request/response payloads are invalid."""


class InboxLayerHTTPError(InboxLayerError):
    """Raised for HTTP non-success responses."""


class InboxLayerAuthError(InboxLayerHTTPError):
    """Raised for authentication and authorization failures."""


class InboxLayerRateLimitError(InboxLayerHTTPError):
    """Raised for HTTP 429 responses."""


class InboxLayerNetworkError(InboxLayerError):
    """Raised for transport-level failures like DNS and TCP errors."""


class InboxLayerTimeoutError(InboxLayerError):
    """Raised when a request exceeds configured timeout."""

