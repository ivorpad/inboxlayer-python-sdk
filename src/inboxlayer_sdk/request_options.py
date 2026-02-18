"""Per-request overrides for the Inbox Layer clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class RequestOptions:
    timeout: float | None = None
    max_retries: int | None = None
    headers: Mapping[str, str] | None = None
    query: Mapping[str, object] | None = None
    json: object | None = None
    stream: bool = False
    response_validation: bool = True
    follow_redirects: bool | None = None
    allow_http: bool = False
    idempotency_key: str | None = None
