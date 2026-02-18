"""Security and verification helpers."""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
from email.utils import parsedate_to_datetime
from typing import Mapping
from urllib.parse import urlparse


SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "x-inbox-layer-token",
    "x-webhook-secret",
}


def sanitize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return headers with sensitive values redacted for logging/telemetry."""
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def validate_base_url(url: str, *, allow_http: bool = False) -> None:
    """Validate base URL to avoid open redirect and scheme abuse."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("base_url must include scheme and host")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported base_url scheme: {parsed.scheme}")
    if parsed.scheme == "http" and not allow_http:
        allowed = {"localhost", "127.0.0.1", "::1"}
        host = (parsed.hostname or "").lower()
        if host not in allowed:
            raise ValueError("Non-HTTPS base_url is not allowed without allow_http=True")
    if "\x00" in url:
        raise ValueError("Invalid base_url")


def verify_webhook_signature(
    payload: bytes | str,
    signature: str,
    secret: str,
    *,
    algorithm: str = "sha256",
) -> bool:
    """Validate HMAC signatures used by inbound webhook consumers.

    Accepted headers include raw hex digest or `sha256=<hex>` style prefixes.
    """
    if not secret:
        return False
    if not signature:
        return False
    prefix = f"{algorithm}="
    normalized_signature = signature.strip()
    if normalized_signature.lower().startswith(prefix):
        normalized_signature = normalized_signature[len(prefix) :].strip()

    if not normalized_signature:
        return False

    digest_cls = getattr(hashlib, algorithm, None)
    if digest_cls is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    message = payload.encode() if isinstance(payload, str) else payload
    expected = hmac.new(secret.encode(), message, digest_cls).hexdigest()
    return hmac.compare_digest(expected.lower(), normalized_signature.lower())


def verify_webhook_token(token: str | None, expected: str | None) -> bool:
    """Constant-time token comparison for token-authenticated inbound webhook routes."""
    if not expected:
        return False
    if not token:
        return False
    return hmac.compare_digest(token, expected)


def parse_retry_after(raw: str | None) -> float | None:
    """Parse Retry-After header values into seconds."""
    if raw is None:
        return None

    raw = raw.strip()
    if not raw:
        return None

    try:
        return max(0.0, float(raw))
    except ValueError:
        pass

    try:
        parsed = parsedate_to_datetime(raw)
    except (ValueError, TypeError, OverflowError):
        return None

    if parsed is None:
        return None

    now = _dt.datetime.now(_dt.timezone.utc)
    parsed_utc = parsed
    if parsed.utcoffset() is None:
        parsed_utc = parsed.replace(tzinfo=_dt.timezone.utc)
    else:
        parsed_utc = parsed.astimezone(_dt.timezone.utc)

    delta = (parsed_utc - now).total_seconds()
    return max(0.0, float(delta))
