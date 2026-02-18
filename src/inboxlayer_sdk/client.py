"""Main synchronous and asynchronous clients for the Inbox Layer API."""

from __future__ import annotations

import asyncio
import os
import random
import time
from datetime import datetime
from types import MappingProxyType
from typing import Any, AsyncIterator, Iterator, Mapping, Sequence, cast

import httpx

from .exceptions import (
    InboxLayerAuthError,
    InboxLayerError,
    InboxLayerHTTPError,
    InboxLayerNetworkError,
    InboxLayerRateLimitError,
    InboxLayerTimeoutError,
    InboxLayerValidationError,
)
from .models import (
    Account,
    AuthResponse,
    CustomDomain,
    CustomDomainInput,
    Draft,
    DraftCollection,
    DraftInput,
    Email,
    EmailActionInput,
    EmailLabelPatch,
    EmailList,
    EmailSendInput,
    EmailSendResponse,
    EmailThread,
    EmailThreadList,
    Inbox,
    InboxCreate,
    InboxEmails,
    InboxList,
    MailboxLabel,
    MailboxLabelInput,
    MailboxLabelList,
    PasswordInput,
    SendResult,
    SuccessResponse,
    User,
    WarmupStatus,
    WebhookSubscription,
    WebhookSubscriptionInput,
)
from .request_options import RequestOptions
from .security import parse_retry_after, validate_base_url
from .streams import SSEEvent, parse_sse_lines, parse_sse_lines_async


def _is_datetime(value: Any) -> bool:
    return isinstance(value, (datetime,))


def _coerce_datetime(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _coerce_json_payload(payload: Any) -> Any:
    if payload is None:
        return None
    if isinstance(payload, Mapping):
        return dict(payload)
    return payload


def _coerce_wrapper_payload(payload: Any, wrapper_key: str) -> Any:
    if payload is None:
        return None

    if isinstance(payload, Mapping):
        if wrapper_key in payload:
            return payload
        return {wrapper_key: dict(payload)}
    return payload


def _coerce_password_payload(payload: Any) -> Any:
    if payload is None:
        raise InboxLayerValidationError("password update body is required")

    if isinstance(payload, Mapping):
        if "user" in payload:
            return dict(payload)
        if {"current_password", "password", "password_confirmation"} <= set(payload):
            return {
                "user": {
                    "current_password": payload.get("current_password"),
                    "password": payload.get("password"),
                    "password_confirmation": payload.get("password_confirmation"),
                }
            }

    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        raise InboxLayerValidationError("password update body must be a mapping")

    return {"user": payload}


def _coerce_query_params(query: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if query is None:
        return None
    normalized: dict[str, Any] = {}
    for key, value in query.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            normalized[key] = ["" if v is None else v for v in value]
            continue
        if _is_datetime(value):
            normalized[key] = _coerce_datetime(value)
            continue
        normalized[key] = value
    return normalized


def _resolve_request_options(options: RequestOptions | None) -> RequestOptions:
    return options or RequestOptions()


def _normalize_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    clean: dict[str, str] = {}
    for key, value in headers.items():
        clean[str(key)] = str(value)
    return clean


def _coerce_stream_response(response: httpx.Response) -> Iterator[SSEEvent] | None:
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        return parse_sse_lines(response.iter_lines())
    return None


class _BaseInboxLayerClient:
    default_base_url = "https://inboxlayer.dev"
    default_timeout = 30.0
    default_max_retries = 3
    default_retriable_methods = frozenset({"GET", "HEAD", "OPTIONS", "DELETE", "PUT", "PATCH"})
    retryable_status_codes = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 524})
    retry_base_delay = 0.4
    retry_max_delay = 10.0
    jitter_range = 0.35

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        timeout: float = default_timeout,
        max_retries: int = default_max_retries,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
        allow_http: bool = False,
        token_env_var: str = "INBOX_LAYER_API_TOKEN",
        base_url_env_var: str = "INBOX_LAYER_API_BASE_URL",
    ) -> None:
        self.base_url = (base_url or os.getenv(base_url_env_var) or self.default_base_url).rstrip("/")
        validate_base_url(self.base_url, allow_http=allow_http)
        token = api_token or os.getenv(token_env_var)
        self.api_token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self._default_headers = {
            "Accept": "application/json",
            "User-Agent": "inboxlayer-python-sdk/0.1.0",
        }
        if self.api_token:
            self._default_headers["Authorization"] = f"Bearer {self.api_token}"
        if headers:
            self._default_headers.update(_normalize_headers(headers))

        self._client_kwargs = {
            "base_url": self.base_url,
            "timeout": timeout,
            "follow_redirects": follow_redirects,
            "trust_env": False,
        }

    def _request_options(self, options: RequestOptions | None) -> RequestOptions:
        return _resolve_request_options(options)

    @staticmethod
    def _path(path: str) -> str:
        if "://" in path:
            raise ValueError("Full URLs are not allowed in path for request method")
        if not path.startswith("/"):
            raise ValueError("Path must be absolute and start with '/'")
        if "\x00" in path:
            raise ValueError("Invalid path characters")
        return path

    def _headers(self, request_options: RequestOptions, idempotency_key: str | None = None) -> dict[str, str]:
        merged = dict(self._default_headers)
        if request_options.headers:
            merged.update(_normalize_headers(request_options.headers))
        if idempotency_key:
            merged.setdefault("Idempotency-Key", idempotency_key)
        return merged

    def _build_request_timeout(self, request_options: RequestOptions) -> float:
        timeout = request_options.timeout if request_options.timeout is not None else self.timeout
        if timeout <= 0:
            raise InboxLayerValidationError("timeout must be greater than 0")
        return float(timeout)

    def _build_max_retries(self, request_options: RequestOptions) -> int:
        max_retries = request_options.max_retries if request_options.max_retries is not None else self.max_retries
        if max_retries < 0:
            raise InboxLayerValidationError("max_retries must be non-negative")
        return int(max_retries)

    def _merge_query(self, request_options: RequestOptions, query: Mapping[str, Any] | None) -> dict[str, Any] | None:
        merged = {}
        for source in (request_options.query, query):
            if source is None:
                continue
            merged.update(_coerce_query_params(dict(source)) or {})
        return merged or None

    def _should_retry(self, method: str, status_code: int, attempt: int, max_retries: int) -> bool:
        if attempt >= max_retries:
            return False
        if method not in self.default_retriable_methods:
            return False
        if status_code in self.retryable_status_codes:
            return True
        return False

    @staticmethod
    def _retry_delay(attempt: int, status_code: int | None = None, retry_after: float | None = None) -> float:
        if status_code == 429 and retry_after is not None:
            return min(max(0.0, retry_after), 60.0)
        base = _BaseInboxLayerClient.retry_base_delay * (2 ** max(0, attempt - 1))
        jitter = random.uniform(0, _BaseInboxLayerClient.jitter_range)
        return min(_BaseInboxLayerClient.retry_max_delay, base + jitter)

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        raw_body = None
        parsed_body = None
        content_type = response.headers.get("content-type", "")
        try:
            raw_body = response.text
            if "application/json" in content_type.lower():
                parsed_body = response.json()
        except Exception:
            raw_body = None

        message = str(parsed_body or raw_body or "request failed")
        if isinstance(parsed_body, Mapping):
            if isinstance(parsed_body.get("error"), str):
                message = parsed_body["error"]
            elif isinstance(parsed_body.get("message"), str):
                message = parsed_body["message"]
            error_code = parsed_body.get("error_code")
        else:
            error_code = None

        headers = MappingProxyType(dict(response.headers))
        retry_after = parse_retry_after(response.headers.get("Retry-After"))
        kwargs = {
            "status_code": response.status_code,
            "error_code": error_code if isinstance(error_code, str) else None,
            "body": parsed_body or raw_body,
            "headers": headers,
            "request_id": response.headers.get("x-request-id"),
            "retry_after": retry_after,
        }
        if response.status_code in {401, 403}:
            raise InboxLayerAuthError(message, **kwargs)
        if response.status_code == 429:
            raise InboxLayerRateLimitError(message, **kwargs)
        if response.status_code >= 500:
            raise InboxLayerHTTPError(message, **kwargs)
        raise InboxLayerHTTPError(message, **kwargs)

    def _parse_response(self, response: httpx.Response) -> Any:
        if response.status_code == 204:
            return None
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type.lower():
            return None
        if not response.content:
            return None
        if "application/json" not in content_type.lower():
            return response.text
        return response.json()


class InboxLayerClient(_BaseInboxLayerClient):
    """Synchronous client."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        timeout: float = _BaseInboxLayerClient.default_timeout,
        max_retries: int = _BaseInboxLayerClient.default_max_retries,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
        httpx_client: httpx.Client | None = None,
        allow_http: bool = False,
    ) -> None:
        super().__init__(
            base_url=base_url,
            api_token=api_token,
            timeout=timeout,
            max_retries=max_retries,
            headers=headers,
            follow_redirects=follow_redirects,
            allow_http=allow_http,
        )
        self._httpx = httpx_client or httpx.Client(**self._client_kwargs)

    def __enter__(self) -> "InboxLayerClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._httpx.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        json_data: Any | None = None,
        options: RequestOptions | None = None,
        stream: bool = False,
        idempotency_key: str | None = None,
    ) -> Any:
        request_options = self._request_options(options)
        path = self._path(path)
        method = method.upper()
        headers = self._headers(request_options, idempotency_key=request_options.idempotency_key or idempotency_key)
        final_query = self._merge_query(request_options, query)
        final_json = request_options.json if request_options.json is not None else json_data
        final_json = _coerce_json_payload(final_json)
        retries = self._build_max_retries(request_options)
        timeout = self._build_request_timeout(request_options)

        attempt = 0
        while True:
            attempt += 1
            try:
                response = self._httpx.request(
                    method=method,
                    url=path,
                    headers=headers,
                    params=final_query,
                    json=final_json,
                    timeout=timeout,
                )
            except httpx.TimeoutException as exc:
                if attempt > retries:
                    raise InboxLayerTimeoutError("Request timed out", timeout=timeout, cause=exc)
                wait = self._retry_delay(attempt, None, None)
                time.sleep(wait)
                continue
            except httpx.NetworkError as exc:
                if attempt > retries:
                    raise InboxLayerNetworkError("Network error", cause=exc)
                wait = self._retry_delay(attempt, None, None)
                time.sleep(wait)
                continue

            if response.is_success:
                break
            if self._should_retry(method, response.status_code, attempt, retries):
                wait = self._retry_delay(
                    attempt,
                    status_code=response.status_code,
                    retry_after=parse_retry_after(response.headers.get("Retry-After")),
                )
                time.sleep(wait)
                continue
            break

        self._raise_for_status(response)
        if stream:
            stream_iter = _coerce_stream_response(response)
            if stream_iter is None:
                response.raise_for_status()
            return stream_iter
        return self._parse_response(response)

    def stream_inbox_events(
        self,
        inbox_id: str,
        *,
        timeout: int | None = None,
        since: str | datetime | None = None,
        options: RequestOptions | None = None,
    ) -> Iterator[SSEEvent]:
        query = {"since": _coerce_datetime(since), "timeout": timeout}
        query = {k: v for k, v in query.items() if v is not None}
        request_options = self._request_options(options)
        retries = self._build_max_retries(request_options)
        attempt = 0
        while True:
            attempt += 1
            try:
                with self._httpx.stream(
                    "GET",
                    self._path(f"/api/v1/inboxes/{inbox_id}/stream"),
                    headers=self._headers(request_options),
                    params=self._merge_query(request_options, query),
                    timeout=self._build_request_timeout(request_options),
                ) as response:
                    self._raise_for_status(response)
                    for line in parse_sse_lines(response.iter_lines()):
                        yield line
                    return
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt > retries:
                    raise InboxLayerNetworkError("SSE stream failed", cause=exc)
                wait = self._retry_delay(attempt, None, None)
                time.sleep(wait)
                continue

    def list_accounts(self, *, options: RequestOptions | None = None) -> list[Account]:
        return self.request("GET", "/api/v1/accounts", options=options)

    def authenticate(self, email: str | None = None, password: str | None = None, *, options: RequestOptions | None = None) -> AuthResponse:
        if email is None or password is None:
            raise InboxLayerValidationError("email and password are required")
        body = {"email": email, "password": password}
        response = self.request("POST", "/api/v1/auth", json_data=body, options=options)
        if isinstance(response, dict) and "token" in response:
            self.api_token = response["token"]
            self._default_headers["Authorization"] = f"Bearer {response['token']}"
        return response

    def post_auth(self, email: str, password: str, *, options: RequestOptions | None = None) -> AuthResponse:
        return self.authenticate(email=email, password=password, options=options)

    def delete_auth(self, *, options: RequestOptions | None = None) -> SuccessResponse:
        response = cast(SuccessResponse, self.request("DELETE", "/api/v1/auth", options=options))
        self.api_token = None
        self._default_headers.pop("Authorization", None)
        return response

    def logout(self, *, options: RequestOptions | None = None) -> SuccessResponse:
        return self.delete_auth(options=options)

    def get_me(self, *, options: RequestOptions | None = None) -> User:
        return self.request("GET", "/api/v1/me", options=options)

    def patch_password(self, body: Mapping[str, Any] | PasswordInput | None = None, *, options: RequestOptions | None = None) -> SuccessResponse:
        return self._simple_password_change("PATCH", body, options=options)

    def put_password(self, body: Mapping[str, Any] | PasswordInput | None = None, *, options: RequestOptions | None = None) -> SuccessResponse:
        return self._simple_password_change("PUT", body, options=options)

    def replace_password(self, body: Mapping[str, Any] | PasswordInput | None = None, *, options: RequestOptions | None = None) -> SuccessResponse:
        return self.put_password(body=body, options=options)

    def _simple_password_change(
        self,
        method: str,
        body: Mapping[str, Any] | PasswordInput | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SuccessResponse:
        payload = _coerce_password_payload(body)
        return cast(
            SuccessResponse,
            self.request(method, "/api/v1/password", json_data=payload, options=options),
        )

    def list_inboxes(
        self,
        *,
        cursor: str | None = None,
        per_page: int | None = None,
        options: RequestOptions | None = None,
    ) -> InboxList:
        return self.request(
            "GET",
            "/api/v1/inboxes",
            query={"cursor": cursor, "per_page": per_page},
            options=options,
        )

    def create_inbox(self, payload: InboxCreate | Mapping[str, Any], *, options: RequestOptions | None = None) -> Inbox:
        return cast(Inbox, self.request("POST", "/api/v1/inboxes", json_data=payload, options=options))

    def get_inbox(self, inbox_id: str, *, cursor: str | None = None, labels: str | None = None, options: RequestOptions | None = None) -> InboxEmails:
        return cast(
            InboxEmails,
            self.request(
                "GET",
                f"/api/v1/inboxes/{inbox_id}",
                query={"cursor": cursor, "labels": labels},
                options=options,
            ),
        )

    def delete_inbox(self, inbox_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, self.request("DELETE", f"/api/v1/inboxes/{inbox_id}", options=options))

    def warmup_inbox(self, inbox_id: str, *, options: RequestOptions | None = None) -> WarmupStatus:
        return cast(
            WarmupStatus,
            self.request("GET", f"/api/v1/inboxes/{inbox_id}/warmup", options=options),
        )

    def list_inbox_drafts(
        self,
        inbox_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> DraftCollection:
        return cast(
            DraftCollection,
            self.request(
                "GET",
                f"/api/v1/inboxes/{inbox_id}/drafts",
                options=options,
            ),
        )

    def create_inbox_draft(
        self,
        inbox_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return cast(
            Draft,
            self.request(
                "POST",
                f"/api/v1/inboxes/{inbox_id}/drafts",
                json_data=payload,
                options=options,
            ),
        )

    def get_inbox_draft(self, inbox_id: str, draft_id: str, *, options: RequestOptions | None = None) -> Draft:
        return cast(
            Draft,
            self.request(
                "GET",
                f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}",
                options=options,
            ),
        )

    def update_inbox_draft(
        self,
        inbox_id: str,
        draft_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return self._patch_or_put_draft(
            "PATCH",
            f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}",
            payload,
            options=options,
        )

    def replace_inbox_draft(
        self,
        inbox_id: str,
        draft_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return self._patch_or_put_draft(
            "PUT",
            f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}",
            payload,
            options=options,
        )

    def _patch_or_put_draft(
        self,
        method: str,
        path: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return cast(Draft, self.request(method, path, json_data=payload, options=options))

    def delete_inbox_draft(self, inbox_id: str, draft_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, self.request("DELETE", f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}", options=options))

    def send_inbox_draft(self, inbox_id: str, draft_id: str, *, options: RequestOptions | None = None) -> SendResult:
        return cast(
            SendResult,
            self.request(
                "POST",
                f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}/send",
                options=options,
            ),
        )

    def list_drafts(self, *, options: RequestOptions | None = None) -> DraftCollection:
        return cast(DraftCollection, self.request("GET", "/api/v1/drafts", options=options))

    def create_draft(
        self,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return cast(Draft, self.request("POST", "/api/v1/drafts", json_data=payload, options=options))

    def get_draft(self, draft_id: str, *, options: RequestOptions | None = None) -> Draft:
        return cast(Draft, self.request("GET", f"/api/v1/drafts/{draft_id}", options=options))

    def update_draft(
        self,
        draft_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return self._patch_or_put_draft(
            "PATCH",
            f"/api/v1/drafts/{draft_id}",
            payload,
            options=options,
        )

    def replace_draft(
        self,
        draft_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return self._patch_or_put_draft(
            "PUT",
            f"/api/v1/drafts/{draft_id}",
            payload,
            options=options,
        )

    def delete_draft(self, draft_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, self.request("DELETE", f"/api/v1/drafts/{draft_id}", options=options))

    def send_draft(self, draft_id: str, *, options: RequestOptions | None = None) -> SendResult:
        return cast(
            SendResult,
            self.request("POST", f"/api/v1/drafts/{draft_id}/send", options=options),
        )

    def list_emails(
        self,
        *,
        inbox: str | None = None,
        cursor: str | None = None,
        options: RequestOptions | None = None,
    ) -> EmailList:
        return cast(
            EmailList,
            self.request(
                "GET",
                "/api/v1/emails",
                query={"inbox": inbox, "cursor": cursor},
                options=options,
            ),
        )

    def create_email(self, payload: EmailSendInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> EmailSendResponse:
        return cast(EmailSendResponse, self.request("POST", "/api/v1/emails", json_data=payload, options=options))

    def patch_email(self, email_id: str, payload: EmailLabelPatch | Mapping[str, Any], *, options: RequestOptions | None = None) -> Email:
        return cast(Email, self.request("PATCH", f"/api/v1/emails/{email_id}", json_data=payload, options=options))

    def put_email(self, email_id: str, payload: EmailLabelPatch | Mapping[str, Any], *, options: RequestOptions | None = None) -> Email:
        return cast(Email, self.request("PUT", f"/api/v1/emails/{email_id}", json_data=payload, options=options))

    def apply_email_actions(
        self,
        email_id: str,
        action: EmailActionInput | EmailLabelPatch | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Email:
        return cast(
            Email,
            self.request("PATCH", f"/api/v1/emails/{email_id}/actions", json_data=action, options=options),
        )

    def reply_email(
        self,
        email_id: str,
        payload: Mapping[str, Any] | EmailSendInput,
        *,
        options: RequestOptions | None = None,
    ) -> SendResult:
        return cast(
            SendResult,
            self.request("POST", f"/api/v1/emails/{email_id}/reply", json_data=payload, options=options),
        )

    def forward_email(
        self,
        email_id: str,
        payload: Mapping[str, Any] | EmailSendInput,
        *,
        options: RequestOptions | None = None,
    ) -> SendResult:
        return cast(
            SendResult,
            self.request("POST", f"/api/v1/emails/{email_id}/forward", json_data=payload, options=options),
        )

    def send_email(self, payload: Mapping[str, Any] | EmailSendInput, *, options: RequestOptions | None = None) -> SendResult:
        return cast(SendResult, self.request("POST", "/api/v1/emails/send", json_data=payload, options=options))

    def search_emails(self, q: str, *, options: RequestOptions | None = None) -> EmailList:
        return cast(
            EmailList,
            self.request("GET", "/api/v1/emails/search", query={"q": q}, options=options),
        )

    def list_mailbox_labels(self, *, options: RequestOptions | None = None) -> MailboxLabelList:
        return cast(MailboxLabelList, self.request("GET", "/api/v1/mailbox_labels", options=options))

    def create_mailbox_label(self, payload: MailboxLabelInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> MailboxLabel:
        return cast(
            MailboxLabel,
            self.request("POST", "/api/v1/mailbox_labels", json_data=payload, options=options),
        )

    def update_mailbox_label(
        self,
        mailbox_label_id: str,
        payload: MailboxLabelInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> MailboxLabel:
        return cast(
            MailboxLabel,
            self.request("PATCH", f"/api/v1/mailbox_labels/{mailbox_label_id}", json_data=payload, options=options),
        )

    def replace_mailbox_label(
        self,
        mailbox_label_id: str,
        payload: MailboxLabelInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> MailboxLabel:
        return cast(
            MailboxLabel,
            self.request("PUT", f"/api/v1/mailbox_labels/{mailbox_label_id}", json_data=payload, options=options),
        )

    def delete_mailbox_label(self, mailbox_label_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, self.request("DELETE", f"/api/v1/mailbox_labels/{mailbox_label_id}", options=options))

    def create_notification_token(self, payload: Mapping[str, Any], *, options: RequestOptions | None = None) -> dict[str, Any]:
        return cast(dict[str, Any], self.request("POST", "/api/v1/notification_tokens", json_data=payload, options=options))

    def list_custom_domains(self, *, options: RequestOptions | None = None) -> list[CustomDomain]:
        return self.request("GET", "/api/v1/custom_domains", options=options)

    def create_custom_domain(self, payload: CustomDomainInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> CustomDomain:
        payload = _coerce_wrapper_payload(payload, "custom_domain")
        return cast(
            CustomDomain,
            self.request("POST", "/api/v1/custom_domains", json_data=payload, options=options),
        )

    def get_custom_domain(self, domain_id: str, *, options: RequestOptions | None = None) -> CustomDomain:
        return cast(
            CustomDomain,
            self.request("GET", f"/api/v1/custom_domains/{domain_id}", options=options),
        )

    def update_custom_domain(
        self,
        domain_id: str,
        payload: CustomDomainInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> CustomDomain:
        payload = _coerce_wrapper_payload(payload, "custom_domain")
        return self._patch_or_put_custom_domain(
            "PATCH",
            f"/api/v1/custom_domains/{domain_id}",
            payload,
            options=options,
        )

    def replace_custom_domain(
        self,
        domain_id: str,
        payload: CustomDomainInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> CustomDomain:
        payload = _coerce_wrapper_payload(payload, "custom_domain")
        return self._patch_or_put_custom_domain(
            "PUT",
            f"/api/v1/custom_domains/{domain_id}",
            payload,
            options=options,
        )

    def _patch_or_put_custom_domain(
        self,
        method: str,
        path: str,
        payload: CustomDomainInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> CustomDomain:
        return cast(
            CustomDomain,
            self.request(method, path, json_data=payload, options=options),
        )

    def delete_custom_domain(self, domain_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, self.request("DELETE", f"/api/v1/custom_domains/{domain_id}", options=options))

    def verify_custom_domain(self, domain_id: str, *, options: RequestOptions | None = None) -> dict[str, Any]:
        return cast(
            dict[str, Any],
            self.request("POST", f"/api/v1/custom_domains/{domain_id}/verify", options=options),
        )

    def list_webhook_subscriptions(self, *, options: RequestOptions | None = None) -> list[WebhookSubscription]:
        return self.request(
            "GET",
            "/api/v1/webhook_subscriptions",
            options=options,
        )

    def create_webhook_subscription(
        self,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        body = _coerce_wrapper_payload(payload, "webhook_subscription")
        return cast(
            WebhookSubscription,
            self.request("POST", "/api/v1/webhook_subscriptions", json_data=body, options=options),
        )

    def get_webhook_subscription(self, webhook_id: str, *, options: RequestOptions | None = None) -> WebhookSubscription:
        return cast(
            WebhookSubscription,
            self.request(
                "GET",
                f"/api/v1/webhook_subscriptions/{webhook_id}",
                options=options,
            ),
        )

    def update_webhook_subscription(
        self,
        webhook_id: str,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        payload = _coerce_wrapper_payload(payload, "webhook_subscription")
        return self._patch_or_put_webhook(
            "PATCH",
            f"/api/v1/webhook_subscriptions/{webhook_id}",
            payload,
            options=options,
        )

    def replace_webhook_subscription(
        self,
        webhook_id: str,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        payload = _coerce_wrapper_payload(payload, "webhook_subscription")
        return self._patch_or_put_webhook(
            "PUT",
            f"/api/v1/webhook_subscriptions/{webhook_id}",
            payload,
            options=options,
        )

    def _patch_or_put_webhook(
        self,
        method: str,
        path: str,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        return cast(
            WebhookSubscription,
            self.request(method, path, json_data=payload, options=options),
        )

    def delete_webhook_subscription(self, webhook_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, self.request("DELETE", f"/api/v1/webhook_subscriptions/{webhook_id}", options=options))

    def test_webhook_subscription(self, webhook_id: str, *, options: RequestOptions | None = None) -> SuccessResponse:
        return cast(
            SuccessResponse,
            self.request("POST", f"/api/v1/webhook_subscriptions/{webhook_id}/test", options=options),
        )

    def list_threads(self, *, options: RequestOptions | None = None) -> EmailThreadList:
        return cast(
            EmailThreadList,
            self.request("GET", "/api/v1/email_threads", options=options),
        )

    def get_email_thread(self, thread_id: str, *, options: RequestOptions | None = None) -> EmailThread:
        return cast(
            EmailThread,
            self.request("GET", f"/api/v1/email_threads/{thread_id}", options=options),
        )


class AsyncInboxLayerClient(_BaseInboxLayerClient):
    """Asynchronous client."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        timeout: float = _BaseInboxLayerClient.default_timeout,
        max_retries: int = _BaseInboxLayerClient.default_max_retries,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
        httpx_client: httpx.AsyncClient | None = None,
        allow_http: bool = False,
    ) -> None:
        super().__init__(
            base_url=base_url,
            api_token=api_token,
            timeout=timeout,
            max_retries=max_retries,
            headers=headers,
            follow_redirects=follow_redirects,
            allow_http=allow_http,
        )
        self._httpx = httpx_client or httpx.AsyncClient(**self._client_kwargs)

    async def __aenter__(self) -> "AsyncInboxLayerClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._httpx.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        json_data: Any | None = None,
        options: RequestOptions | None = None,
        stream: bool = False,
    ) -> Any:
        request_options = self._request_options(options)
        path = self._path(path)
        method = method.upper()
        headers = self._headers(request_options)
        final_query = self._merge_query(request_options, query)
        final_json = request_options.json if request_options.json is not None else json_data
        final_json = _coerce_json_payload(final_json)
        retries = self._build_max_retries(request_options)
        timeout = self._build_request_timeout(request_options)

        attempt = 0
        while True:
            attempt += 1
            try:
                response = await self._httpx.request(
                    method=method,
                    url=path,
                    headers=headers,
                    params=final_query,
                    json=final_json,
                    timeout=timeout,
                )
            except httpx.TimeoutException as exc:
                if attempt > retries:
                    raise InboxLayerTimeoutError("Request timed out", timeout=timeout, cause=exc)
                wait = self._retry_delay(attempt, None, None)
                await asyncio.sleep(wait)
                continue
            except httpx.NetworkError as exc:
                if attempt > retries:
                    raise InboxLayerNetworkError("Network error", cause=exc)
                wait = self._retry_delay(attempt, None, None)
                await asyncio.sleep(wait)
                continue

            if response.is_success:
                break
            if self._should_retry(method, response.status_code, attempt, retries):
                wait = self._retry_delay(
                    attempt,
                    status_code=response.status_code,
                    retry_after=parse_retry_after(response.headers.get("Retry-After")),
                )
                await asyncio.sleep(wait)
                continue
            break

        self._raise_for_status(response)
        if stream:
            if response.headers.get("content-type", "").startswith("text/event-stream"):
                return parse_sse_lines(response.aiter_lines())
            return None
        return self._parse_response(response)

    async def stream_inbox_events(
        self,
        inbox_id: str,
        *,
        timeout: int | None = None,
        since: str | datetime | None = None,
        options: RequestOptions | None = None,
    ) -> AsyncIterator[SSEEvent]:
        query = {"since": _coerce_datetime(since), "timeout": timeout}
        query = {k: v for k, v in query.items() if v is not None}
        request_options = self._request_options(options)
        retries = self._build_max_retries(request_options)
        attempt = 0
        while True:
            attempt += 1
            try:
                async with self._httpx.stream(
                    "GET",
                    self._path(f"/api/v1/inboxes/{inbox_id}/stream"),
                    headers=self._headers(request_options),
                    params=self._merge_query(request_options, query),
                    timeout=self._build_request_timeout(request_options),
                ) as response:
                    self._raise_for_status(response)
                    async for event in parse_sse_lines_async(response.aiter_lines()):
                        yield event
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt > retries:
                    raise InboxLayerNetworkError("SSE stream failed", cause=exc)
                wait = self._retry_delay(attempt, None, None)
                await asyncio.sleep(wait)
                continue
            return

    async def list_accounts(self, *, options: RequestOptions | None = None) -> list[Account]:
        return cast(list[Account], await self.request("GET", "/api/v1/accounts", options=options))

    async def authenticate(self, email: str | None = None, password: str | None = None, *, options: RequestOptions | None = None) -> AuthResponse:
        if email is None or password is None:
            raise InboxLayerValidationError("email and password are required")
        body = {"email": email, "password": password}
        response = await self.request("POST", "/api/v1/auth", json_data=body, options=options)
        if isinstance(response, dict) and "token" in response:
            self.api_token = response["token"]
            self._default_headers["Authorization"] = f"Bearer {response['token']}"
        return response

    async def post_auth(self, email: str, password: str, *, options: RequestOptions | None = None) -> AuthResponse:
        return await self.authenticate(email=email, password=password, options=options)

    async def delete_auth(self, *, options: RequestOptions | None = None) -> SuccessResponse:
        response = cast(SuccessResponse, await self.request("DELETE", "/api/v1/auth", options=options))
        self.api_token = None
        self._default_headers.pop("Authorization", None)
        return response

    async def logout(self, *, options: RequestOptions | None = None) -> SuccessResponse:
        return await self.delete_auth(options=options)

    async def get_me(self, *, options: RequestOptions | None = None) -> User:
        return cast(User, await self.request("GET", "/api/v1/me", options=options))

    async def patch_password(self, body: Mapping[str, Any] | PasswordInput | None = None, *, options: RequestOptions | None = None) -> SuccessResponse:
        return await self._simple_password_change("PATCH", body, options=options)

    async def put_password(self, body: Mapping[str, Any] | PasswordInput | None = None, *, options: RequestOptions | None = None) -> SuccessResponse:
        return await self._simple_password_change("PUT", body, options=options)

    async def replace_password(self, body: Mapping[str, Any] | PasswordInput | None = None, *, options: RequestOptions | None = None) -> SuccessResponse:
        return await self.put_password(body=body, options=options)

    async def _simple_password_change(
        self,
        method: str,
        body: Mapping[str, Any] | PasswordInput | None = None,
        *,
        options: RequestOptions | None = None,
    ) -> SuccessResponse:
        payload = _coerce_password_payload(body)
        return cast(
            SuccessResponse,
            await self.request(method, "/api/v1/password", json_data=payload, options=options),
        )

    async def list_inboxes(self, *, cursor: str | None = None, per_page: int | None = None, options: RequestOptions | None = None) -> InboxList:
        return cast(
            InboxList,
            await self.request(
                "GET",
                "/api/v1/inboxes",
                query={"cursor": cursor, "per_page": per_page},
                options=options,
            ),
        )

    async def create_inbox(self, payload: InboxCreate | Mapping[str, Any], *, options: RequestOptions | None = None) -> Inbox:
        return cast(Inbox, await self.request("POST", "/api/v1/inboxes", json_data=payload, options=options))

    async def get_inbox(self, inbox_id: str, *, cursor: str | None = None, labels: str | None = None, options: RequestOptions | None = None) -> InboxEmails:
        return cast(
            InboxEmails,
            await self.request(
                "GET",
                f"/api/v1/inboxes/{inbox_id}",
                query={"cursor": cursor, "labels": labels},
                options=options,
            ),
        )

    async def delete_inbox(self, inbox_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, await self.request("DELETE", f"/api/v1/inboxes/{inbox_id}", options=options))

    async def warmup_inbox(self, inbox_id: str, *, options: RequestOptions | None = None) -> WarmupStatus:
        return cast(
            WarmupStatus,
            await self.request("GET", f"/api/v1/inboxes/{inbox_id}/warmup", options=options),
        )

    async def list_drafts(self, *, options: RequestOptions | None = None) -> DraftCollection:
        return cast(DraftCollection, await self.request("GET", "/api/v1/drafts", options=options))

    async def create_draft(self, payload: DraftInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> Draft:
        return cast(Draft, await self.request("POST", "/api/v1/drafts", json_data=payload, options=options))

    async def get_draft(self, draft_id: str, *, options: RequestOptions | None = None) -> Draft:
        return cast(Draft, await self.request("GET", f"/api/v1/drafts/{draft_id}", options=options))

    async def update_draft(self, draft_id: str, payload: DraftInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> Draft:
        return cast(Draft, await self.request("PATCH", f"/api/v1/drafts/{draft_id}", json_data=payload, options=options))

    async def replace_draft(self, draft_id: str, payload: DraftInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> Draft:
        return cast(Draft, await self.request("PUT", f"/api/v1/drafts/{draft_id}", json_data=payload, options=options))

    async def delete_draft(self, draft_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, await self.request("DELETE", f"/api/v1/drafts/{draft_id}", options=options))

    async def send_draft(self, draft_id: str, *, options: RequestOptions | None = None) -> SendResult:
        return cast(
            SendResult,
            await self.request("POST", f"/api/v1/drafts/{draft_id}/send", options=options),
        )

    async def list_emails(self, *, inbox: str | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> EmailList:
        return cast(
            EmailList,
            await self.request("GET", "/api/v1/emails", query={"inbox": inbox, "cursor": cursor}, options=options),
        )

    async def create_email(self, payload: EmailSendInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> EmailSendResponse:
        return cast(EmailSendResponse, await self.request("POST", "/api/v1/emails", json_data=payload, options=options))

    async def patch_email(self, email_id: str, payload: EmailLabelPatch | Mapping[str, Any], *, options: RequestOptions | None = None) -> Email:
        return cast(Email, await self.request("PATCH", f"/api/v1/emails/{email_id}", json_data=payload, options=options))

    async def put_email(self, email_id: str, payload: EmailLabelPatch | Mapping[str, Any], *, options: RequestOptions | None = None) -> Email:
        return cast(Email, await self.request("PUT", f"/api/v1/emails/{email_id}", json_data=payload, options=options))

    async def apply_email_actions(
        self,
        email_id: str,
        action: EmailActionInput | EmailLabelPatch | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Email:
        return cast(
            Email,
            await self.request("PATCH", f"/api/v1/emails/{email_id}/actions", json_data=action, options=options),
        )

    async def reply_email(self, email_id: str, payload: Mapping[str, Any] | EmailSendInput, *, options: RequestOptions | None = None) -> SendResult:
        return cast(
            SendResult,
            await self.request("POST", f"/api/v1/emails/{email_id}/reply", json_data=payload, options=options),
        )

    async def forward_email(self, email_id: str, payload: Mapping[str, Any] | EmailSendInput, *, options: RequestOptions | None = None) -> SendResult:
        return cast(
            SendResult,
            await self.request("POST", f"/api/v1/emails/{email_id}/forward", json_data=payload, options=options),
        )

    async def send_email(self, payload: Mapping[str, Any] | EmailSendInput, *, options: RequestOptions | None = None) -> SendResult:
        return cast(SendResult, await self.request("POST", "/api/v1/emails/send", json_data=payload, options=options))

    async def search_emails(self, q: str, *, options: RequestOptions | None = None) -> EmailList:
        return cast(
            EmailList,
            await self.request("GET", "/api/v1/emails/search", query={"q": q}, options=options),
        )

    async def list_mailbox_labels(self, *, options: RequestOptions | None = None) -> MailboxLabelList:
        return cast(MailboxLabelList, await self.request("GET", "/api/v1/mailbox_labels", options=options))

    async def create_mailbox_label(self, payload: MailboxLabelInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> MailboxLabel:
        return cast(
            MailboxLabel,
            await self.request("POST", "/api/v1/mailbox_labels", json_data=payload, options=options),
        )

    async def update_mailbox_label(
        self,
        mailbox_label_id: str,
        payload: MailboxLabelInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> MailboxLabel:
        return cast(
            MailboxLabel,
            await self.request("PATCH", f"/api/v1/mailbox_labels/{mailbox_label_id}", json_data=payload, options=options),
        )

    async def replace_mailbox_label(
        self,
        mailbox_label_id: str,
        payload: MailboxLabelInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> MailboxLabel:
        return cast(
            MailboxLabel,
            await self.request("PUT", f"/api/v1/mailbox_labels/{mailbox_label_id}", json_data=payload, options=options),
        )

    async def delete_mailbox_label(self, mailbox_label_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, await self.request("DELETE", f"/api/v1/mailbox_labels/{mailbox_label_id}", options=options))

    async def create_notification_token(self, payload: Mapping[str, Any], *, options: RequestOptions | None = None) -> dict[str, Any]:
        return cast(dict[str, Any], await self.request("POST", "/api/v1/notification_tokens", json_data=payload, options=options))

    async def list_custom_domains(self, *, options: RequestOptions | None = None) -> list[CustomDomain]:
        return cast(list[CustomDomain], await self.request("GET", "/api/v1/custom_domains", options=options))

    async def create_custom_domain(self, payload: CustomDomainInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> CustomDomain:
        payload = _coerce_wrapper_payload(payload, "custom_domain")
        return cast(
            CustomDomain,
            await self.request("POST", "/api/v1/custom_domains", json_data=payload, options=options),
        )

    async def get_custom_domain(self, domain_id: str, *, options: RequestOptions | None = None) -> CustomDomain:
        return cast(
            CustomDomain,
            await self.request("GET", f"/api/v1/custom_domains/{domain_id}", options=options),
        )

    async def update_custom_domain(self, domain_id: str, payload: CustomDomainInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> CustomDomain:
        payload = _coerce_wrapper_payload(payload, "custom_domain")
        return cast(
            CustomDomain,
            await self.request("PATCH", f"/api/v1/custom_domains/{domain_id}", json_data=payload, options=options),
        )

    async def replace_custom_domain(self, domain_id: str, payload: CustomDomainInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> CustomDomain:
        payload = _coerce_wrapper_payload(payload, "custom_domain")
        return cast(
            CustomDomain,
            await self.request("PUT", f"/api/v1/custom_domains/{domain_id}", json_data=payload, options=options),
        )

    async def delete_custom_domain(self, domain_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, await self.request("DELETE", f"/api/v1/custom_domains/{domain_id}", options=options))

    async def verify_custom_domain(self, domain_id: str, *, options: RequestOptions | None = None) -> dict[str, Any]:
        return cast(dict[str, Any], await self.request("POST", f"/api/v1/custom_domains/{domain_id}/verify", options=options))

    async def list_webhook_subscriptions(self, *, options: RequestOptions | None = None) -> list[WebhookSubscription]:
        return cast(list[WebhookSubscription], await self.request("GET", "/api/v1/webhook_subscriptions", options=options))

    async def create_webhook_subscription(
        self,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        payload = _coerce_wrapper_payload(payload, "webhook_subscription")
        return cast(
            WebhookSubscription,
            await self.request(
                "POST",
                "/api/v1/webhook_subscriptions",
                json_data=payload,
                options=options,
            ),
        )

    async def get_webhook_subscription(self, webhook_id: str, *, options: RequestOptions | None = None) -> WebhookSubscription:
        return cast(
            WebhookSubscription,
            await self.request("GET", f"/api/v1/webhook_subscriptions/{webhook_id}", options=options),
        )

    async def update_webhook_subscription(
        self,
        webhook_id: str,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        payload = _coerce_wrapper_payload(payload, "webhook_subscription")
        return cast(
            WebhookSubscription,
            await self.request(
                "PATCH",
                f"/api/v1/webhook_subscriptions/{webhook_id}",
                json_data=payload,
                options=options,
            ),
        )

    async def replace_webhook_subscription(
        self,
        webhook_id: str,
        payload: WebhookSubscriptionInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> WebhookSubscription:
        payload = _coerce_wrapper_payload(payload, "webhook_subscription")
        return cast(
            WebhookSubscription,
            await self.request(
                "PUT",
                f"/api/v1/webhook_subscriptions/{webhook_id}",
                json_data=payload,
                options=options,
            ),
        )

    async def delete_webhook_subscription(self, webhook_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, await self.request("DELETE", f"/api/v1/webhook_subscriptions/{webhook_id}", options=options))

    async def test_webhook_subscription(self, webhook_id: str, *, options: RequestOptions | None = None) -> SuccessResponse:
        return cast(
            SuccessResponse,
            await self.request("POST", f"/api/v1/webhook_subscriptions/{webhook_id}/test", options=options),
        )

    async def list_threads(self, *, options: RequestOptions | None = None) -> EmailThreadList:
        return cast(
            EmailThreadList,
            await self.request("GET", "/api/v1/email_threads", options=options),
        )

    async def get_email_thread(self, thread_id: str, *, options: RequestOptions | None = None) -> EmailThread:
        return cast(
            EmailThread,
            await self.request("GET", f"/api/v1/email_threads/{thread_id}", options=options),
        )

    async def list_inbox_drafts(
        self,
        inbox_id: str,
        *,
        options: RequestOptions | None = None,
    ) -> DraftCollection:
        return cast(
            DraftCollection,
            await self.request(
                "GET",
                f"/api/v1/inboxes/{inbox_id}/drafts",
                options=options,
            ),
        )

    async def create_inbox_draft(self, inbox_id: str, payload: DraftInput | Mapping[str, Any], *, options: RequestOptions | None = None) -> Draft:
        return cast(
            Draft,
            await self.request(
                "POST",
                f"/api/v1/inboxes/{inbox_id}/drafts",
                json_data=payload,
                options=options,
            ),
        )

    async def get_inbox_draft(self, inbox_id: str, draft_id: str, *, options: RequestOptions | None = None) -> Draft:
        return cast(
            Draft,
            await self.request("GET", f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}", options=options),
        )

    async def update_inbox_draft(
        self,
        inbox_id: str,
        draft_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return cast(
            Draft,
            await self.request(
                "PATCH",
                f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}",
                json_data=payload,
                options=options,
            ),
        )

    async def replace_inbox_draft(
        self,
        inbox_id: str,
        draft_id: str,
        payload: DraftInput | Mapping[str, Any],
        *,
        options: RequestOptions | None = None,
    ) -> Draft:
        return cast(
            Draft,
            await self.request(
                "PUT",
                f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}",
                json_data=payload,
                options=options,
            ),
        )

    async def delete_inbox_draft(self, inbox_id: str, draft_id: str, *, options: RequestOptions | None = None) -> None:
        return cast(None, await self.request("DELETE", f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}", options=options))

    async def send_inbox_draft(self, inbox_id: str, draft_id: str, *, options: RequestOptions | None = None) -> SendResult:
        return cast(
            SendResult,
            await self.request("POST", f"/api/v1/inboxes/{inbox_id}/drafts/{draft_id}/send", options=options),
        )
