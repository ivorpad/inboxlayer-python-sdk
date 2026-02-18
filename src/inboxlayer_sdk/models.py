"""Typed request and response models generated from the OpenAPI contract."""

from __future__ import annotations

from typing import Any, NotRequired, TypedDict


# ── Response types ────────────────────────────────────────────

class AuthResponse(TypedDict):
    token: str
    name: NotRequired[str]
    expires_at: NotRequired[str | None]


class User(TypedDict):
    id: NotRequired[int]
    email: NotRequired[str]
    first_name: NotRequired[str]
    last_name: NotRequired[str]


class Account(TypedDict):
    id: NotRequired[int]
    name: NotRequired[str]


class Inbox(TypedDict):
    id: NotRequired[str]
    name: NotRequired[str]
    email_address: NotRequired[str]
    is_disabled: NotRequired[bool]
    api_created: NotRequired[bool]


class Email(TypedDict):
    id: NotRequired[str]
    from_address: NotRequired[str]
    to_address: NotRequired[str]
    subject: NotRequired[str]
    labels: NotRequired[list[str]]
    created_at: NotRequired[str]
    updated_at: NotRequired[str]


class Draft(TypedDict):
    id: NotRequired[str]
    inbox_id: NotRequired[str]
    subject: NotRequired[str]
    to: NotRequired[list[str]]
    to_address: NotRequired[str]
    status: NotRequired[str]


class SendResult(TypedDict):
    id: NotRequired[str]
    message_id: NotRequired[str]
    status: NotRequired[str]
    provider_message_id: NotRequired[str]


class MailboxLabel(TypedDict):
    id: NotRequired[str]
    name: NotRequired[str]
    slug: NotRequired[str]
    color: NotRequired[str]
    system: NotRequired[bool]


class CustomDomain(TypedDict):
    id: NotRequired[str]
    domain: NotRequired[str]
    verified_status: NotRequired[str]
    dkim_host: NotRequired[str]
    dkim_value: NotRequired[str]


class WebhookSubscription(TypedDict):
    id: NotRequired[str]
    url: NotRequired[str]
    events: NotRequired[list[str]]
    active: NotRequired[bool]
    created_at: NotRequired[str]


class EmailThread(TypedDict):
    id: NotRequired[str]
    thread_id: NotRequired[str]
    subject: NotRequired[str]
    participants: NotRequired[list[str]]
    email_count: NotRequired[int]


class WarmupStatus(TypedDict):
    inbox_id: NotRequired[int]
    warmup_started_at: NotRequired[str | None]


class ErrorResponse(TypedDict):
    error: NotRequired[str]
    error_code: NotRequired[str]


class SuccessResponse(TypedDict):
    success: NotRequired[bool]


# ── Collection / list wrappers ────────────────────────────────

class InboxList(TypedDict):
    data: NotRequired[list[Inbox]]


class InboxEmails(TypedDict):
    id: NotRequired[str]
    name: NotRequired[str]
    emails: NotRequired[list[Email]]
    data: NotRequired[list[Email]]


class EmailList(TypedDict):
    emails: NotRequired[list[Email]]
    data: NotRequired[list[Email]]
    meta: NotRequired[dict[str, Any]]


class DraftCollection(TypedDict):
    count: NotRequired[int]
    drafts: NotRequired[list[Draft]]
    data: NotRequired[list[Draft]]


class MailboxLabelList(TypedDict):
    data: NotRequired[list[MailboxLabel]]


class EmailThreadList(TypedDict):
    data: NotRequired[list[EmailThread]]
    meta: NotRequired[dict[str, Any]]


class EmailSendResponse(TypedDict):
    message: NotRequired[str]
    job: NotRequired[str]


# ── Input types ───────────────────────────────────────────────

class InboxCreate(TypedDict, total=False):
    name: str
    custom_domain_id: str


class DraftInput(TypedDict, total=False):
    to: str | list[str]
    subject: str
    text_body: str
    html_body: str


class EmailSendInput(TypedDict, total=False):
    to: str | list[str]
    subject: str
    text_body: str
    html_body: str
    inbox_id: str
    message_type: str


class EmailLabelPatch(TypedDict, total=False):
    add_labels: list[str]
    remove_labels: list[str]
    labels: list[str]


class EmailActionInput(TypedDict, total=False):
    add_labels: list[str]
    remove_labels: list[str]
    labels: list[str]
    mark_read: bool
    move_to: str


class MailboxLabelInput(TypedDict, total=False):
    name: str
    slug: str
    color: str


class CustomDomainPayload(TypedDict, total=False):
    domain: str
    dkim_host: str
    dkim_value: str
    spf_host: str
    spf_value: str


class CustomDomainInput(TypedDict):
    custom_domain: CustomDomainPayload


class WebhookSubscriptionPayload(TypedDict, total=False):
    url: str
    active: bool
    events: list[str]


class WebhookSubscriptionInput(TypedDict):
    webhook_subscription: WebhookSubscriptionPayload


class PasswordCredentials(TypedDict):
    current_password: str
    password: str
    password_confirmation: str


class PasswordInput(TypedDict):
    user: PasswordCredentials
