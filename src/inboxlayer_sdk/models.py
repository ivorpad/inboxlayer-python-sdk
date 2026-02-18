"""Typed request and response models generated from the OpenAPI contract."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InboxLayerModel(BaseModel):
    model_config = ConfigDict(extra="ignore", coerce_numbers_to_str=True)


class ErrorResponse(InboxLayerModel):
    error: str | None = None
    error_code: str | None = None


class SuccessResponse(InboxLayerModel):
    success: bool | None = None


class Account(InboxLayerModel):
    id: int | None = None
    name: str | None = None


class User(InboxLayerModel):
    id: int | None = None
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None


class AuthResponse(InboxLayerModel):
    token: str
    name: str | None = None
    expires_at: datetime | None = None


class Inbox(InboxLayerModel):
    id: str
    name: str
    email_address: str
    is_disabled: bool = False
    api_created: bool = False


class InboxCreate(InboxLayerModel):
    name: str
    custom_domain_id: str | None = None


class Email(InboxLayerModel):
    id: str | None = None
    from_address: str | None = None
    to_address: str | None = None
    subject: str | None = None
    labels: list[str] = Field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None


class EmailList(InboxLayerModel):
    emails: list[Email] = Field(default_factory=list)
    data: list[Email] = Field(default_factory=list)
    meta: dict[str, Any] | None = None


class EmailSendInput(InboxLayerModel):
    to: str | list[str]
    subject: str | None = None
    text_body: str | None = None
    html_body: str | None = None
    inbox_id: str | None = None
    message_type: str | None = None


class SendResult(InboxLayerModel):
    id: str | None = None
    message_id: str | None = None
    status: str | None = None
    provider_message_id: str | None = None


class EmailSendResponse(InboxLayerModel):
    message: str | None = None
    job: str | None = None


class EmailActionInput(InboxLayerModel):
    add_labels: list[str] | None = None
    remove_labels: list[str] | None = None
    labels: list[str] | None = None
    mark_read: bool | None = None
    move_to: str | None = None


class EmailLabelPatch(InboxLayerModel):
    add_labels: list[str] | None = None
    remove_labels: list[str] | None = None
    labels: list[str] | None = None


class Draft(InboxLayerModel):
    id: str | None = None
    inbox_id: str | None = None
    subject: str | None = None
    to: list[str] | str | None = None
    to_address: str | None = None
    status: str | None = None


class DraftCollection(InboxLayerModel):
    count: int | None = None
    drafts: list[Draft] = Field(default_factory=list)
    data: list[Draft] = Field(default_factory=list)


class DraftInput(InboxLayerModel):
    to: str | list[str] | None = None
    subject: str | None = None
    text_body: str | None = None
    html_body: str | None = None


class MailboxLabel(InboxLayerModel):
    id: str | None = None
    name: str | None = None
    slug: str | None = None
    color: str | None = None
    system: bool | None = None


class MailboxLabelList(InboxLayerModel):
    data: list[MailboxLabel] = Field(default_factory=list)


class MailboxLabelInput(InboxLayerModel):
    name: str | None = None
    slug: str | None = None
    color: str | None = None


class CustomDomain(InboxLayerModel):
    id: str | None = None
    domain: str | None = None
    verified_status: str | None = None
    dkim_host: str | None = None
    dkim_value: str | None = None


class CustomDomainInput(InboxLayerModel):
    class CustomDomainPayload(InboxLayerModel):
        domain: str
        dkim_host: str | None = None
        dkim_value: str | None = None
        spf_host: str | None = None
        spf_value: str | None = None

    custom_domain: CustomDomainPayload

    @model_validator(mode="before")
    @classmethod
    def _coerce_custom_domain(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            if "custom_domain" in value:
                return value
            if {"domain", "dkim_host", "dkim_value", "spf_host", "spf_value"} & value.keys():
                return {"custom_domain": value}
        return value


class PasswordCredentials(InboxLayerModel):
    current_password: str
    password: str
    password_confirmation: str


class PasswordInput(InboxLayerModel):
    """Payload for PATCH / PUT /api/v1/password."""

    user: PasswordCredentials

    @model_validator(mode="before")
    @classmethod
    def _coerce_user(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            if "user" in value:
                return value
            if {
                "current_password",
                "password",
                "password_confirmation",
            } <= value.keys():
                return {
                    "user": {
                        "current_password": value.get("current_password"),
                        "password": value.get("password"),
                        "password_confirmation": value.get("password_confirmation"),
                    }
                }
        return value


class WebhookSubscription(InboxLayerModel):
    id: str | None = None
    url: str | None = None
    events: list[str] = Field(default_factory=list)
    active: bool | None = None
    created_at: str | None = None


class WebhookSubscriptionInput(InboxLayerModel):
    class WebhookSubscriptionPayload(InboxLayerModel):
        url: str | None = None
        active: bool | None = None
        events: list[str] = Field(default_factory=list)

    webhook_subscription: WebhookSubscriptionPayload

    @model_validator(mode="before")
    @classmethod
    def _coerce_webhook_subscription(cls, value: Any) -> Any:
        if isinstance(value, Mapping):
            if "webhook_subscription" in value:
                return value
            if {"url", "active", "events"} & value.keys():
                return {"webhook_subscription": value}
        return value


class InboxList(InboxLayerModel):
    data: list[Inbox] = Field(default_factory=list)


class InboxEmails(InboxLayerModel):
    id: str | None = None
    name: str | None = None
    emails: list[Email] = Field(default_factory=list)
    data: list[Email] = Field(default_factory=list)


class WarmupStatus(InboxLayerModel):
    inbox_id: int | None = None
    warmup_started_at: datetime | None = None


class EmailThread(InboxLayerModel):
    id: str | None = None
    thread_id: str | None = None
    subject: str | None = None
    participants: list[str] = Field(default_factory=list)
    email_count: int | None = None


class EmailThreadList(InboxLayerModel):
    data: list[EmailThread] = Field(default_factory=list)
    meta: dict[str, Any] | None = None
