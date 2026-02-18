# Inbox Layer Python SDK

This package provides both synchronous and asynchronous clients for the Inbox Layer API.

## Install

```bash
pip install inboxlayer-python-sdk
```

## Quick start

```python
from inboxlayer_sdk import AsyncInboxLayerClient, InboxLayerClient

client = InboxLayerClient(api_token="...")  # sync

me = client.get_me()
accounts = client.list_accounts()
```

```python
import asyncio
from inboxlayer_sdk import AsyncInboxLayerClient

async def main() -> None:
    async with AsyncInboxLayerClient(api_token="...") as client:
        inboxes = await client.list_inboxes()
        async for event in client.stream_inbox_events("inbox_id"):
            print(event.event, event.data)

asyncio.run(main())
```

## Client initialization

- `InboxLayerClient(api_token=None, allow_http=False, ...)` for synchronous calls.
- `AsyncInboxLayerClient(...)` for asynchronous calls.
- `allow_http=True` is required when calling local servers over `http://`.
- `authenticate()` can be used without an initial token; it stores the returned token on the client automatically.

```python
from inboxlayer_sdk import InboxLayerClient

client = InboxLayerClient(base_url="http://localhost:3033", allow_http=True)
auth = client.authenticate(email="user@example.com", password="secret")
print(auth.token)
```

`post_auth` is a convenience alias for `authenticate`.

## CLI

```bash
inboxlayer-check-contract
```

Validates the shipped endpoint map against the embedded OpenAPI document.

## All public methods (both clients)

Both `InboxLayerClient` and `AsyncInboxLayerClient` expose the same public methods.

### Auth

- `authenticate(email: str | None = None, password: str | None = None, options: RequestOptions | None = None) -> AuthResponse`
- `post_auth(email: str, password: str, options: RequestOptions | None = None) -> AuthResponse`
- `delete_auth(options: RequestOptions | None = None) -> SuccessResponse`
- `logout(options: RequestOptions | None = None) -> SuccessResponse`

### Account and session context

- `get_me(options: RequestOptions | None = None) -> User`

### Password

- `patch_password(body: Mapping[str, Any] | PasswordInput | None = None, options: RequestOptions | None = None) -> SuccessResponse`
- `put_password(body: Mapping[str, Any] | PasswordInput | None = None, options: RequestOptions | None = None) -> SuccessResponse`
- `replace_password(body: Mapping[str, Any] | PasswordInput | None = None, options: RequestOptions | None = None) -> SuccessResponse`

### Accounts

- `list_accounts(options: RequestOptions | None = None) -> list[Account]`

### Inboxes

- `list_inboxes(cursor: str | None = None, per_page: int | None = None, options: RequestOptions | None = None) -> InboxList`
- `create_inbox(payload: InboxCreate | Mapping[str, Any], options: RequestOptions | None = None) -> Inbox`
- `get_inbox(inbox_id: str, cursor: str | None = None, labels: str | None = None, options: RequestOptions | None = None) -> InboxEmails`
- `delete_inbox(inbox_id: str, options: RequestOptions | None = None) -> None`
- `warmup_inbox(inbox_id: str, options: RequestOptions | None = None) -> WarmupStatus`
- `stream_inbox_events(inbox_id: str, timeout: int | None = None, since: str | datetime | None = None, options: RequestOptions | None = None) -> Iterator[SSEEvent] | AsyncIterator[SSEEvent]`

### Drafts

- `list_inbox_drafts(inbox_id: str, options: RequestOptions | None = None) -> DraftCollection`
- `create_inbox_draft(inbox_id: str, payload: DraftInput | Mapping[str, Any], options: RequestOptions | None = None) -> Draft`
- `get_inbox_draft(inbox_id: str, draft_id: str, options: RequestOptions | None = None) -> Draft`
- `update_inbox_draft(inbox_id: str, draft_id: str, payload: DraftInput | Mapping[str, Any], options: RequestOptions | None = None) -> Draft`
- `replace_inbox_draft(inbox_id: str, draft_id: str, payload: DraftInput | Mapping[str, Any], options: RequestOptions | None = None) -> Draft`
- `delete_inbox_draft(inbox_id: str, draft_id: str, options: RequestOptions | None = None) -> None`
- `send_inbox_draft(inbox_id: str, draft_id: str, options: RequestOptions | None = None) -> SendResult`
- `list_drafts(options: RequestOptions | None = None) -> DraftCollection`
- `create_draft(payload: DraftInput | Mapping[str, Any], options: RequestOptions | None = None) -> Draft`
- `get_draft(draft_id: str, options: RequestOptions | None = None) -> Draft`
- `update_draft(draft_id: str, payload: DraftInput | Mapping[str, Any], options: RequestOptions | None = None) -> Draft`
- `replace_draft(draft_id: str, payload: DraftInput | Mapping[str, Any], options: RequestOptions | None = None) -> Draft`
- `delete_draft(draft_id: str, options: RequestOptions | None = None) -> None`
- `send_draft(draft_id: str, options: RequestOptions | None = None) -> SendResult`

### Emails

- `list_emails(inbox: str | None = None, cursor: str | None = None, options: RequestOptions | None = None) -> EmailList`
- `create_email(payload: EmailSendInput | Mapping[str, Any], options: RequestOptions | None = None) -> EmailSendResponse`
- `patch_email(email_id: str, payload: EmailLabelPatch | Mapping[str, Any], options: RequestOptions | None = None) -> Email`
- `put_email(email_id: str, payload: EmailLabelPatch | Mapping[str, Any], options: RequestOptions | None = None) -> Email`
- `apply_email_actions(email_id: str, action: EmailActionInput | EmailLabelPatch | Mapping[str, Any], options: RequestOptions | None = None) -> Email`
- `reply_email(email_id: str, payload: Mapping[str, Any] | EmailSendInput, options: RequestOptions | None = None) -> SendResult`
- `forward_email(email_id: str, payload: Mapping[str, Any] | EmailSendInput, options: RequestOptions | None = None) -> SendResult`
- `send_email(payload: Mapping[str, Any] | EmailSendInput, options: RequestOptions | None = None) -> SendResult`
- `search_emails(q: str, options: RequestOptions | None = None) -> EmailList`

### Mailbox labels

- `list_mailbox_labels(options: RequestOptions | None = None) -> MailboxLabelList`
- `create_mailbox_label(payload: MailboxLabelInput | Mapping[str, Any], options: RequestOptions | None = None) -> MailboxLabel`
- `update_mailbox_label(mailbox_label_id: str, payload: MailboxLabelInput | Mapping[str, Any], options: RequestOptions | None = None) -> MailboxLabel`
- `replace_mailbox_label(mailbox_label_id: str, payload: MailboxLabelInput | Mapping[str, Any], options: RequestOptions | None = None) -> MailboxLabel`
- `delete_mailbox_label(mailbox_label_id: str, options: RequestOptions | None = None) -> None`

### Utilities and integration

- `create_notification_token(payload: Mapping[str, Any], options: RequestOptions | None = None) -> dict[str, Any]`

### Custom domains

- `list_custom_domains(options: RequestOptions | None = None) -> list[CustomDomain]`
- `create_custom_domain(payload: CustomDomainInput | Mapping[str, Any], options: RequestOptions | None = None) -> CustomDomain`
- `get_custom_domain(domain_id: str, options: RequestOptions | None = None) -> CustomDomain`
- `update_custom_domain(domain_id: str, payload: CustomDomainInput | Mapping[str, Any], options: RequestOptions | None = None) -> CustomDomain`
- `replace_custom_domain(domain_id: str, payload: CustomDomainInput | Mapping[str, Any], options: RequestOptions | None = None) -> CustomDomain`
- `delete_custom_domain(domain_id: str, options: RequestOptions | None = None) -> None`
- `verify_custom_domain(domain_id: str, options: RequestOptions | None = None) -> dict[str, Any]`

### Webhooks

- `list_webhook_subscriptions(options: RequestOptions | None = None) -> list[WebhookSubscription]`
- `create_webhook_subscription(payload: WebhookSubscriptionInput | Mapping[str, Any], options: RequestOptions | None = None) -> WebhookSubscription`
- `get_webhook_subscription(webhook_id: str, options: RequestOptions | None = None) -> WebhookSubscription`
- `update_webhook_subscription(webhook_id: str, payload: WebhookSubscriptionInput | Mapping[str, Any], options: RequestOptions | None = None) -> WebhookSubscription`
- `replace_webhook_subscription(webhook_id: str, payload: WebhookSubscriptionInput | Mapping[str, Any], options: RequestOptions | None = None) -> WebhookSubscription`
- `delete_webhook_subscription(webhook_id: str, options: RequestOptions | None = None) -> None`
- `test_webhook_subscription(webhook_id: str, options: RequestOptions | None = None) -> SuccessResponse`

### Thread endpoints

- `list_threads(options: RequestOptions | None = None) -> EmailThreadList`
- `get_email_thread(thread_id: str, options: RequestOptions | None = None) -> EmailThread`

### Client-level helpers

- `request(...)`: shared low-level request helper
- `close() -> None`: sync client cleanup
- `aclose() -> None`: async client cleanup
- Sync context manager: `__enter__`, `__exit__`, and `with client:`
- Async context manager: `__aenter__`, `__aexit__`, and `async with client:`

## Error types

- `InboxLayerError`
- `InboxLayerValidationError`
- `InboxLayerAuthError`
- `InboxLayerRateLimitError`
- `InboxLayerTimeoutError`
- `InboxLayerNetworkError`
- `InboxLayerHTTPError`
