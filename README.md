# Inbox Layer Python SDK

This package provides both synchronous and asynchronous clients for the Inbox Layer API.

## Install

```bash
pip install inboxlayer-python-sdk
```

## Quick start

```python
from inboxlayer_sdk import InboxLayerClient

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

All responses are plain dicts (typed as `TypedDict`), so use bracket access:

```python
auth = client.authenticate(email="user@example.com", password="secret")
print(auth["token"])
```

## Client initialization

- `InboxLayerClient(api_token=None, allow_http=False, ...)` for synchronous calls.
- `AsyncInboxLayerClient(...)` for asynchronous calls.
- Default base URL is `https://inboxlayer.dev`.
- `allow_http=True` is required when calling local servers over `http://`.
- `authenticate()` can be used without an initial token; it stores the returned token on the client automatically.

```python
from inboxlayer_sdk import InboxLayerClient

client = InboxLayerClient(base_url="http://localhost:3033", allow_http=True)
auth = client.authenticate(email="user@example.com", password="secret")
print(auth["token"])
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

- `authenticate(email, password, *, options) -> AuthResponse`
- `post_auth(email, password, *, options) -> AuthResponse`
- `delete_auth(*, options) -> SuccessResponse`
- `logout(*, options) -> SuccessResponse`

### Account and session context

- `get_me(*, options) -> User`

### Password

- `patch_password(body: PasswordInput | PasswordCredentials | None, *, options) -> SuccessResponse`
- `put_password(body: PasswordInput | PasswordCredentials | None, *, options) -> SuccessResponse`
- `replace_password(body: PasswordInput | PasswordCredentials | None, *, options) -> SuccessResponse`

### Accounts

- `list_accounts(*, options) -> list[Account]`

### Inboxes

- `list_inboxes(*, cursor, per_page, options) -> InboxList`
- `create_inbox(payload: InboxCreate, *, options) -> Inbox`
- `get_inbox(inbox_id, *, cursor, labels, options) -> InboxEmails`
- `delete_inbox(inbox_id, *, options) -> None`
- `warmup_inbox(inbox_id, *, options) -> WarmupStatus`
- `stream_inbox_events(inbox_id, *, timeout, since, options) -> Iterator[SSEEvent] | AsyncIterator[SSEEvent]`

### Drafts

- `list_inbox_drafts(inbox_id, *, options) -> DraftCollection`
- `create_inbox_draft(inbox_id, payload: DraftInput, *, options) -> Draft`
- `get_inbox_draft(inbox_id, draft_id, *, options) -> Draft`
- `update_inbox_draft(inbox_id, draft_id, payload: DraftInput, *, options) -> Draft`
- `replace_inbox_draft(inbox_id, draft_id, payload: DraftInput, *, options) -> Draft`
- `delete_inbox_draft(inbox_id, draft_id, *, options) -> None`
- `send_inbox_draft(inbox_id, draft_id, *, options) -> SendResult`
- `list_drafts(*, options) -> DraftCollection`
- `create_draft(payload: DraftInput, *, options) -> Draft`
- `get_draft(draft_id, *, options) -> Draft`
- `update_draft(draft_id, payload: DraftInput, *, options) -> Draft`
- `replace_draft(draft_id, payload: DraftInput, *, options) -> Draft`
- `delete_draft(draft_id, *, options) -> None`
- `send_draft(draft_id, *, options) -> SendResult`

### Emails

- `list_emails(*, inbox, cursor, options) -> EmailList`
- `create_email(payload: EmailSendInput, *, options) -> EmailSendResponse`
- `patch_email(email_id, payload: EmailLabelPatch, *, options) -> Email`
- `put_email(email_id, payload: EmailLabelPatch, *, options) -> Email`
- `apply_email_actions(email_id, action: EmailActionInput | EmailLabelPatch, *, options) -> Email`
- `reply_email(email_id, payload: EmailSendInput, *, options) -> SendResult`
- `forward_email(email_id, payload: EmailSendInput, *, options) -> SendResult`
- `send_email(payload: EmailSendInput, *, options) -> SendResult`
- `search_emails(q, *, options) -> EmailList`

### Mailbox labels

- `list_mailbox_labels(*, options) -> MailboxLabelList`
- `create_mailbox_label(payload: MailboxLabelInput, *, options) -> MailboxLabel`
- `update_mailbox_label(mailbox_label_id, payload: MailboxLabelInput, *, options) -> MailboxLabel`
- `replace_mailbox_label(mailbox_label_id, payload: MailboxLabelInput, *, options) -> MailboxLabel`
- `delete_mailbox_label(mailbox_label_id, *, options) -> None`

### Utilities and integration

- `create_notification_token(payload: NotificationTokenInput, *, options) -> SuccessResponse`

### Custom domains

- `list_custom_domains(*, options) -> list[CustomDomain]`
- `create_custom_domain(payload: CustomDomainInput | CustomDomainPayload, *, options) -> CustomDomain`
- `get_custom_domain(domain_id, *, options) -> CustomDomain`
- `update_custom_domain(domain_id, payload: CustomDomainInput | CustomDomainPayload, *, options) -> CustomDomain`
- `replace_custom_domain(domain_id, payload: CustomDomainInput | CustomDomainPayload, *, options) -> CustomDomain`
- `delete_custom_domain(domain_id, *, options) -> None`
- `verify_custom_domain(domain_id, *, options) -> CustomDomain`

### Webhooks

- `list_webhook_subscriptions(*, options) -> list[WebhookSubscription]`
- `create_webhook_subscription(payload: WebhookSubscriptionInput | WebhookSubscriptionPayload, *, options) -> WebhookSubscription`
- `get_webhook_subscription(webhook_id, *, options) -> WebhookSubscription`
- `update_webhook_subscription(webhook_id, payload: WebhookSubscriptionInput | WebhookSubscriptionPayload, *, options) -> WebhookSubscription`
- `replace_webhook_subscription(webhook_id, payload: WebhookSubscriptionInput | WebhookSubscriptionPayload, *, options) -> WebhookSubscription`
- `delete_webhook_subscription(webhook_id, *, options) -> None`
- `test_webhook_subscription(webhook_id, *, options) -> SuccessResponse`

### Thread endpoints

- `list_threads(*, options) -> EmailThreadList`
- `get_email_thread(thread_id, *, options) -> EmailThread`

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
