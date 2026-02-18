# API Reference

Both `InboxLayerClient` and `AsyncInboxLayerClient` expose the same methods. Async methods return awaitables.

## Auth

- `authenticate(email, password, *, options) -> AuthResponse`
- `post_auth(email, password, *, options) -> AuthResponse`
- `delete_auth(*, options) -> SuccessResponse`
- `logout(*, options) -> SuccessResponse`

## Account

- `get_me(*, options) -> User`
- `list_accounts(*, options) -> list[Account]`

## Password

- `patch_password(body, *, options) -> SuccessResponse`
- `put_password(body, *, options) -> SuccessResponse`
- `replace_password(body, *, options) -> SuccessResponse`

## Inboxes

- `list_inboxes(*, cursor, per_page, options) -> InboxList`
- `create_inbox(payload, *, options) -> Inbox`
- `get_inbox(inbox_id, *, cursor, labels, options) -> InboxEmails`
- `delete_inbox(inbox_id, *, options) -> None`
- `warmup_inbox(inbox_id, *, options) -> WarmupStatus`
- `stream_inbox_events(inbox_id, *, timeout, since, options) -> Iterator[SSEEvent]`

## Drafts (inbox-scoped)

- `list_inbox_drafts(inbox_id, *, options) -> DraftCollection`
- `create_inbox_draft(inbox_id, payload, *, options) -> Draft`
- `get_inbox_draft(inbox_id, draft_id, *, options) -> Draft`
- `update_inbox_draft(inbox_id, draft_id, payload, *, options) -> Draft`
- `replace_inbox_draft(inbox_id, draft_id, payload, *, options) -> Draft`
- `delete_inbox_draft(inbox_id, draft_id, *, options) -> None`
- `send_inbox_draft(inbox_id, draft_id, *, options) -> SendResult`

## Drafts (global)

- `list_drafts(*, options) -> DraftCollection`
- `create_draft(payload, *, options) -> Draft`
- `get_draft(draft_id, *, options) -> Draft`
- `update_draft(draft_id, payload, *, options) -> Draft`
- `replace_draft(draft_id, payload, *, options) -> Draft`
- `delete_draft(draft_id, *, options) -> None`
- `send_draft(draft_id, *, options) -> SendResult`

## Emails

- `list_emails(*, inbox, cursor, options) -> EmailList`
- `create_email(payload, *, options) -> EmailSendResponse`
- `send_email(payload, *, options) -> SendResult`
- `search_emails(q, *, options) -> EmailList`
- `patch_email(email_id, payload, *, options) -> Email`
- `put_email(email_id, payload, *, options) -> Email`
- `apply_email_actions(email_id, action, *, options) -> Email`
- `reply_email(email_id, payload, *, options) -> SendResult`
- `forward_email(email_id, payload, *, options) -> SendResult`

## Threads

- `list_threads(*, options) -> EmailThreadList`
- `get_email_thread(thread_id, *, options) -> EmailThread`

## Mailbox Labels

- `list_mailbox_labels(*, options) -> MailboxLabelList`
- `create_mailbox_label(payload, *, options) -> MailboxLabel`
- `update_mailbox_label(mailbox_label_id, payload, *, options) -> MailboxLabel`
- `replace_mailbox_label(mailbox_label_id, payload, *, options) -> MailboxLabel`
- `delete_mailbox_label(mailbox_label_id, *, options) -> None`

## Custom Domains

- `list_custom_domains(*, options) -> list[CustomDomain]`
- `create_custom_domain(payload, *, options) -> CustomDomain`
- `get_custom_domain(domain_id, *, options) -> CustomDomain`
- `update_custom_domain(domain_id, payload, *, options) -> CustomDomain`
- `replace_custom_domain(domain_id, payload, *, options) -> CustomDomain`
- `delete_custom_domain(domain_id, *, options) -> None`
- `verify_custom_domain(domain_id, *, options) -> CustomDomain`

## Webhooks

- `list_webhook_subscriptions(*, options) -> list[WebhookSubscription]`
- `create_webhook_subscription(payload, *, options) -> WebhookSubscription`
- `get_webhook_subscription(webhook_id, *, options) -> WebhookSubscription`
- `update_webhook_subscription(webhook_id, payload, *, options) -> WebhookSubscription`
- `replace_webhook_subscription(webhook_id, payload, *, options) -> WebhookSubscription`
- `delete_webhook_subscription(webhook_id, *, options) -> None`
- `test_webhook_subscription(webhook_id, *, options) -> SuccessResponse`

## Utilities

- `create_notification_token(payload, *, options) -> SuccessResponse`

## Client Helpers

- `request(...)` - Low-level HTTP request method
- `close()` / `aclose()` - Cleanup
- Context managers: `with InboxLayerClient(...) as client:` / `async with AsyncInboxLayerClient(...) as client:`
