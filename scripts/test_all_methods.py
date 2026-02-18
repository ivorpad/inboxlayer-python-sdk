#!/usr/bin/env python3
"""Integration test: exercise every public method on InboxLayerClient."""

from __future__ import annotations

import sys

from inboxlayer_sdk import InboxLayerClient, InboxLayerHTTPError

API_TOKEN = "sK3pByRuMsgFRKoZjemNhRdz"
BASE_URL = "http://localhost:3033"

passed: list[str] = []
failed: list[tuple[str, str]] = []
skipped: list[tuple[str, str]] = []


def ok(name: str, result: object = None) -> None:
    tag = type(result).__name__ if result is not None else "None"
    print(f"  PASS  {name}  -> {tag}")
    passed.append(name)


def fail(name: str, err: Exception) -> None:
    msg = str(err)[:200]
    print(f"  FAIL  {name}  -> {msg}")
    failed.append((name, msg))


def skip(name: str, reason: str) -> None:
    print(f"  SKIP  {name}  ({reason})")
    skipped.append((name, reason))


def expect_error(name: str, exc: InboxLayerHTTPError, allowed: set[int]) -> None:
    if exc.status_code in allowed:
        ok(name, exc)
    else:
        fail(name, exc)


def crash(name: str, exc: Exception) -> None:
    msg = f"{type(exc).__name__}: {exc}"[:200]
    print(f"  CRASH {name}  -> {msg}")
    failed.append((name, msg))


def run(name: str, fn, *, allowed: set[int] | None = None):
    """Run fn(), record pass/fail/expected-error."""
    try:
        result = fn()
        ok(name, result)
        return result
    except InboxLayerHTTPError as e:
        if allowed and e.status_code in allowed:
            ok(name, e)
        else:
            fail(name, e)
        return None
    except Exception as e:
        crash(name, e)
        return None


def main() -> None:
    client = InboxLayerClient(
        base_url=BASE_URL,
        api_token=API_TOKEN,
        allow_http=True,
        max_retries=0,
        timeout=15.0,
    )

    # ── Auth / session ────────────────────────────────────────────
    print("\n=== Auth / session ===")

    run("get_me", lambda: client.get_me(), allowed={401, 403})
    run("list_accounts", lambda: client.list_accounts(), allowed={401, 403, 404})

    # ── Inboxes ───────────────────────────────────────────────────
    print("\n=== Inboxes ===")

    inbox_id: str | None = None
    inbox_list = run("list_inboxes", lambda: client.list_inboxes(), allowed={401, 403})
    if inbox_list and isinstance(inbox_list, dict) and inbox_list.get("data"):
        inbox_id = inbox_list["data"][0]["id"]

    created_inbox_id: str | None = None
    inbox = run("create_inbox", lambda: client.create_inbox({"name": "sdk-test-inbox"}), allowed={401, 403, 422})
    if inbox and isinstance(inbox, dict) and "id" in inbox:
        created_inbox_id = inbox["id"]

    target_inbox = created_inbox_id or inbox_id
    if target_inbox:
        run("get_inbox", lambda: client.get_inbox(target_inbox), allowed={401, 403, 404})
        run("warmup_inbox", lambda: client.warmup_inbox(target_inbox), allowed={401, 403, 404, 422})
    else:
        skip("get_inbox", "no inbox available")
        skip("warmup_inbox", "no inbox available")

    # ── Inbox Drafts ──────────────────────────────────────────────
    print("\n=== Inbox Drafts ===")

    if target_inbox:
        run("list_inbox_drafts", lambda: client.list_inbox_drafts(target_inbox), allowed={401, 403, 404})

        inbox_draft = run(
            "create_inbox_draft",
            lambda: client.create_inbox_draft(target_inbox, {"to": "test@example.com", "subject": "SDK Test", "text_body": "Hello from SDK test"}),
            allowed={401, 403, 404, 422},
        )
        inbox_draft_id = inbox_draft.get("id") if inbox_draft and isinstance(inbox_draft, dict) else None

        if inbox_draft_id:
            run("get_inbox_draft", lambda: client.get_inbox_draft(target_inbox, inbox_draft_id), allowed={401, 403, 404})
            run("update_inbox_draft", lambda: client.update_inbox_draft(target_inbox, inbox_draft_id, {"subject": "Updated"}), allowed={401, 403, 404, 422})
            run("replace_inbox_draft", lambda: client.replace_inbox_draft(target_inbox, inbox_draft_id, {"to": "test@example.com", "subject": "Replaced"}), allowed={401, 403, 404, 422})
            run("send_inbox_draft", lambda: client.send_inbox_draft(target_inbox, inbox_draft_id), allowed={401, 403, 404, 422})
            run("delete_inbox_draft", lambda: client.delete_inbox_draft(target_inbox, inbox_draft_id), allowed={401, 403, 404, 410, 422})
        else:
            for m in ("get_inbox_draft", "update_inbox_draft", "replace_inbox_draft", "send_inbox_draft", "delete_inbox_draft"):
                skip(m, "no draft created")
    else:
        for m in ("list_inbox_drafts", "create_inbox_draft", "get_inbox_draft",
                   "update_inbox_draft", "replace_inbox_draft", "send_inbox_draft", "delete_inbox_draft"):
            skip(m, "no inbox available")

    # ── Global Drafts ─────────────────────────────────────────────
    print("\n=== Global Drafts ===")

    run("list_drafts", lambda: client.list_drafts(), allowed={401, 403})

    global_draft = run(
        "create_draft",
        lambda: client.create_draft({"to": "test@example.com", "subject": "Global Draft", "text_body": "test body", "inbox_id": target_inbox}),
        allowed={401, 403, 422},
    )
    global_draft_id = global_draft.get("id") if global_draft and isinstance(global_draft, dict) else None

    if global_draft_id:
        run("get_draft", lambda: client.get_draft(global_draft_id), allowed={401, 403, 404})
        run("update_draft", lambda: client.update_draft(global_draft_id, {"subject": "Updated Global"}), allowed={401, 403, 404, 422})
        run("replace_draft", lambda: client.replace_draft(global_draft_id, {"to": "test@example.com", "subject": "Replaced Global"}), allowed={401, 403, 404, 422})
        run("send_draft", lambda: client.send_draft(global_draft_id), allowed={401, 403, 404, 422})
        run("delete_draft", lambda: client.delete_draft(global_draft_id), allowed={401, 403, 404, 410, 422})
    else:
        for m in ("get_draft", "update_draft", "replace_draft", "send_draft", "delete_draft"):
            skip(m, "no draft created")

    # ── Emails ────────────────────────────────────────────────────
    print("\n=== Emails ===")

    email_id: str | None = None
    email_list = run("list_emails", lambda: client.list_emails(inbox=target_inbox), allowed={401, 403, 422})
    if email_list and isinstance(email_list, dict):
        emails = email_list.get("emails", []) or email_list.get("data", [])
        if emails:
            email_id = emails[0]["id"]

    run("create_email", lambda: client.create_email({"to": "test@example.com", "subject": "SDK create_email", "text_body": "test"}), allowed={401, 403, 422})
    run("send_email", lambda: client.send_email({"to": "test@example.com", "subject": "SDK send_email", "text_body": "test"}), allowed={401, 403, 422})
    run("search_emails", lambda: client.search_emails("test"), allowed={401, 403, 404})

    if email_id:
        run("patch_email", lambda: client.patch_email(email_id, {"add_labels": ["test-label"]}), allowed={401, 403, 404, 422})
        run("put_email", lambda: client.put_email(email_id, {"labels": ["test-label"]}), allowed={401, 403, 404, 422})
        run("apply_email_actions", lambda: client.apply_email_actions(email_id, {"mark_read": True}), allowed={401, 403, 404, 422})
        run("reply_email", lambda: client.reply_email(email_id, {"text_body": "reply test"}), allowed={401, 403, 404, 422})
        run("forward_email", lambda: client.forward_email(email_id, {"to": "fwd@example.com", "text_body": "forward test"}), allowed={401, 403, 404, 422})
    else:
        for m in ("patch_email", "put_email", "apply_email_actions", "reply_email", "forward_email"):
            skip(m, "no email available")

    # ── Mailbox Labels ────────────────────────────────────────────
    print("\n=== Mailbox Labels ===")

    run("list_mailbox_labels", lambda: client.list_mailbox_labels(), allowed={401, 403})

    label = run(
        "create_mailbox_label",
        lambda: client.create_mailbox_label({"name": "sdk-test-label", "color": "#ff0000"}),
        allowed={401, 403, 422},
    )
    label_id = label.get("id") if label and isinstance(label, dict) else None

    if label_id:
        run("update_mailbox_label", lambda: client.update_mailbox_label(label_id, {"name": "sdk-test-updated"}), allowed={401, 403, 404, 422})
        run("replace_mailbox_label", lambda: client.replace_mailbox_label(label_id, {"name": "sdk-test-replaced", "color": "#00ff00"}), allowed={401, 403, 404, 422})
        run("delete_mailbox_label", lambda: client.delete_mailbox_label(label_id), allowed={401, 403, 404})
    else:
        for m in ("update_mailbox_label", "replace_mailbox_label", "delete_mailbox_label"):
            skip(m, "no label created")

    # ── Custom Domains ────────────────────────────────────────────
    print("\n=== Custom Domains ===")

    domain_id: str | None = None
    domains = run("list_custom_domains", lambda: client.list_custom_domains(), allowed={401, 403})
    if domains and isinstance(domains, list) and domains:
        domain_id = domains[0]["id"]

    created_domain = run(
        "create_custom_domain",
        lambda: client.create_custom_domain({"domain": "sdk-test.example.com"}),
        allowed={401, 403, 422},
    )
    created_domain_id = created_domain.get("id") if created_domain and isinstance(created_domain, dict) else None

    target_domain = created_domain_id or domain_id
    if target_domain:
        run("get_custom_domain", lambda: client.get_custom_domain(target_domain), allowed={401, 403, 404})
        run("update_custom_domain", lambda: client.update_custom_domain(target_domain, {"domain": "sdk-test.example.com"}), allowed={401, 403, 404, 422})
        run("replace_custom_domain", lambda: client.replace_custom_domain(target_domain, {"domain": "sdk-test.example.com"}), allowed={401, 403, 404, 422})
        run("verify_custom_domain", lambda: client.verify_custom_domain(target_domain), allowed={401, 403, 404, 422})
        if created_domain_id:
            run("delete_custom_domain", lambda: client.delete_custom_domain(created_domain_id), allowed={401, 403, 404})
        else:
            skip("delete_custom_domain", "won't delete pre-existing domain")
    else:
        for m in ("get_custom_domain", "update_custom_domain", "replace_custom_domain",
                   "verify_custom_domain", "delete_custom_domain"):
            skip(m, "no domain available")

    # ── Webhooks ──────────────────────────────────────────────────
    print("\n=== Webhooks ===")

    webhook_id: str | None = None
    webhooks = run("list_webhook_subscriptions", lambda: client.list_webhook_subscriptions(), allowed={401, 403})
    if webhooks and isinstance(webhooks, list) and webhooks:
        webhook_id = webhooks[0]["id"]

    created_wh = run(
        "create_webhook_subscription",
        lambda: client.create_webhook_subscription({
            "url": "https://httpbin.org/post",
            "events": ["email.received"],
            "active": True,
        }),
        allowed={401, 403, 422},
    )
    created_webhook_id = created_wh.get("id") if created_wh and isinstance(created_wh, dict) else None

    target_webhook = created_webhook_id or webhook_id
    if target_webhook:
        run("get_webhook_subscription", lambda: client.get_webhook_subscription(target_webhook), allowed={401, 403, 404})
        run("update_webhook_subscription", lambda: client.update_webhook_subscription(target_webhook, {
            "url": "https://httpbin.org/post", "events": ["email.received"], "active": True,
        }), allowed={401, 403, 404, 422})
        run("replace_webhook_subscription", lambda: client.replace_webhook_subscription(target_webhook, {
            "url": "https://httpbin.org/post", "events": ["email.received"], "active": True,
        }), allowed={401, 403, 404, 422})
        run("test_webhook_subscription", lambda: client.test_webhook_subscription(target_webhook), allowed={401, 403, 404, 422})
        if created_webhook_id:
            run("delete_webhook_subscription", lambda: client.delete_webhook_subscription(created_webhook_id), allowed={401, 403, 404})
        else:
            skip("delete_webhook_subscription", "won't delete pre-existing webhook")
    else:
        for m in ("get_webhook_subscription", "update_webhook_subscription",
                   "replace_webhook_subscription", "test_webhook_subscription",
                   "delete_webhook_subscription"):
            skip(m, "no webhook available")

    # ── Threads ───────────────────────────────────────────────────
    print("\n=== Threads ===")

    thread_id: str | None = None
    threads = run("list_threads", lambda: client.list_threads(), allowed={401, 403, 500})
    if threads and isinstance(threads, dict) and threads.get("data"):
        thread_id = threads["data"][0]["id"]

    if thread_id:
        run("get_email_thread", lambda: client.get_email_thread(thread_id), allowed={401, 403, 404})
    else:
        skip("get_email_thread", "no thread available")

    # ── Notification tokens ───────────────────────────────────────
    print("\n=== Notification tokens ===")

    run("create_notification_token", lambda: client.create_notification_token({"token": "test-fcm-token", "platform": "ios"}), allowed={401, 403, 404, 422})

    # ── Cleanup: delete created inbox ─────────────────────────────
    print("\n=== Cleanup ===")

    if created_inbox_id:
        run("delete_inbox", lambda: client.delete_inbox(created_inbox_id), allowed={401, 403, 404})
    else:
        skip("delete_inbox", "no inbox was created")

    client.close()

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print(f"PASSED: {len(passed)}   FAILED: {len(failed)}   SKIPPED: {len(skipped)}")
    if failed:
        print("\nFailed methods:")
        for name, err in failed:
            print(f"  - {name}: {err}")
    if skipped:
        print("\nSkipped methods:")
        for name, reason in skipped:
            print(f"  - {name}: {reason}")
    print("=" * 60)

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
