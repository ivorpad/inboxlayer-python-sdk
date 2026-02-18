# Inbox Layer Python SDK

[![pypi](https://img.shields.io/pypi/v/inboxlayer-sdk)](https://pypi.python.org/pypi/inboxlayer-sdk)

The Inbox Layer Python SDK provides convenient access to the [Inbox Layer](https://inboxlayer.dev) API from Python.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Async Client](#async-client)
- [Streaming](#streaming)
- [Exception Handling](#exception-handling)
- [Webhook Verification](#webhook-verification)
- [Advanced](#advanced)
  - [Request Options](#request-options)
  - [Retries](#retries)
  - [Timeouts](#timeouts)
  - [Custom HTTP Client](#custom-http-client)
- [Reference](#reference)

## Installation

Requires Python 3.10+.

```sh
pip install inboxlayer-sdk
```

## Usage

```python
from inboxlayer_sdk import InboxLayerClient

client = InboxLayerClient(api_token="YOUR_API_TOKEN")

# List inboxes
inboxes = client.list_inboxes()
for inbox in inboxes["data"]:
    print(inbox["email_address"])

# Send an email
client.send_email({
    "to": "recipient@example.com",
    "subject": "Hello",
    "text_body": "Sent from Inbox Layer",
})
```

All responses are plain dicts typed with `TypedDict`, so use bracket access:

```python
me = client.get_me()
print(me["email"])
```

The API token can also be set via the `INBOX_LAYER_API_TOKEN` environment variable:

```python
# Reads token from INBOX_LAYER_API_TOKEN
client = InboxLayerClient()
```

## Async Client

The SDK exports an async client with the same interface:

```python
import asyncio
from inboxlayer_sdk import AsyncInboxLayerClient

async def main() -> None:
    async with AsyncInboxLayerClient(api_token="YOUR_API_TOKEN") as client:
        inboxes = await client.list_inboxes()
        email = await client.send_email({
            "to": "recipient@example.com",
            "subject": "Hello from async",
            "text_body": "Sent asynchronously",
        })

asyncio.run(main())
```

## Streaming

Listen for real-time inbox events using Server-Sent Events:

```python
# Sync
for event in client.stream_inbox_events("inbox_id"):
    print(event.event, event.json())
```

```python
# Async
async for event in client.stream_inbox_events("inbox_id"):
    print(event.event, event.json())
```

Each `SSEEvent` has `event`, `data`, `id`, and `retry` fields, plus a `.json()` helper to parse `data` as JSON.

## Exception Handling

When the API returns a non-success status code, a typed exception is raised:

```python
from inboxlayer_sdk import InboxLayerClient, InboxLayerHTTPError, InboxLayerAuthError

client = InboxLayerClient(api_token="YOUR_API_TOKEN")

try:
    client.get_me()
except InboxLayerAuthError as e:
    print(e.status_code)  # 401 or 403
    print(e.body)
except InboxLayerHTTPError as e:
    print(e.status_code)
    print(e.body)
```

**Exception hierarchy:**

| Exception | When |
|---|---|
| `InboxLayerError` | Base for all SDK errors |
| `InboxLayerHTTPError` | Any non-2xx response |
| `InboxLayerAuthError` | 401/403 authentication failures |
| `InboxLayerRateLimitError` | 429 rate limit exceeded |
| `InboxLayerValidationError` | Request/response validation failures |
| `InboxLayerTimeoutError` | Request timed out |
| `InboxLayerNetworkError` | DNS/TCP transport errors |

All HTTP exceptions expose `status_code`, `body`, `headers`, `error_code`, `request_id`, and `retry_after`.

## Webhook Verification

Verify incoming webhook signatures:

```python
from inboxlayer_sdk.security import verify_webhook_signature

is_valid = verify_webhook_signature(
    payload=request.body,
    signature=request.headers["X-Signature"],
    secret="your_webhook_secret",
)
```

## Advanced

### Request Options

Every method accepts an optional `options` parameter to override client defaults per-request:

```python
from inboxlayer_sdk import RequestOptions

client.list_inboxes(options=RequestOptions(
    timeout=60.0,
    max_retries=5,
    headers={"X-Custom": "value"},
    idempotency_key="unique-key",
))
```

### Retries

Requests are automatically retried with exponential backoff. A request is retried when any of these status codes is returned:

- 408 (Timeout)
- 429 (Too Many Requests)
- 5xx (Server Errors)

The default is 3 retries. Override per-client or per-request:

```python
# Per-client
client = InboxLayerClient(api_token="...", max_retries=5)

# Per-request
client.list_inboxes(options=RequestOptions(max_retries=1))
```

Rate-limited responses with a `Retry-After` header are respected automatically.

### Timeouts

The default timeout is 30 seconds. Override per-client or per-request:

```python
client = InboxLayerClient(api_token="...", timeout=60.0)

# Per-request
client.list_inboxes(options=RequestOptions(timeout=10.0))
```

### Custom HTTP Client

Pass a custom `httpx` client for proxies, transports, or other configuration:

```python
import httpx
from inboxlayer_sdk import InboxLayerClient

client = InboxLayerClient(
    api_token="...",
    httpx_client=httpx.Client(
        proxy="http://my.proxy.example.com",
        transport=httpx.HTTPTransport(local_address="0.0.0.0"),
    ),
)
```

For local development over HTTP:

```python
client = InboxLayerClient(
    base_url="http://localhost:3033",
    allow_http=True,
)
auth = client.authenticate(email="user@example.com", password="secret")
```

## Reference

A full list of all methods is available in [REFERENCE.md](REFERENCE.md).
