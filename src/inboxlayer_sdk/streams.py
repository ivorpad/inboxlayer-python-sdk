"""SSE stream parser and helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, AsyncIterator, Iterator


@dataclass(frozen=True)
class SSEEvent:
    event: str | None
    data: str
    id: str | None = None
    retry: int | None = None
    raw: str | None = None

    def json(self) -> Any | None:
        """Attempt to parse event data as JSON."""
        try:
            return json.loads(self.data) if self.data else None
        except Exception:
            return None


def parse_sse_lines(lines: Iterator[str]) -> Iterator[SSEEvent]:
    """Parse a stream of SSE lines into typed events."""
    event_name: str | None = None
    event_id: str | None = None
    event_retry: int | None = None
    event_data: list[str] = []
    raw_parts: list[str] = []

    def emit() -> SSEEvent | None:
        if not event_data:
            return None
        return SSEEvent(
            event=event_name or "message",
            data="\n".join(event_data),
            id=event_id,
            retry=event_retry,
            raw="\n".join(raw_parts),
        )

    def reset() -> None:
        nonlocal event_name, event_id, event_retry, event_data, raw_parts
        event_name = None
        event_id = None
        event_retry = None
        event_data = []
        raw_parts = []

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            event = emit()
            if event is not None:
                yield event
            reset()
            continue
        if line.startswith(":"):
            continue

        raw_parts.append(line)
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]

        if field == "event":
            event_name = value
        elif field == "data":
            event_data.append(value)
        elif field == "id":
            event_id = value
        elif field == "retry":
            try:
                event_retry = int(value)
            except ValueError:
                pass

    final_event = emit()
    if final_event is not None:
        yield final_event


async def parse_sse_lines_async(lines: AsyncIterator[str]) -> AsyncIterator[SSEEvent]:
    """Parse an async stream of SSE lines into typed events."""
    event_name: str | None = None
    event_id: str | None = None
    event_retry: int | None = None
    event_data: list[str] = []
    raw_parts: list[str] = []

    async def emit() -> SSEEvent | None:
        if not event_data:
            return None
        return SSEEvent(
            event=event_name or "message",
            data="\n".join(event_data),
            id=event_id,
            retry=event_retry,
            raw="\n".join(raw_parts),
        )

    async def reset() -> None:
        nonlocal event_name, event_id, event_retry, event_data, raw_parts
        event_name = None
        event_id = None
        event_retry = None
        event_data = []
        raw_parts = []

    async for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            event = await emit()
            if event is not None:
                yield event
            await reset()
            continue

        if line.startswith(":"):
            continue

        raw_parts.append(line)
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]

        if field == "event":
            event_name = value
        elif field == "data":
            event_data.append(value)
        elif field == "id":
            event_id = value
        elif field == "retry":
            try:
                event_retry = int(value)
            except ValueError:
                pass

    final_event = await emit()
    if final_event is not None:
        yield final_event
