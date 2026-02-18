from __future__ import annotations

import asyncio

from inboxlayer_sdk.streams import SSEEvent, parse_sse_lines, parse_sse_lines_async


def test_parse_sse_lines_collects_events() -> None:
    lines = [
        "event: update\n",
        "data: {\"id\":1}\n",
        "retry: 1500\n",
        "",
        "data: final\n",
        "",
    ]
    events = list(parse_sse_lines(iter(lines)))

    assert len(events) == 2
    assert events[0].event == "update"
    assert events[0].data == "{\"id\":1}"
    assert events[0].retry == 1500
    assert events[1].event == "message"
    assert events[1].data == "final"
    assert events[1].retry is None


def test_parse_sse_lines_async_collects_events() -> None:
    async def collect() -> list[SSEEvent]:
        events: list[SSEEvent] = []

        async def generator():
            yield "data: first\n"
            yield "data: line2\n"
            yield ""
            yield "event: finalize\n"
            yield "data: done\n"
            yield ""

        async for event in parse_sse_lines_async(generator()):
            events.append(event)
        return events

    events = asyncio.run(collect())
    assert len(events) == 2
    assert events[0].event == "message"
    assert events[0].data == "first\nline2"
    assert events[1].event == "finalize"
