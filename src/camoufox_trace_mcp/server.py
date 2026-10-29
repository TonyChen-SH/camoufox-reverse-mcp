"""Optional stdio MCP adapter. It exposes analysis, never process execution."""

from __future__ import annotations

from pathlib import Path
import asyncio
import sys
from typing import Any

from .analysis import INTERPRETATION, compare_captures, filter_events, summarize
from .store import TraceStore


async def run_stdio(server) -> None:
    """Use POSIX event-loop pipes with the SDK's JSON-RPC transport."""
    from mcp.server.stdio import stdio_server

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    read_transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    write_protocol = asyncio.StreamReaderProtocol(asyncio.StreamReader())
    write_transport, _ = await loop.connect_write_pipe(lambda: write_protocol, sys.stdout.buffer)
    writer = asyncio.StreamWriter(write_transport, write_protocol, None, loop)

    class Output:
        async def write(self, text):
            writer.write(text.encode("utf-8"))

        async def flush(self):
            await writer.drain()

    try:
        async with stdio_server(stdin=reader, stdout=Output()) as (read_stream, write_stream):
            await server._mcp_server.run(
                read_stream, write_stream, server._mcp_server.create_initialization_options())
    finally:
        read_transport.close()
        writer.close()
        await writer.wait_closed()


def create_server(trace_root: str | Path, *, allow_legacy: bool = False):
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations

    store = TraceStore(trace_root)
    server = FastMCP("Camoufox trace analysis", instructions=INTERPRETATION)
    annotations = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                  idempotentHint=True, openWorldHint=False)

    @server.tool(annotations=annotations)
    def list_traces(offset: int = 0, limit: int = 50) -> dict[str, Any]:
        """List relative JSONL paths beneath the configured trace root."""
        return store.list(offset=offset, limit=limit)

    @server.tool(annotations=annotations)
    def summarize_trace(path: str) -> dict[str, Any]:
        """Report observed APIs, sources, coverage, integrity and collection outcomes."""
        return summarize(store.read(path, allow_legacy=allow_legacy))

    @server.tool(annotations=annotations)
    def get_trace_events(path: str, api: str | None = None, source_url: str | None = None,
                         pid: int | None = None, threw: bool | None = None,
                         offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """Filter observed events by exact API, URL, PID or exception state; paginate."""
        return filter_events(store.read(path, allow_legacy=allow_legacy), api=api,
                             source_url=source_url, pid=pid, threw=threw, offset=offset, limit=limit)

    @server.tool(annotations=annotations)
    def compare_traces(baseline: str, candidate: str) -> dict[str, Any]:
        """Compare observed API/source counts, preserving each capture's limitations."""
        return compare_captures(store.read(baseline, allow_legacy=allow_legacy),
                                store.read(candidate, allow_legacy=allow_legacy))

    return server

