"""Optional stdio MCP adapter. It exposes analysis, never process execution."""

from __future__ import annotations

from pathlib import Path
import asyncio
import sys
from typing import Any, Literal

from .analysis import INTERPRETATION, compare_captures, filter_events, summarize
from .reader import Operation, Scope
from .store import TraceStore
from .vv8 import raw_records_page, script_source, scripts_page


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
        """List relative JSONL and raw VV8 log paths beneath the configured trace root."""
        return store.list(offset=offset, limit=limit)

    @server.tool(annotations=annotations)
    def summarize_trace(path: str, channel: Literal['binding', 'engine'] | None = None) -> dict[str, Any]:
        """Report observed APIs, sources, coverage, integrity and collection outcomes."""
        return summarize(store.read(path, allow_legacy=allow_legacy), channel=channel)

    @server.tool(annotations=annotations)
    def get_trace_events(path: str, api: str | None = None, source_url: str | None = None,
                         pid: int | None = None, threw: bool | None = None,
                         offset: int = 0, limit: int = 100, op: Operation | None = None,
                         scope: Scope | Literal["unknown"] | None = None,
                         channel: Literal['binding', 'engine'] | None = None,
                         tid: int | None = None, isolate: str | None = None,
                         script_id: int | None = None, property_name: str | None = None,
                         source_offset: int | None = None) -> dict[str, Any]:
        """Filter exact API, operation, member scope, URL, PID or exception state; paginate.

        Scope unknown selects older records that do not declare a member scope.
        """
        return filter_events(store.read(path, allow_legacy=allow_legacy), api=api,
                             source_url=source_url, pid=pid, threw=threw, offset=offset, limit=limit,
                             op=op, scope=scope, channel=channel, tid=tid, isolate=isolate,
                             script_id=script_id, property_name=property_name, source_offset=source_offset)

    @server.tool(annotations=annotations)
    def compare_traces(baseline: str, candidate: str,
                       channel: Literal['binding', 'engine'] | None = None) -> dict[str, Any]:
        """Compare observed API/source counts, preserving each capture's limitations."""
        return compare_captures(store.read(baseline, allow_legacy=allow_legacy),
                                store.read(candidate, allow_legacy=allow_legacy), channel=channel)

    @server.tool(annotations=annotations)
    def get_trace_scripts(path: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """List native script registrations with process/thread/isolate/eval provenance."""
        return scripts_page(store.read(path, allow_legacy=allow_legacy), offset=offset, limit=limit)

    @server.tool(annotations=annotations)
    def get_trace_script_source(path: str, index: int, offset: int = 0,
                                limit: int = 4096) -> dict[str, Any]:
        """Read registered full source in pages; page offsets are Unicode code points.

        The event's source_offset retains the producer's UTF-16 code-unit convention.
        """
        return script_source(store.read(path, allow_legacy=allow_legacy), index, offset=offset, limit=limit)

    @server.tool(annotations=annotations)
    def get_trace_raw_records(path: str, offset: int = 0, limit: int = 100,
                              pid: int | None = None, tid: int | None = None) -> dict[str, Any]:
        """Read reassembled raw VV8 records, grouped by producer thread; no invented return values."""
        return raw_records_page(store.read(path, allow_legacy=allow_legacy), offset=offset, limit=limit,
                                pid=pid, tid=tid)

    return server

