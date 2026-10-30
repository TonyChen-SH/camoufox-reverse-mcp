"""Optional stdio MCP adapter. It exposes analysis, never process execution."""

from __future__ import annotations

from pathlib import Path
import asyncio
import base64
import json
import sys
from typing import Any, Literal

from .analysis import INTERPRETATION, compare_captures, filter_events, summarize
from .reader import Operation, Scope
from .store import TraceStore
from .vv8 import raw_records_page, script_source, scripts_page


def _sdk_safe(value: Any) -> Any:
    """Represent non-scalar strings without losing the producer's UTF-16 code units."""
    if isinstance(value, str):
        if not any(0xd800 <= ord(char) <= 0xdfff for char in value):
            return value
        return {'encoding': 'utf16le_base64',
                'data': base64.b64encode(value.encode('utf-16-le', 'surrogatepass')).decode('ascii'),
                'escaped': json.dumps(value, ensure_ascii=True)}
    if isinstance(value, dict):
        if any(isinstance(key, str) and any(0xd800 <= ord(char) <= 0xdfff for char in key)
               for key in value):
            return {'encoding': 'utf16_keyed_entries',
                    'entries': [{'key': _sdk_safe(key), 'value': _sdk_safe(item)}
                                for key, item in value.items()]}
        return {key: _sdk_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sdk_safe(item) for item in value]
    return value


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
    server = FastMCP("Camoufox trace analysis", instructions=INTERPRETATION +
                     ' MCP strings containing unpaired UTF-16 surrogates use '
                     '{encoding:"utf16le_base64",data,escaped}; data preserves UTF-16LE code units '
                     'without a BOM and escaped is an ASCII JSON string literal. '
                     'Mappings with such keys use {encoding:"utf16_keyed_entries",entries:[{key,value}]}. '
                     'Ordinary Unicode strings retain their usual representation.')
    annotations = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                  idempotentHint=True, openWorldHint=False)

    @server.tool(annotations=annotations)
    def list_traces(offset: int = 0, limit: int = 50) -> dict[str, Any]:
        """List relative JSONL and raw VV8 log paths beneath the configured trace root."""
        return _sdk_safe(store.list(offset=offset, limit=limit))

    @server.tool(annotations=annotations)
    def summarize_trace(path: str, channel: Literal['binding', 'engine'] | None = None) -> dict[str, Any]:
        """Report observed APIs, sources, coverage, integrity and collection outcomes."""
        return _sdk_safe(summarize(store.read(path, allow_legacy=allow_legacy), channel=channel))

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
        return _sdk_safe(filter_events(store.read(path, allow_legacy=allow_legacy), api=api,
                             source_url=source_url, pid=pid, threw=threw, offset=offset, limit=limit,
                             op=op, scope=scope, channel=channel, tid=tid, isolate=isolate,
                             script_id=script_id, property_name=property_name, source_offset=source_offset))

    @server.tool(annotations=annotations)
    def compare_traces(baseline: str, candidate: str,
                       channel: Literal['binding', 'engine'] | None = None) -> dict[str, Any]:
        """Compare observed API/source counts, preserving each capture's limitations."""
        return _sdk_safe(compare_captures(store.read(baseline, allow_legacy=allow_legacy),
                                         store.read(candidate, allow_legacy=allow_legacy), channel=channel))

    @server.tool(annotations=annotations)
    def get_trace_scripts(path: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """List native script registrations with process/thread/isolate/eval provenance."""
        return _sdk_safe(scripts_page(store.read(path, allow_legacy=allow_legacy), offset=offset, limit=limit))

    @server.tool(annotations=annotations)
    def get_trace_script_source(path: str, index: int, offset: int = 0,
                                limit: int = 4096) -> dict[str, Any]:
        """Read registered full source in pages; page offsets are Unicode code points.

        The event's source_offset retains the producer's UTF-16 code-unit convention.
        """
        return _sdk_safe(script_source(store.read(path, allow_legacy=allow_legacy), index, offset=offset, limit=limit))

    @server.tool(annotations=annotations)
    def get_trace_raw_records(path: str, offset: int = 0, limit: int = 100,
                              pid: int | None = None, tid: int | None = None) -> dict[str, Any]:
        """Read reassembled raw VV8 records, grouped by producer thread; no invented return values."""
        return _sdk_safe(raw_records_page(store.read(path, allow_legacy=allow_legacy), offset=offset, limit=limit,
                                         pid=pid, tid=tid))

    return server

