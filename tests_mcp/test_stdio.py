import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


class StdioIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_only_tool_round_trip_and_escape_rejection(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            trace_root = Path(directory) / "traces"
            trace_root.mkdir()
            (trace_root / "pilot.jsonl").write_bytes((ROOT / "fixtures" / "pilot.jsonl").read_bytes())
            (trace_root / "escape.jsonl").symlink_to(ROOT / "fixtures" / "pilot.jsonl")
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-m", "camoufox_trace_mcp", "serve", "--trace-root", str(trace_root)],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
            )
            with open(Path(directory) / "server-stderr", "w+") as errlog:
                async with stdio_client(parameters, errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as session:
                        await session.initialize()
                        tools = (await session.list_tools()).tools
                        self.assertEqual({tool.name for tool in tools}, {
                            "list_traces", "summarize_trace", "get_trace_events", "compare_traces"})
                        self.assertTrue(all(tool.annotations.readOnlyHint for tool in tools))
                        listing = await session.call_tool("list_traces", {})
                        self.assertFalse(listing.isError)
                        self.assertEqual(listing.structuredContent["traces"], ["pilot.jsonl"])
                        summary = await session.call_tool("summarize_trace", {"path": "pilot.jsonl"})
                        self.assertFalse(summary.isError)
                        self.assertEqual(summary.structuredContent["event_count"], 3)
                        events = await session.call_tool("get_trace_events", {"path": "pilot.jsonl", "limit": 1})
                        self.assertEqual(events.structuredContent["next_offset"], 1)
                        comparison = await session.call_tool("compare_traces", {
                            "baseline": "pilot.jsonl", "candidate": "pilot.jsonl"})
                        self.assertTrue(all(item["delta"] == 0 for item in comparison.structuredContent["api_count_deltas"]))
                        for path in ("../pilot.jsonl", "escape.jsonl", str(ROOT / "fixtures" / "pilot.jsonl")):
                            rejected = await session.call_tool("summarize_trace", {"path": path})
                            self.assertTrue(rejected.isError)
                        no_executor = await session.call_tool("collect", {"argv": ["true"]})
                        self.assertTrue(no_executor.isError)
                        (trace_root / "webidl.jsonl").write_bytes((ROOT / "fixtures" / "webidl.jsonl").read_bytes())
                        generic = await session.call_tool("summarize_trace", {"path": "webidl.jsonl"})
                        self.assertFalse(generic.isError)
                        self.assertEqual(generic.structuredContent["metadata"][0]["coverage"], "webidl-bindings")
                        self.assertEqual({site["scope"] for site in generic.structuredContent["call_sites"]},
                                         {"instance", "static", "constructor"})
                        for operation, expected in (("get", 1), ("set", 1), ("call", 2), ("construct", 1)):
                            selected = await session.call_tool("get_trace_events", {
                                "path": "webidl.jsonl", "op": operation})
                            self.assertFalse(selected.isError)
                            self.assertEqual(selected.structuredContent["matched"], expected)
                            self.assertTrue(all(event["op"] == operation
                                                for event in selected.structuredContent["events"]))
                        static = await session.call_tool("get_trace_events", {
                            "path": "webidl.jsonl", "op": "call", "scope": "static"})
                        self.assertEqual(static.structuredContent["events"][0]["api"], "URL.canParse")
                        unknown = await session.call_tool("get_trace_events", {
                            "path": "pilot.jsonl", "scope": "unknown"})
                        self.assertEqual(unknown.structuredContent["matched"], 3)
                        for arguments in ({"op": "read"}, {"scope": "global"}):
                            rejected = await session.call_tool("get_trace_events", {
                                "path": "webidl.jsonl", **arguments})
                            self.assertTrue(rejected.isError)


if __name__ == "__main__":
    unittest.main()
