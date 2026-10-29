"""Stdlib CLI; importing it does not import the optional MCP dependency."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .analysis import analysis_exit_code, compare_captures, filter_events, summarize
from .collector import DEFAULT_OUTPUT_BYTES, collect, collection_exit_code
from .reader import MAX_EVENTS, read_capture


def _reader_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--legacy", action="store_true", help="accept original PropertyTracer records")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS, help="reader event retention cap")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze native Camoufox API traces.")
    commands = parser.add_subparsers(dest="command", required=True)
    summary = commands.add_parser("summarize", help="summarize observed APIs and sources")
    summary.add_argument("path")
    _reader_options(summary)
    events = commands.add_parser("events", help="filter and paginate observed API records")
    events.add_argument("path")
    _reader_options(events)
    events.add_argument("--api")
    events.add_argument("--source-url")
    events.add_argument("--pid", type=int)
    events.add_argument("--threw", choices=("true", "false"))
    events.add_argument("--offset", type=int, default=0)
    events.add_argument("--limit", type=int, default=100)
    compare = commands.add_parser("compare", help="compare observed API/source counts")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    _reader_options(compare)
    collector = commands.add_parser("collect", help="run explicit local argv and save marked stderr")
    collector.add_argument("--output", required=True, help="new JSONL file; existing files are refused")
    collector.add_argument("--timeout", type=float, default=60)
    collector.add_argument("--max-output-bytes", type=int, default=DEFAULT_OUTPUT_BYTES)
    collector.add_argument("argv", nargs=argparse.REMAINDER, help="-- command arg ... (never a shell)")
    server = commands.add_parser("serve", help="serve read-only MCP tools over stdio")
    server.add_argument("--trace-root", required=True)
    server.add_argument("--legacy", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "serve":
            try:
                from .server import create_server, run_stdio
                server = create_server(arguments.trace_root, allow_legacy=arguments.legacy)
            except ImportError as error:
                raise ValueError("serve requires the optional extra: pip install '.[mcp]'") from error
            asyncio.run(run_stdio(server))
            return 0
        if arguments.command == "collect":
            command = arguments.argv
            if command[:1] == ["--"]:
                command = command[1:]
            outcome = collect(command, arguments.output, timeout=arguments.timeout,
                              max_output_bytes=arguments.max_output_bytes)
            capture = read_capture(arguments.output)
            report = summarize(capture)
            report["output"] = arguments.output
            code = collection_exit_code(outcome, analysis_exit_code(capture))
        else:
            options = {"allow_legacy": arguments.legacy, "max_events": arguments.max_events}
            if arguments.command == "compare":
                baseline = read_capture(arguments.baseline, **options)
                candidate = read_capture(arguments.candidate, **options)
                report = compare_captures(baseline, candidate)
                code = max(analysis_exit_code(baseline), analysis_exit_code(candidate))
            else:
                capture = read_capture(arguments.path, **options)
                code = analysis_exit_code(capture)
                if arguments.command == "summarize":
                    report = summarize(capture)
                else:
                    threw = None if arguments.threw is None else arguments.threw == "true"
                    report = filter_events(capture, api=arguments.api, source_url=arguments.source_url,
                                           pid=arguments.pid, threw=threw, offset=arguments.offset,
                                           limit=arguments.limit)
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
        return code
    except (ValueError, OSError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
