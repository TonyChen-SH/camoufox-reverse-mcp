"""Stdlib CLI; importing it does not import the optional MCP dependency."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .analysis import analysis_exit_code, compare_captures, filter_events, summarize
from .collector import DEFAULT_OUTPUT_BYTES, collect, collection_exit_code
from .reader import MAX_EVENTS, MAX_INPUT_BYTES, MAX_LINE_BYTES, OPERATIONS, SCOPES, read_capture
from .vv8 import DEFAULT_SEGMENT_BYTES, export_vv8, import_vv8, raw_records_page, script_source, scripts_page


def _reader_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--legacy", action="store_true", help="accept original PropertyTracer records")
    parser.add_argument("--max-events", type=int, default=MAX_EVENTS, help="reader event retention cap")
    parser.add_argument('--input-format', choices=('auto', 'jsonl', 'vv8'), default='auto')
    parser.add_argument('--max-input-bytes', type=int, default=MAX_INPUT_BYTES)
    parser.add_argument('--max-line-bytes', type=int, default=MAX_LINE_BYTES)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze native Camoufox API traces.")
    commands = parser.add_subparsers(dest="command", required=True)
    summary = commands.add_parser("summarize", help="summarize observed APIs and sources")
    summary.add_argument("path")
    _reader_options(summary)
    summary.add_argument('--channel', choices=('binding', 'engine'))
    events = commands.add_parser("events", help="filter and paginate observed API records")
    events.add_argument("path")
    _reader_options(events)
    events.add_argument("--api")
    events.add_argument("--op", choices=OPERATIONS, help="exact WebIDL operation")
    events.add_argument("--scope", choices=(*SCOPES, "unknown"),
                        help="member scope; unknown selects records without a scope")
    events.add_argument("--source-url")
    events.add_argument("--pid", type=int)
    events.add_argument('--tid', type=int)
    events.add_argument('--isolate')
    events.add_argument('--script-id', type=int)
    events.add_argument('--property-name')
    events.add_argument('--source-offset', type=int)
    events.add_argument('--channel', choices=('binding', 'engine'))
    events.add_argument("--threw", choices=("true", "false"))
    events.add_argument("--offset", type=int, default=0)
    events.add_argument("--limit", type=int, default=100)
    compare = commands.add_parser("compare", help="compare observed API/source counts")
    compare.add_argument("baseline")
    compare.add_argument("candidate")
    _reader_options(compare)
    compare.add_argument('--channel', choices=('binding', 'engine'))
    for name in ('scripts', 'script-source', 'raw-records', 'export-vv8'):
        command = commands.add_parser(name)
        command.add_argument('path')
        _reader_options(command)
        if name == 'export-vv8':
            command.add_argument('--output', required=True, help='new directory for per-thread VV8 logs')
            command.add_argument('--segment-bytes', type=int, default=DEFAULT_SEGMENT_BYTES,
                                 help='roll over after this byte threshold, between whole records')
        else:
            command.add_argument('--offset', type=int, default=0)
            command.add_argument('--limit', type=int, default=4096 if name == 'script-source' else 100)
        if name == 'script-source':
            command.add_argument('--index', type=int, required=True)
        if name == 'raw-records':
            command.add_argument('--pid', type=int)
            command.add_argument('--tid', type=int)
    importer = commands.add_parser('import-vv8', help='wrap a raw VV8 log as native transport JSONL')
    importer.add_argument('path', nargs='+', help='explicit raw files; numeric segments are validated and sorted')
    importer.add_argument('--output', required=True)
    importer.add_argument('--pid', type=int)
    importer.add_argument('--tid', type=int)
    collector = commands.add_parser("collect", help="run explicit local argv and save marked stderr")
    collector.add_argument("--output", required=True, help="new JSONL file; existing files are refused")
    collector.add_argument("--timeout", type=float, default=60)
    collector.add_argument("--max-output-bytes", type=int, default=DEFAULT_OUTPUT_BYTES)
    collector.add_argument('--engine', action='store_true', help='enable CAMOUFOX_ENGINE_TRACE')
    collector.add_argument('--no-bindings', action='store_true', help='disable the binding trace channel')
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
                              max_output_bytes=arguments.max_output_bytes,
                              engine=arguments.engine, binding=not arguments.no_bindings)
            capture = read_capture(arguments.output)
            report = summarize(capture)
            report["output"] = arguments.output
            code = collection_exit_code(outcome, analysis_exit_code(capture))
        elif arguments.command == 'import-vv8':
            report = import_vv8(arguments.path, arguments.output, pid=arguments.pid, tid=arguments.tid)
            code = 0
        else:
            options = {"allow_legacy": arguments.legacy, "max_events": arguments.max_events,
                       'input_format': arguments.input_format, 'max_input_bytes': arguments.max_input_bytes,
                       'max_line_bytes': arguments.max_line_bytes}
            if arguments.command == "compare":
                baseline = read_capture(arguments.baseline, **options)
                candidate = read_capture(arguments.candidate, **options)
                report = compare_captures(baseline, candidate, channel=arguments.channel)
                code = max(analysis_exit_code(baseline), analysis_exit_code(candidate))
            else:
                capture = read_capture(arguments.path, **options)
                code = analysis_exit_code(capture)
                if arguments.command == "summarize":
                    report = summarize(capture, channel=arguments.channel)
                elif arguments.command == 'scripts':
                    report = scripts_page(capture, offset=arguments.offset, limit=arguments.limit)
                elif arguments.command == 'script-source':
                    report = script_source(capture, arguments.index, offset=arguments.offset, limit=arguments.limit)
                elif arguments.command == 'raw-records':
                    report = raw_records_page(capture, offset=arguments.offset, limit=arguments.limit,
                                              pid=arguments.pid, tid=arguments.tid)
                elif arguments.command == 'export-vv8':
                    report = export_vv8(capture, arguments.output, segment_bytes=arguments.segment_bytes)
                else:
                    threw = None if arguments.threw is None else arguments.threw == "true"
                    report = filter_events(capture, api=arguments.api, source_url=arguments.source_url,
                                           pid=arguments.pid, threw=threw, offset=arguments.offset,
                                           limit=arguments.limit, op=arguments.op, scope=arguments.scope,
                                           channel=arguments.channel, tid=arguments.tid, isolate=arguments.isolate,
                                           script_id=arguments.script_id, property_name=arguments.property_name,
                                           source_offset=arguments.source_offset)
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
        return code
    except (ValueError, OSError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
