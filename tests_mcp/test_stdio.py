import base64
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
    async def test_many_unavailable_sources_have_bounded_previews_and_an_independent_sdk_cursor(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            trace_root = Path(directory) / 'traces'
            trace_root.mkdir()
            controls = [dict(schema=1, event='source_unavailable', channel='engine', pid=41, tid=51,
                             source_id=index, reason='source_missing', filename=None,
                             introduction_type=None, retrievable=False) for index in range(100, 305)]
            raw = ['~a', '@?', '$1:"fixture.js":x;', '!1', 'g0:{1,Window}:"x"']
            rows = controls + [dict(schema=1, event='vv8', pid=41, tid=51, record=index,
                                     part=0, final=True, data=value) for index, value in enumerate(raw, 1)]
            (trace_root / 'many.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            parameters = StdioServerParameters(
                command=sys.executable,
                args=['-m', 'camoufox_trace_mcp', 'serve', '--trace-root', str(trace_root)],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
            )
            with open(Path(directory) / 'server-stderr', 'w+') as errlog:
                async with stdio_client(parameters, errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as session:
                        await session.initialize()
                        for name, extra in (('summarize_trace', {}), ('get_trace_events', {'limit': 1}),
                                            ('get_trace_raw_records', {'limit': 1}),
                                            ('get_trace_script_source', {'index': 0, 'limit': 1})):
                            result = await session.call_tool(name, {'path': 'many.jsonl', **extra})
                            self.assertFalse(result.isError, str(result.content))
                            report = result.structuredContent
                            if name == 'summarize_trace':
                                report = report['engine']
                            self.assertEqual(report['source_unavailable'], controls[:100])
                            self.assertEqual(report['source_unavailable_count'], 205)
                            self.assertTrue(report['source_unavailable_limited'])
                            self.assertFalse(report['source_provenance_complete'])
                        recovered, offset = [], 0
                        while offset is not None:
                            result = await session.call_tool('get_trace_scripts', {
                                'path': 'many.jsonl', 'offset': offset, 'limit': 83})
                            self.assertFalse(result.isError, str(result.content))
                            page = result.structuredContent
                            self.assertEqual(page['matched'], 1)
                            self.assertIsNone(page['next_offset'])
                            self.assertEqual(page['source_unavailable_count'], 205)
                            self.assertEqual(page['source_unavailable_matched'], 205)
                            self.assertEqual(len(page['scripts']), 1 if offset == 0 else 0)
                            self.assertLessEqual(len(page['source_unavailable']), 83)
                            recovered.extend(page['source_unavailable'])
                            offset = page['source_unavailable_next_offset']
                        self.assertEqual(recovered, controls)

    async def test_missing_source_metadata_survives_the_seven_read_only_tools(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            trace_root = Path(directory) / 'traces'
            trace_root.mkdir()
            control = dict(schema=1, event='source_unavailable', channel='engine', pid=41, tid=51,
                           source_id=1, reason='source_missing', filename=None,
                           introduction_type=None, retrievable=False, scope='source', truncated=False)
            raw = ['~a', '@?', '!?', 'c-1:%native:#U', '$2:#?:child();', '!2', 'g0:{1,Window}:"x"']
            rows = [control] + [dict(schema=1, event='vv8', pid=41, tid=51, record=index,
                                     part=0, final=True, data=value) for index, value in enumerate(raw, 1)]
            (trace_root / 'missing.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            parameters = StdioServerParameters(
                command=sys.executable,
                args=['-m', 'camoufox_trace_mcp', 'serve', '--trace-root', str(trace_root)],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
            )
            with open(Path(directory) / 'server-stderr', 'w+') as errlog:
                async with stdio_client(parameters, errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as session:
                        await session.initialize()
                        requests = {'list_traces': {}, 'summarize_trace': {'path': 'missing.jsonl'},
                                    'get_trace_events': {'path': 'missing.jsonl'},
                                    'get_trace_scripts': {'path': 'missing.jsonl'},
                                    'get_trace_script_source': {'path': 'missing.jsonl', 'index': 0},
                                    'get_trace_raw_records': {'path': 'missing.jsonl'},
                                    'compare_traces': {'baseline': 'missing.jsonl', 'candidate': 'missing.jsonl'}}
                        reports = {}
                        for name, arguments in requests.items():
                            result = await session.call_tool(name, arguments)
                            self.assertFalse(result.isError, f'{name}: {result.content!r}')
                            self.assertIsNotNone(result.structuredContent, name)
                            reports[name] = result.structuredContent
                        summary = reports['summarize_trace']
                        self.assertEqual(summary['integrity'], 'no_known_loss')
                        self.assertFalse(summary['engine']['source_provenance_complete'])
                        self.assertEqual(summary['engine']['source_unavailable'], [control])
                        for name in ('get_trace_events', 'get_trace_scripts', 'get_trace_script_source', 'get_trace_raw_records'):
                            self.assertEqual(reports[name]['source_unavailable'], [control])
                            self.assertFalse(reports[name]['source_provenance_complete'])
                        self.assertIsNone(reports['get_trace_events']['events'][0]['source'])
                        self.assertEqual(reports['get_trace_script_source']['source'], 'child();')
                        self.assertEqual([item['raw'] for item in reports['get_trace_raw_records']['records']], raw)
                        self.assertEqual(reports['compare_traces']['call_site_changes'], [])

    async def test_engine_stop_reasons_are_reported_without_claiming_an_event_cap(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            trace_root = Path(directory) / 'traces'
            trace_root.mkdir()
            reasons = ('engine_source_or_context', 'engine_value', 'engine_transport', 'engine_record_cap')
            limits = {}
            for reason in reasons:
                rows = [dict(schema=1, event='vv8', pid=4758, tid=1, record=index,
                             part=0, final=True, data=raw) for index, raw in enumerate(['~a', '@?'], 1)]
                limit = dict(schema=1, event='limit', pid=4758, channel='engine', emitted=2, reason=reason)
                limits[reason] = limit
                (trace_root / f'{reason}.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows + [limit]))
            parameters = StdioServerParameters(
                command=sys.executable,
                args=['-m', 'camoufox_trace_mcp', 'serve', '--trace-root', str(trace_root)],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
            )
            with open(Path(directory) / 'server-stderr', 'w+') as errlog:
                async with stdio_client(parameters, errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as session:
                        await session.initialize()
                        for reason in reasons:
                            result = await session.call_tool('summarize_trace', {'path': f'{reason}.jsonl'})
                            self.assertFalse(result.isError, str(result.content))
                            report = result.structuredContent
                            self.assertEqual(report['limits'], [limits[reason]])
                            self.assertEqual(report['integrity'], 'incomplete')
                            expected = 'producer_event_cap' if reason == 'engine_record_cap' else 'producer_stopped'
                            other = 'producer_stopped' if reason == 'engine_record_cap' else 'producer_event_cap'
                            self.assertIn(expected, report['statuses'])
                            self.assertNotIn(other, report['statuses'])
                        compared = await session.call_tool('compare_traces', {
                            'baseline': 'engine_source_or_context.jsonl', 'candidate': 'engine_record_cap.jsonl'})
                        self.assertFalse(compared.isError, str(compared.content))
                        self.assertIn('producer_stopped', compared.structuredContent['baseline']['statuses'])
                        self.assertIn('producer_event_cap', compared.structuredContent['candidate']['statuses'])

    async def test_lone_utf16_surrogates_are_recoverable_through_all_tools(self):
        def restored(value):
            self.assertEqual(value['encoding'], 'utf16le_base64')
            self.assertTrue(value['escaped'].isascii())
            decoded = base64.b64decode(value['data'], validate=True).decode('utf-16-le', 'surrogatepass')
            self.assertEqual(json.loads(value['escaped']), decoded)
            return decoded

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            trace_root = Path(directory) / 'traces'
            trace_root.mkdir()
            original = ['~a', '@?', r'$1:"https\://site.test/a.js":const x = "\ud800"; window.x;',
                        '!1', 'g-1:{1,Window}:"x"']
            (trace_root / 'source.log').write_text('\n'.join(original) + '\n', encoding='ascii')
            source_text = 'const face = "🦊";\r\nconst x = "\ud800"; window.x;'
            records = ['~a', r'@"origin\ud800":"token\udfff"',
                       r'$1:"https\://site.test/\ud800.js":const face = "\ud83e\udd8a";\x0d\x0aconst x = "\ud800"; window.x;',
                       '!1', r'g-1:{1,Window}:"prop\ud800"',
                       r'c-1:%log:{2,Console}:"arg\udfff":sym\ud800:"\ud83e\udd8a"',
                       r'$2:1:eval("\udfff");', '!2', r's-1:{1,Window}:"plain":"\ud800"']
            (trace_root / 'edges.log').write_text('\n'.join(records) + '\n', encoding='ascii')
            (trace_root / 'low-\udcff.jsonl').write_bytes(b'')
            metadata = json.loads((ROOT / 'fixtures/pilot.jsonl').read_text().splitlines()[0])
            metadata['labels'] = {'\ud800': 'first', 'plain': '\udfff'}
            (trace_root / 'keyed.jsonl').write_text(json.dumps(metadata) + '\n', encoding='ascii')
            parameters = StdioServerParameters(
                command=sys.executable,
                args=['-m', 'camoufox_trace_mcp', 'serve', '--trace-root', str(trace_root)],
                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
            )
            with open(Path(directory) / 'server-stderr', 'w+') as errlog:
                async with stdio_client(parameters, errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=10)) as session:
                        await session.initialize()
                        source = await session.call_tool('get_trace_script_source', {'path': 'source.log', 'index': 0})
                        self.assertFalse(source.isError, str(source.content))
                        self.assertEqual(restored(source.structuredContent['source']),
                                         'const x = "\ud800"; window.x;')
                        requests = {
                            'list_traces': {},
                            'summarize_trace': {'path': 'edges.log'},
                            'get_trace_events': {'path': 'edges.log'},
                            'compare_traces': {'baseline': 'edges.log', 'candidate': 'edges.log'},
                            'get_trace_scripts': {'path': 'edges.log'},
                            'get_trace_script_source': {'path': 'edges.log', 'index': 0},
                            'get_trace_raw_records': {'path': 'edges.log'},
                        }
                        reports = {}
                        for name, arguments in requests.items():
                            result = await session.call_tool(name, arguments)
                            self.assertFalse(result.isError, f'{name}: {result.content!r}')
                            self.assertIsNotNone(result.structuredContent, name)
                            json.dumps(result.structuredContent, ensure_ascii=False).encode('utf-8')
                            reports[name] = result.structuredContent
                        self.assertIn('low-\udcff.jsonl', [restored(name) if isinstance(name, dict) else name
                                                       for name in reports['list_traces']['traces']])
                        summary = reports['summarize_trace']
                        self.assertEqual(summary['integrity'], 'no_known_loss')
                        self.assertIn('Window.prop\ud800', [restored(item['api']) if isinstance(item['api'], dict)
                                                           else item['api'] for item in summary['apis']])
                        events = reports['get_trace_events']['events']
                        self.assertEqual(restored(events[0]['property']['value']), 'prop\ud800')
                        self.assertEqual(restored(events[0]['source']['url']), 'https://site.test/\ud800.js')
                        self.assertEqual(restored(events[0]['origin']), 'origin\ud800')
                        self.assertEqual(restored(events[0]['security_token']), 'token\udfff')
                        self.assertEqual(restored(events[1]['args'][0]['value']), 'arg\udfff')
                        self.assertEqual(restored(events[1]['args'][1]['raw']), 'sym\ud800')
                        self.assertEqual(events[1]['args'][2]['value'], '🦊')
                        self.assertEqual(events[1]['api'], 'Console.log')
                        self.assertEqual(restored(events[2]['args'][0]['value']), '\ud800')
                        scripts = reports['get_trace_scripts']['scripts']
                        self.assertEqual(scripts[1]['parent_id'], 1)
                        self.assertEqual(restored(scripts[0]['url']), 'https://site.test/\ud800.js')
                        self.assertEqual(restored(reports['get_trace_script_source']['source']), source_text)
                        self.assertEqual(reports['get_trace_script_source']['utf16_length'],
                                         len(source_text.encode('utf-16-le', 'surrogatepass')) // 2)
                        raw = reports['get_trace_raw_records']['records']
                        self.assertEqual([item['raw'] for item in raw], records)
                        self.assertEqual(reports['compare_traces']['call_site_changes'], [])
                        keyed = await session.call_tool('summarize_trace', {'path': 'keyed.jsonl'})
                        self.assertFalse(keyed.isError, str(keyed.content))
                        labels = keyed.structuredContent['metadata'][0]['labels']
                        self.assertEqual(labels['encoding'], 'utf16_keyed_entries')
                        self.assertEqual(restored(labels['entries'][0]['key']), '\ud800')
                        self.assertEqual(labels['entries'][0]['value'], 'first')
                        self.assertEqual(labels['entries'][1]['key'], 'plain')
                        self.assertEqual(restored(labels['entries'][1]['value']), '\udfff')

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
                            "list_traces", "summarize_trace", "get_trace_events", "compare_traces",
                            'get_trace_scripts', 'get_trace_script_source', 'get_trace_raw_records'})
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
                        (trace_root / 'engine.jsonl').write_bytes((ROOT / 'fixtures/engine.jsonl').read_bytes())
                        engine = await session.call_tool('summarize_trace', {'path': 'engine.jsonl', 'channel': 'engine'})
                        self.assertFalse(engine.isError)
                        self.assertEqual(engine.structuredContent['engine_event_count'], 4)
                        scripts = await session.call_tool('get_trace_scripts', {'path': 'engine.jsonl'})
                        self.assertFalse(scripts.isError)
                        self.assertEqual(scripts.structuredContent['scripts'][0]['script_id'], 1)
                        source = await session.call_tool('get_trace_script_source', {
                            'path': 'engine.jsonl', 'index': 0, 'limit': 1000})
                        self.assertIn('🦊', source.structuredContent['source'])
                        selected = await session.call_tool('get_trace_events', {
                            'path': 'engine.jsonl', 'channel': 'engine', 'op': 'get', 'pid': 41,
                            'tid': 51, 'isolate': '0x10', 'script_id': 1, 'property_name': 'userAgent'})
                        self.assertEqual(selected.structuredContent['matched'], 1)
                        event = selected.structuredContent['events'][0]
                        self.assertEqual(event['source']['line'], 2)
                        self.assertEqual(event['result']['reason'], 'not_observed')
                        self.assertIsNone(event['threw'])
                        raw = await session.call_tool('get_trace_raw_records', {'path': 'engine.jsonl', 'tid': 51})
                        self.assertEqual(raw.structuredContent['matched'], 8)
                        self.assertTrue(raw.structuredContent['records'][0]['raw'].startswith('~'))
                        unchanged = await session.call_tool('compare_traces', {
                            'baseline': 'engine.jsonl', 'candidate': 'engine.jsonl', 'channel': 'engine'})
                        self.assertEqual(unchanged.structuredContent['call_site_changes'], [])
                        rejected = await session.call_tool('get_trace_script_source', {
                            'path': 'engine.jsonl', 'index': -1})
                        self.assertTrue(rejected.isError)
                        unknown_rows = [dict(schema=1, event='vv8', pid=41, tid=51,
                                             record=index, part=0, final=True, data=raw)
                                        for index, raw in enumerate(['~a', '@?', '!?', 'c-1:%native:#U'], 1)]
                        (trace_root / 'unknown.jsonl').write_text(
                            ''.join(json.dumps(row) + '\n' for row in unknown_rows))
                        unknown = await session.call_tool('summarize_trace', {'path': 'unknown.jsonl'})
                        self.assertFalse(unknown.isError)
                        self.assertEqual(unknown.structuredContent['integrity'], 'no_known_loss')
                        self.assertIn('provenance_unknown', unknown.structuredContent['statuses'])
                        unknown_events = await session.call_tool('get_trace_events', {
                            'path': 'unknown.jsonl', 'channel': 'engine'})
                        self.assertIsNone(unknown_events.structuredContent['events'][0]['script_id'])
                        self.assertTrue(unknown_events.structuredContent['events'][0]['provenance_unknown'])


if __name__ == "__main__":
    unittest.main()
