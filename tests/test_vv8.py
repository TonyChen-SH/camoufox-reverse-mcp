import json
import gc
import hashlib
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import weakref

from camoufox_trace_mcp import compare_captures, filter_events, read_capture, summarize
from camoufox_trace_mcp.reader import parse_lines

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'const s = "🦊";\r\nnavigator.userAgent;\n'
OFFSET = len('const s = "🦊";\r\n'.encode('utf-16-le')) // 2
RAW = ['~0x10', '@"https\\://example.test/page":"https\\://example.test"',
       '$1:"https\\://example.test/probe.js":const s = "\\ud83e\\udd8a";\\x0d\\x0anavigator.userAgent;\\x0a',
       '!1', f'g{OFFSET}:{{17,Navigator}}:"userAgent"',
       f's{OFFSET}:{{18,HTMLInputElement}}:"value":"synthetic"',
       f'c{OFFSET}:%log:{{19,Console}}:-0:"colon\\:quote"',
       f'n{OFFSET}:%URL:"https\\://example.test/"']


def envelopes(records=RAW, *, pid=41, tid=51, chunk=80):
    result = []
    for number, raw in enumerate(records, 1):
        parts = [raw[index:index + chunk] for index in range(0, len(raw), chunk)]
        for part, data in enumerate(parts):
            result.append({'schema': 1, 'event': 'vv8', 'pid': pid, 'tid': tid,
                           'record': number, 'part': part, 'final': part == len(parts) - 1, 'data': data})
    return result


def capture(records):
    return parse_lines(json.dumps(record) for record in records)


class Vv8Tests(unittest.TestCase):
    def test_source_hash_preserves_lone_units_and_declares_its_byte_encoding(self):
        result = capture(envelopes(['~a', '@?', '$1:"edge.js":A\\ud800B\\udfffC\\ud83e\\udd8a',
                                    '!1', 'g3:{1,Window}:"x"']))
        script = result.engine.scripts[0]
        self.assertEqual(script['source'], 'A\ud800B\udfffC🦊')
        self.assertEqual(script['source_sha256_encoding'], 'utf-8-surrogatepass')
        exact_bytes = b'A\xed\xa0\x80B\xed\xbf\xbfC\xf0\x9f\xa6\x8a'
        self.assertEqual(script['source_sha256'], hashlib.sha256(exact_bytes).hexdigest())
        self.assertNotEqual(script['source_sha256'],
                            hashlib.sha256(b'A\xef\xbf\xbdB\xef\xbf\xbdC\xf0\x9f\xa6\x8a').hexdigest())
        self.assertEqual(result.events[0]['source_offset'], 3)
        self.assertEqual(result.events[0]['source']['column'], 4)
        self.assertEqual(result.flags, set())

    def test_chunk_assembly_preserves_source_context_and_unobserved_values(self):
        result = capture(envelopes())
        self.assertEqual(len(result.events), 4)
        event = result.events[0]
        self.assertEqual(event['channel'], 'engine')
        self.assertEqual((event['pid'], event['tid'], event['isolate'], event['script_id']),
                         (41, 51, '0x10', 1))
        self.assertEqual(event['source'], {'url': 'https://example.test/probe.js', 'line': 2, 'column': 1})
        self.assertEqual(event['source_offset'], OFFSET)
        self.assertEqual(event['result'], {'type': 'unavailable', 'reason': 'not_observed'})
        self.assertIsNone(event['threw'])
        self.assertEqual(result.engine.scripts[0]['source'], SOURCE)
        self.assertEqual(result.events[1]['args'][0]['value'], 'synthetic')
        self.assertEqual(math.copysign(1, result.events[2]['args'][0]['value']), -1)
        self.assertEqual(result.events[3]['api'], 'URL.constructor')

    def test_binding_and_engine_channels_never_share_aggregate_counts(self):
        binding = [json.loads(line) for line in (ROOT / 'fixtures/pilot.jsonl').read_text().splitlines()]
        result = capture(binding + envelopes())
        report = summarize(result)
        counts = {(item['channel'], item['api']): item['count'] for item in report['apis']}
        self.assertEqual(counts['binding', 'Navigator.userAgent'], 1)
        self.assertEqual(counts['engine', 'Navigator.userAgent'], 1)
        self.assertEqual(filter_events(result, channel='engine')['matched'], 4)
        self.assertEqual(filter_events(result, channel='binding')['matched'], 3)
        self.assertEqual(filter_events(result, channel='engine', threw=False)['matched'], 0)
        self.assertEqual(compare_captures(result, result)['call_site_changes'], [])

    def test_interleaved_threads_and_isolates_keep_separate_script_registries(self):
        other = ['~0x20', '@?', '$1:"other.js":other();', '!1', 'g0:{7,Screen}:"width"']
        first, second = envelopes(), envelopes(other, tid=52, chunk=11)
        mixed = []
        while first or second:
            if first:
                mixed.append(first.pop(0))
            if second:
                mixed.append(second.pop(0))
        result = capture(mixed)
        urls = {event['tid']: event['source']['url'] for event in result.events}
        self.assertEqual(urls, {51: 'https://example.test/probe.js', 52: 'other.js'})
        self.assertEqual(len(result.engine.scripts), 2)
        switching = capture(envelopes(['~a', '@?', '$1:"a.js":a();', '!1', '~b', '@?',
                                      '$1:"b.js":b();', '!1', 'g0:{1,Screen}:"width"',
                                      '~a', '!1', 'g0:{1,Screen}:"width"']))
        self.assertEqual([event['source']['url'] for event in switching.events], ['b.js', 'a.js'])

    def test_eval_parent_is_registered_without_inventing_a_child_url(self):
        records = ['~a', '@?', '$1:"outer.js":eval("x");', '$2:1:x;', '!2', 'g0:{1,Window}:"x"']
        result = capture(envelopes(records))
        child = result.engine.scripts[1]
        self.assertEqual(child['parent_id'], 1)
        self.assertIsNone(child['url'])
        self.assertEqual(result.events[0]['script_id'], 2)

    def test_missing_parts_duplicates_and_invalid_envelopes_are_explicit(self):
        complete = envelopes(chunk=8)
        for records in (complete[:-1], [complete[1]], [complete[0], complete[0]],
                        [dict(complete[0], part=2)], [dict(complete[0], pid=True)],
                        [dict(complete[0], data='nonascii🦊')], [dict(complete[0], final=1)],
                        [dict(complete[0], data='x' * 4096)]):
            with self.subTest(records=records[:1]):
                result = capture(records)
                self.assertEqual(summarize(result)['integrity'], 'incomplete')
                self.assertTrue(any(flag.startswith('vv8_') for flag in result.flags))

    def test_bad_raw_records_and_cross_isolate_script_references_are_explicit(self):
        for records in (['~a', '!7'], ['~a', '$2:1:eval();'], ['~a', '$1:"a":x', '$1:"b":y'],
                        ['~a', '@?:too:many'], ['~a', 'g0:{1,Window}'],
                        ['~a', '@?', '$1:"x":x', '!1', '~b', '!1'], ['~a', '$1:"x":bad\\q']):
            with self.subTest(records=records):
                self.assertEqual(summarize(capture(envelopes(records)))['integrity'], 'incomplete')

    def test_utf16_positions_handle_astral_and_all_javascript_line_terminators(self):
        from camoufox_trace_mcp.vv8 import source_position
        source = 'a🦊b\r\nc\rd\ne\u2028f\u2029g'
        self.assertEqual(source_position(source, 3), (1, 4))
        self.assertEqual(source_position(source, 6), (2, 1))
        self.assertEqual(source_position(source, 8), (3, 1))
        self.assertEqual(source_position(source, 10), (4, 1))
        self.assertEqual(source_position(source, 12), (5, 1))
        self.assertEqual(source_position(source, 14), (6, 1))
        self.assertIsNone(source_position(source, -1))
        self.assertIsNone(source_position(source, 100))

    def test_raw_import_export_and_incomplete_export_rejection(self):
        from camoufox_trace_mcp.vv8 import export_vv8
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            path = base / 'vv8-1-41-51-main.0.log'
            raw = '\n'.join(RAW) + '\n'
            path.write_text(raw, encoding='ascii')
            result = read_capture(path)
            self.assertEqual(len(result.events), 4)
            exported = export_vv8(result, base / 'export')
            self.assertEqual(len(exported['files']), 1)
            self.assertEqual((base / 'export' / exported['files'][0]['name']).read_text(), raw)
            reread = read_capture(base / 'export' / exported['files'][0]['name'])
            self.assertEqual((reread.events[0]['pid'], reread.events[0]['tid']), (41, 51))
            with self.assertRaises(FileExistsError):
                export_vv8(result, base / 'export')
            with self.assertRaises(ValueError):
                export_vv8(capture(envelopes(chunk=8)[:-1]), base / 'incomplete')
            self.assertFalse((base / 'incomplete').exists())

    def test_collector_and_cli_consume_engine_fragments_without_browser(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / 'capture.jsonl'
            payload = ''.join('CAMOUFOX_TRACE ' + json.dumps(row) + '\n' for row in envelopes())
            script = "import os,sys; assert os.environ['CAMOUFOX_ENGINE_TRACE']=='1'; assert os.environ['CAMOUFOX_TRACE']=='0'; sys.stderr.write(" + repr(payload) + ')'
            environment = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
            result = subprocess.run([sys.executable, '-S', '-m', 'camoufox_trace_mcp', 'collect',
                                     '--engine', '--no-bindings', '--output', str(path), '--',
                                     sys.executable, '-c', script], cwd=ROOT, env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['engine_event_count'], 4)
            events = subprocess.run([sys.executable, '-S', '-m', 'camoufox_trace_mcp', 'events',
                                     str(path), '--channel', 'engine', '--op', 'construct'],
                                    env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(events.returncode, 0, events.stderr)
            self.assertEqual(json.loads(events.stdout)['matched'], 1)

    def test_complete_long_sources_and_arguments_are_available_in_pages(self):
        from camoufox_trace_mcp.vv8 import script_source, scripts_page, raw_records_page
        source, argument = 'x' * 20000, 'a' * 40000
        records = ['~a', '@?', '$1:"long.js":' + source, '!1',
                   'c0:%log:{1,Console}:"' + argument + '"']
        rows = envelopes(records, chunk=1024)
        self.assertTrue(all(len(json.dumps(row).encode()) <= 4096 for row in rows))
        result = capture(rows)
        self.assertEqual(result.flags, set())
        self.assertEqual(result.engine.scripts[0]['source'], source)
        self.assertEqual(result.events[0]['args'][0]['value'], argument)
        self.assertNotIn('source', scripts_page(result)['scripts'][0])
        self.assertEqual(script_source(result, 0, offset=19000, limit=4096)['source'], source[19000:])
        self.assertIsNone(script_source(result, 0, offset=19000)['next_offset'])
        self.assertEqual(raw_records_page(result, tid=51)['matched'], 5)
        for kwargs in ({'offset': -1}, {'limit': 0}, {'limit': 65537}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                script_source(result, 0, **kwargs)

    def test_import_roundtrip_marks_the_source_of_supplied_identity(self):
        from camoufox_trace_mcp.vv8 import import_vv8
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            raw, output = base / 'raw.log', base / 'wrapped.jsonl'
            raw.write_text('\n'.join(RAW) + '\n', encoding='ascii')
            with self.assertRaises(ValueError):
                import_vv8(raw, output)
            self.assertFalse(output.exists())
            import_vv8(raw, output, pid=41, tid=51)
            result = read_capture(output)
            self.assertEqual(result.events[0]['identity_source'], 'import_options')
            self.assertEqual(result.engine.scripts[0]['source'], SOURCE)
            self.assertEqual([item['raw'] for stream in result.engine.streams.values()
                              for item in stream.records], RAW)
            with self.assertRaises(FileExistsError):
                import_vv8(raw, output, pid=41, tid=51)

    def test_strict_escapes_and_raw_value_tokens(self):
        from camoufox_trace_mcp.vv8 import split_fields, value_summary
        self.assertEqual(split_fields(r'a\:b:\x00:\ud83e\udd8a:'), ['a:b', '\0', '🦊', ''])
        self.assertEqual(value_summary('"a"b"')['value'], 'a"b')
        self.assertEqual(value_summary('{17,Navigator}')['class'], 'Navigator')
        self.assertEqual(value_summary('{17,key:value}')['raw'], '{17,key:value}')
        self.assertNotIn('class', value_summary('{17,key:value}'))
        for raw in ('\\', r'\x0', r'\u12', r'\uZZZZ', r'\z'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                split_fields(raw)

    def test_corrupt_transport_invalidates_context_instead_of_borrowing_it(self):
        rows = envelopes(RAW[:5])
        invalid = dict(envelopes(['~a'])[0], record=6, data='bad\nline')
        following = dict(envelopes([RAW[4]])[0], record=7)
        result = capture(rows + [invalid, following])
        self.assertIn('vv8_malformed_lines', result.flags)
        self.assertIn('vv8_missing_context', result.flags)
        self.assertIsNone(result.events[-1]['script_id'])
        self.assertIsNone(result.events[-1]['source'])

    def test_security_tokens_can_be_opaque_reference_value_summaries(self):
        result = capture(envelopes(['~a', '@"https\\://example.test/":{7,Window}',
                                    '$1:"x.js":x', '!1', 'g0:{1,Window}:"x"']))
        self.assertEqual(result.flags, set())
        self.assertEqual(result.events[0]['security_token'], '{7,Window}')

    def test_finished_captures_release_full_sources_without_waiting_for_gc(self):
        was_enabled = gc.isenabled()
        gc.disable()
        try:
            result = capture(envelopes())
            reference = weakref.ref(result)
            del result
            self.assertIsNone(reference())
        finally:
            if was_enabled:
                gc.enable()

    def test_explicit_unknown_caller_is_valid_and_does_not_borrow_previous_script(self):
        from camoufox_trace_mcp.vv8 import export_vv8
        records = RAW[:4] + ['!?', 'c-1:%native:#U', 'n-1:%URL',
                            'g-1:{1,Window}:"x"', 's-1:{1,Window}:"x":1', '!1', RAW[4]]
        result = capture(envelopes(records))
        self.assertIn('provenance_unknown', result.flags)
        self.assertNotIn('vv8_missing_context', result.flags)
        self.assertEqual(summarize(result)['integrity'], 'no_known_loss')
        for event in result.events[:-1]:
            self.assertIsNone(event['script_id'])
            self.assertIsNone(event['source'])
            self.assertTrue(event['provenance_unknown'])
        self.assertEqual(result.events[-1]['script_id'], 1)
        self.assertFalse(result.events[-1]['provenance_unknown'])
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            manifest = export_vv8(result, Path(directory) / 'export')
            actual = Path(directory) / 'export' / manifest['files'][0]['name']
            self.assertEqual(actual.read_text(), '\n'.join(records) + '\n')
        for missing in (['~a', '!?', '!99', 'c-1:%native:#U'], ['~a', 'c-1:%native:#U']):
            with self.subTest(missing=missing):
                broken = capture(envelopes(missing))
                self.assertIn('vv8_missing_context', broken.flags)
                self.assertEqual(summarize(broken)['integrity'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
