import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from camoufox_trace_mcp import read_capture, summarize
from camoufox_trace_mcp.vv8 import export_vv8, import_vv8
from test_vv8 import ROOT, RAW, SOURCE, OFFSET, capture, envelopes


class Vv8SegmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def segment(self, rank, records, *, tid=51, name='main'):
        path = self.base / f'vv8-100-41-{tid}-{name}.{rank}.log'
        path.write_text(''.join(record + '\n' for record in records), encoding='ascii')
        return path

    def test_numeric_segments_share_registry_instead_of_lexical_order(self):
        paths = [self.segment(0, RAW[:4])]
        for rank in range(1, 11):
            paths.append(self.segment(rank, [f's{OFFSET}:{{18,HTMLInputElement}}:"value":{rank}']))
        wrapped = self.base / 'wrapped.jsonl'
        import_vv8(sorted(paths), wrapped)
        result = read_capture(wrapped)
        self.assertEqual(result.flags, set())
        self.assertEqual([event['args'][0]['value'] for event in result.events], list(range(1, 11)))
        self.assertEqual(result.engine.scripts[0]['source'], SOURCE)
        self.assertTrue(all(event['script_id'] == 1 and event['source']['line'] == 2
                            for event in result.events))

    def test_multiple_thread_clusters_keep_separate_registries(self):
        paths = [self.segment(1, RAW[4:]), self.segment(0, RAW[:4]),
                 self.segment(1, ['g0:{7,Screen}:"width"'], tid=52, name='worker'),
                 self.segment(0, ['~b', '@?', '$1:"worker.js":x', '!1'], tid=52, name='worker')]
        wrapped = self.base / 'wrapped.jsonl'
        report = import_vv8(paths, wrapped)
        result = read_capture(wrapped)
        self.assertEqual(result.flags, set())
        self.assertEqual(len(report['streams']), 2)
        self.assertEqual(len(result.engine.scripts), 2)
        worker = [event for event in result.events if event['tid'] == 52][0]
        self.assertEqual(worker['source']['url'], 'worker.js')
        self.assertEqual(worker['isolate'], 'b')

    def test_missing_or_duplicate_segments_are_refused_before_output(self):
        first = self.segment(0, RAW[:4])
        last = self.segment(2, RAW[4:])
        for paths in ([last], [first, last], [first, first]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                import_vv8(paths, self.base / 'must-not-exist.jsonl')
            self.assertFalse((self.base / 'must-not-exist.jsonl').exists())

    def test_rollover_preserves_whole_records_and_native_manifest_identity(self):
        result = capture(envelopes())
        exported = export_vv8(result, self.base / 'export', segment_bytes=40)
        self.assertGreater(len(exported['files']), 1)
        self.assertEqual([item['segment'] for item in exported['files']], list(range(len(exported['files']))))
        self.assertEqual(sum(item['records'] for item in exported['files']), len(RAW))
        joined = ''
        paths = []
        for item in exported['files']:
            self.assertEqual((item['pid'], item['tid']), (41, 51))
            path = self.base / 'export' / item['name']
            self.assertEqual(item['bytes'], path.stat().st_size)
            joined += path.read_text()
            paths.append(path)
        self.assertEqual(joined, '\n'.join(RAW) + '\n')
        self.assertEqual(joined.count('$1:'), 1)
        self.assertTrue(all(item['bytes'] > 40 for item in exported['files'][:-1]))
        self.assertEqual(exported['files'][0]['first_record'], 1)
        self.assertEqual(exported['files'][-1]['last_record'], len(RAW))
        self.assertEqual(exported['filename_timestamp'], 'export_creation_time_not_event_time')
        wrapped = self.base / 'rolled.jsonl'
        import_vv8(list(reversed(paths)), wrapped)
        reread = read_capture(wrapped)
        self.assertEqual(reread.flags, set())
        self.assertEqual([event['vv8_raw'] for event in reread.events], RAW[4:])
        for invalid in (0, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                export_vv8(result, self.base / 'invalid', segment_bytes=invalid)
            self.assertFalse((self.base / 'invalid').exists())

    def test_segment_boundaries_and_reused_stream_identities_are_not_silently_merged(self):
        first, second = self.segment(0, RAW[:4]), self.segment(1, RAW[4:])
        first.write_bytes(first.read_bytes().rstrip(b'\n'))
        with self.assertRaises(ValueError):
            import_vv8([first, second], self.base / 'truncated.jsonl')
        self.assertFalse((self.base / 'truncated.jsonl').exists())
        first.write_text('\n'.join(RAW) + '\n', encoding='ascii')
        other = self.base / 'vv8-200-41-51-main.0.log'
        other.write_bytes(first.read_bytes())
        with self.assertRaises(ValueError):
            import_vv8([first, other], self.base / 'ambiguous.jsonl')
        self.assertFalse((self.base / 'ambiguous.jsonl').exists())

    def test_cli_import_accepts_multiple_explicit_segment_paths(self):
        first, second = self.segment(0, RAW[:4]), self.segment(1, RAW[4:])
        output = self.base / 'cli.jsonl'
        result = subprocess.run([sys.executable, '-S', '-m', 'camoufox_trace_mcp', 'import-vv8',
                                 str(second), str(first), '--output', str(output)],
                                cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(summarize(read_capture(output))['engine_event_count'], 4)

    def test_literal_and_json_escaped_percent_fragments_roundtrip_with_byte_limits(self):
        argument = '%o%O%j%%s' * 1000
        records = ['~a', '@?', '$1:"percent.js":x', '!1', f'c0:%log:{{1,Console}}:"{argument}"']
        raw = self.segment(0, records)
        output = self.base / 'percent.jsonl'
        import_vv8(raw, output)
        lines = output.read_text().splitlines()
        self.assertTrue(all(len(line.encode('ascii')) <= 4096 for line in lines))
        self.assertEqual(read_capture(output).events[0]['args'][0]['value'], argument)
        escaped = [json.dumps(row, separators=(',', ':')).replace('%', r'\u0025')
                   for row in envelopes(records, chunk=128)]
        self.assertTrue(all(len(line.encode('ascii')) <= 4096 for line in escaped))
        from camoufox_trace_mcp.reader import parse_lines
        self.assertEqual(parse_lines(escaped).events[0]['args'][0]['value'], argument)


if __name__ == '__main__':
    unittest.main()
