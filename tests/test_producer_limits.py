import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from camoufox_trace_mcp import filter_events, read_capture, summarize
from camoufox_trace_mcp.analysis import analysis_exit_code
from camoufox_trace_mcp.collector import collect
from camoufox_trace_mcp.reader import parse_lines
from camoufox_trace_mcp.vv8 import export_vv8, import_vv8, raw_records_page, script_source, scripts_page
from test_vv8 import ROOT, envelopes


class ProducerLimitTests(unittest.TestCase):
    def unavailable(self, **extra):
        return {'schema': 1, 'event': 'source_unavailable', 'channel': 'engine', 'pid': 41, 'tid': 51,
                'source_id': 0, 'reason': 'source_missing', 'filename': None,
                'introduction_type': None, 'retrievable': False, **extra}

    def test_unavailable_previews_are_bounded_pages_are_independent_and_manifest_keeps_every_control(self):
        controls = [self.unavailable(source_id=index) for index in range(100, 305)]
        raw = ['~a', '@?', '$1:"fixture.js":x;', '!1', 'g0:{1,Window}:"x"']
        capture = parse_lines(json.dumps(row) for row in controls + envelopes(raw))
        for report in (summarize(capture)['engine'], filter_events(capture, limit=1),
                       raw_records_page(capture, offset=1, limit=1), script_source(capture, 0, limit=1)):
            self.assertEqual(report['source_unavailable'], controls[:100])
            self.assertEqual(report['source_unavailable_count'], 205)
            self.assertTrue(report['source_unavailable_limited'])
        recovered, offset = [], 0
        while offset is not None:
            page = scripts_page(capture, offset=offset, limit=73)
            self.assertEqual(page['matched'], 1)
            self.assertIsNone(page['next_offset'])
            self.assertEqual(len(page['scripts']), 1 if offset == 0 else 0)
            self.assertEqual(page['source_unavailable_matched'], 205)
            self.assertEqual(page['source_unavailable_offset'], offset)
            self.assertEqual(page['source_unavailable_limit'], 73)
            self.assertLessEqual(len(page['source_unavailable']), 73)
            recovered.extend(page['source_unavailable'])
            offset = page['source_unavailable_next_offset']
        self.assertEqual(recovered, controls)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'export'
            manifest = export_vv8(capture, destination)
            self.assertEqual(manifest['source_unavailable'], controls)
            self.assertEqual(manifest['source_unavailable_count'], 205)
            self.assertFalse(manifest['source_unavailable_limited'])
            imported = Path(directory) / 'imported.jsonl'
            import_vv8([destination / entry['name'] for entry in manifest['files']], imported,
                       manifest=destination / 'manifest.json')
            self.assertEqual(read_capture(imported).engine.source_unavailable, controls)

    def test_missing_source_is_metadata_without_transport_loss_or_a_fabricated_script(self):
        control = self.unavailable(scope='source', truncated=False)
        records = ['~a', '@?', '!?', 'c-1:%native:#U']
        capture = parse_lines(json.dumps(row) for row in [control] + envelopes(records))
        report = summarize(capture, channel='engine')
        self.assertEqual(report['integrity'], 'no_known_loss')
        self.assertIn('source_unavailable', report['statuses'])
        self.assertNotIn('unknown_events', report['statuses'])
        self.assertFalse(report['engine']['source_provenance_complete'])
        self.assertEqual(report['engine']['source_unavailable'], [control])
        self.assertEqual(capture.engine.scripts, [])
        self.assertIsNone(capture.events[0]['source'])
        self.assertEqual(analysis_exit_code(capture), 0)
        self.assertEqual(raw_records_page(capture)['source_unavailable'], [control])
        retried = dict(control, reason='source_not_loaded', retrievable=True)
        recovered = parse_lines(json.dumps(row) for row in [retried] + envelopes(records + [
            '$0:"recovered.js":recovered();', '!0', 'g0:{1,Window}:"x"']))
        self.assertEqual(recovered.engine.scripts[0]['source'], 'recovered();')
        self.assertEqual(recovered.engine.summary()['source_unavailable'], [retried])
        self.assertFalse(recovered.engine.summary()['source_provenance_complete'])
        self.assertEqual(summarize(recovered)['integrity'], 'no_known_loss')

    def test_source_provenance_scope_does_not_claim_binding_source_or_global_coverage(self):
        for capture in (parse_lines([]), read_capture(ROOT / 'fixtures/pilot.jsonl')):
            with self.subTest(events=len(capture.events)):
                availability = capture.engine.source_availability()
                self.assertFalse(availability['source_provenance_complete'])
                self.assertEqual(availability['source_provenance_scope'], 'observed_engine_sources')
        registered = read_capture(ROOT / 'fixtures/engine.jsonl')
        self.assertTrue(registered.engine.source_availability()['source_provenance_complete'])

    def test_source_metadata_cannot_replace_a_missing_registration_or_repair_unknown_script_ids(self):
        control = self.unavailable(source_id=37)
        cases = [(['~a', '@?', '!37', 'c-1:%native:#U'], 'vv8_missing_context'),
                 (['~a', '@?', 'c-1:%native:#U'], 'vv8_missing_context'),
                 (['~a', '@?', '$2:37:child();', '!2', 'g0:{1,Window}:"x"'], 'vv8_unknown_parent')]
        for records, status in cases:
            with self.subTest(records=records), tempfile.TemporaryDirectory() as directory:
                capture = parse_lines(json.dumps(row) for row in [control] + envelopes(records))
                self.assertIn(status, capture.flags)
                self.assertEqual(summarize(capture)['integrity'], 'incomplete')
                with self.assertRaises(ValueError):
                    export_vv8(capture, Path(directory) / 'export')
                raw = Path(directory) / 'vv8-1-41-51-case.0.log'
                raw.write_text('\n'.join(records) + '\n')
                manifest = Path(directory) / 'manifest.json'
                manifest.write_text(json.dumps({'format': 'visiblev8', 'files': [{'name': raw.name}],
                                                'statuses': [], 'source_unavailable': [control],
                                                'source_provenance_complete': True}))
                output = Path(directory) / 'must-not-exist.jsonl'
                with self.assertRaises(ValueError):
                    import_vv8(raw, output, manifest=manifest)
                self.assertFalse(output.exists())

    def test_no_shell_collector_preserves_source_controls_and_api_records(self):
        control = self.unavailable()
        rows = [control] + envelopes(['~a', '@?', '!?', 'c-1:%native:#U'])
        stderr = ''.join('CAMOUFOX_TRACE ' + json.dumps(row) + '\n' for row in rows)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'collected.jsonl'
            outcome = collect([sys.executable, '-S', '-c', 'import sys; sys.stderr.write(sys.argv[1])', stderr],
                              output, timeout=5, engine=True, binding=False)
            self.assertEqual(outcome['termination'], 'normal_exit')
            capture = read_capture(output)
            self.assertEqual(capture.engine.summary()['source_unavailable'], [control])
            self.assertEqual(summarize(capture)['integrity'], 'no_known_loss')
            self.assertEqual(len(capture.events), 1)

    def test_available_child_keeps_its_source_and_unknown_parent_without_losing_metadata(self):
        control = self.unavailable(source_id=2, reason='introduction_cycle', scope='introduction',
                                   introduction_source_id=1, filename='child.js',
                                   introduction_type='eval', filename_truncated=False,
                                   introduction_type_truncated=False, retrievable=True)
        records = ['~a', '@?', '$2:#?:child();', '!2', 'g0:{1,Window}:"x"']
        capture = parse_lines(json.dumps(row) for row in envelopes(records) + [control])
        self.assertEqual(summarize(capture)['integrity'], 'no_known_loss')
        page = scripts_page(capture)
        self.assertEqual(page['source_unavailable'], [control])
        self.assertFalse(page['source_provenance_complete'])
        self.assertTrue(page['scripts'][0]['parent_unknown'])
        source = script_source(capture, 0)
        self.assertEqual(source['source'], 'child();')
        self.assertEqual(source['source_unavailable'], [control])
        self.assertFalse(source['source_provenance_complete'])
        self.assertEqual(capture.events[0]['script_id'], 2)

    def test_source_metadata_roundtrips_in_an_explicit_export_manifest(self):
        control = self.unavailable(reason='source_not_loaded', retrievable=True)
        records = ['~a', '@?', '!?', 'c-1:%native:#U']
        capture = parse_lines(json.dumps(row) for row in envelopes(records) + [control])
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'export'
            manifest = export_vv8(capture, destination)
            self.assertEqual(manifest['source_unavailable'], [control])
            self.assertFalse(manifest['source_provenance_complete'])
            raw = destination / manifest['files'][0]['name']
            self.assertEqual(raw.read_text(), '\n'.join(records) + '\n')
            imported = Path(directory) / 'imported.jsonl'
            import_vv8(raw, imported, manifest=destination / 'manifest.json')
            reread = read_capture(imported)
            self.assertEqual(summarize(reread)['integrity'], 'no_known_loss')
            self.assertEqual(reread.engine.summary()['source_unavailable'], [control])
            self.assertEqual([event['vv8_raw'] for event in reread.events], [records[-1]])
            command = [sys.executable, '-S', '-m', 'camoufox_trace_mcp', 'import-vv8', str(raw),
                       '--manifest', str(destination / 'manifest.json'), '--output', str(Path(directory) / 'cli.jsonl')]
            result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(read_capture(Path(directory) / 'cli.jsonl').engine.summary()['source_unavailable'], [control])

    def test_manifest_import_rejects_mismatched_invalid_or_known_loss_metadata(self):
        control = self.unavailable()
        capture = parse_lines(json.dumps(row) for row in envelopes(['~a', '@?', '!?', 'c-1:%native:#U']) + [control])
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'export'
            manifest = export_vv8(capture, destination)
            raw = destination / manifest['files'][0]['name']
            variants = [dict(manifest, statuses=['producer_stopped']), dict(manifest, files=[]),
                        dict(manifest, source_unavailable=[dict(control, retrievable=1)]),
                        dict(manifest, source_unavailable=[dict(control, schema=2)])]
            sidecar = Path(directory) / 'invalid.json'
            for index, variant in enumerate(variants):
                with self.subTest(index=index):
                    sidecar.write_text(json.dumps(variant))
                    output = Path(directory) / f'invalid-{index}.jsonl'
                    with self.assertRaises(ValueError):
                        import_vv8(raw, output, manifest=sidecar)
                    self.assertFalse(output.exists())
            with self.assertRaises(ValueError):
                import_vv8(raw, Path(directory) / 'override.jsonl', pid=99, manifest=destination / 'manifest.json')

    def test_invalid_source_metadata_is_rejected_without_relaxing_the_known_loss_boundary(self):
        for change in ({'pid': 0}, {'tid': True}, {'source_id': -1}, {'source_id': 2 ** 32},
                       {'filename': 1}, {'introduction_type': []}, {'retrievable': 1},
                       {'reason': ''}, {'scope': 'invented'}, {'truncated': 'false'},
                       {'introduction_source_id': -1}):
            with self.subTest(change=change):
                capture = parse_lines([json.dumps(self.unavailable(**change))])
                self.assertIn('malformed_lines', capture.flags)
                self.assertEqual(summarize(capture)['integrity'], 'incomplete')

    def test_missing_source_and_actual_source_error_are_distinct(self):
        control = self.unavailable()
        rows = [control] + envelopes(['~a', '@?', '!?', 'c-1:%native:#U'])
        missing = parse_lines(json.dumps(row) for row in rows)
        failed = parse_lines(json.dumps(row) for row in rows + [
            {'schema': 1, 'event': 'limit', 'channel': 'engine', 'pid': 41,
             'emitted': 4, 'reason': 'engine_source_load_oom'}])
        self.assertEqual(summarize(missing)['integrity'], 'no_known_loss')
        self.assertEqual(summarize(failed)['integrity'], 'incomplete')
        self.assertIn('producer_stopped', failed.flags)
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            export_vv8(failed, Path(directory) / 'export')

    def test_actual_source_context_stop_after_two_records_is_not_an_event_cap(self):
        limit = {'schema': 1, 'event': 'limit', 'pid': 4758, 'channel': 'engine',
                 'emitted': 2, 'reason': 'engine_source_or_context'}
        capture = parse_lines(json.dumps(row) for row in envelopes(['~a', '@?'], pid=4758) + [limit])
        summary = summarize(capture, channel='engine')
        self.assertIn('producer_stopped', summary['statuses'])
        self.assertNotIn('producer_event_cap', summary['statuses'])
        self.assertEqual(summary['limits'], [limit])
        self.assertEqual(summary['integrity'], 'incomplete')
        self.assertEqual(analysis_exit_code(capture), 65)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'export'
            with self.assertRaises(ValueError):
                export_vv8(capture, output)
            self.assertFalse(output.exists())

    def test_other_engine_stops_remain_known_loss_and_keep_unknown_provenance_separate(self):
        for reason in ('engine_value', 'engine_transport', 'engine_future_failure', None):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                limit = {'schema': 1, 'event': 'limit', 'pid': 41, 'channel': 'engine', 'emitted': 4}
                if reason is not None:
                    limit['reason'] = reason
                rows = envelopes(['~a', '@?', '!?', 'c-1:%native:#U']) + [limit]
                capture = parse_lines(json.dumps(row) for row in rows)
                summary = summarize(capture)
                self.assertIn('producer_stopped', summary['statuses'])
                self.assertNotIn('producer_event_cap', summary['statuses'])
                self.assertIn('provenance_unknown', summary['statuses'])
                self.assertEqual(summary['integrity'], 'incomplete')
                self.assertEqual(summary['limits'], [limit])
                self.assertEqual(analysis_exit_code(capture), 65)
                with self.assertRaises(ValueError):
                    export_vv8(capture, Path(directory) / 'export')

    def test_engine_record_caps_and_legacy_binding_limits_keep_the_cap_status(self):
        for extra in ({'channel': 'engine', 'reason': 'engine_record_cap'}, {},
                      {'channel': 'binding'}, {'reason': 'invalid_max_events'},
                      {'channel': 'binding', 'reason': 'invalid_max_events'}):
            with self.subTest(extra=extra):
                limit = {'schema': 1, 'event': 'limit', 'pid': 41, 'emitted': 0, **extra}
                capture = parse_lines([json.dumps(limit)])
                summary = summarize(capture)
                self.assertIn('producer_event_cap', summary['statuses'])
                self.assertNotIn('producer_stopped', summary['statuses'])
                self.assertEqual(summary['limits'], [limit])
                self.assertEqual(summary['integrity'], 'incomplete')

    def test_invalid_limit_counts_stay_malformed(self):
        for count in (-1, True, '2', None):
            with self.subTest(count=count):
                limit = {'schema': 1, 'event': 'limit', 'pid': 41, 'channel': 'engine',
                         'reason': 'engine_source_or_context', 'emitted': count}
                capture = parse_lines([json.dumps(limit)])
                self.assertIn('malformed_lines', capture.flags)
                self.assertEqual(capture.limits, [])
                self.assertEqual(analysis_exit_code(capture), 65)

    def test_cli_reports_the_stop_reason_and_refuses_complete_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stopped.jsonl'
            rows = envelopes(['~a', '@?']) + [{'schema': 1, 'event': 'limit', 'pid': 41,
                                             'channel': 'engine', 'emitted': 2, 'reason': 'engine_transport'}]
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            command = [sys.executable, '-S', '-m', 'camoufox_trace_mcp']
            options = dict(cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
                           capture_output=True, text=True, timeout=5)
            summary = subprocess.run(command + ['summarize', str(path)], **options)
            self.assertEqual(summary.returncode, 65, summary.stderr)
            report = json.loads(summary.stdout)
            self.assertIn('producer_stopped', report['statuses'])
            self.assertNotIn('producer_event_cap', report['statuses'])
            self.assertEqual(report['limits'][0]['reason'], 'engine_transport')
            output = Path(directory) / 'export'
            exported = subprocess.run(command + ['export-vv8', str(path), '--output', str(output)], **options)
            self.assertEqual(exported.returncode, 2)
            self.assertIn('cannot export a capture with known loss', exported.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
