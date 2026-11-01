import hashlib
import errno
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from camoufox_trace_mcp.collector import collect, collection_exit_code
from camoufox_trace_mcp.reader import MAX_LINE_BYTES


class RawStderrTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / 'trace.jsonl'
        self.raw = self.directory / 'private.stderr'

    def run_bytes(self, data, **options):
        return collect([sys.executable, '-c', f'import os; os.write(2, {data!r})'],
                       self.output, **options)

    def test_invalid_json_has_absolute_byte_offset_without_raw_payload(self):
        prefix = b'ignored\r\n[child] CAMOUFOX_TRACE '
        payload = '{"secret":"\u4e2d",}'.encode()
        self.run_bytes(prefix + payload + b'\n')
        record = json.loads(self.output.read_text().splitlines()[0])
        self.assertEqual(record['stderr_byte_offset'], len(b'ignored\r\n'))
        self.assertEqual(record['payload_byte_offset'], len(prefix))
        self.assertEqual(record['error_byte_offset'], len(prefix) + len(payload) - 1)
        self.assertNotIn('secret', self.output.read_text())

    def test_private_raw_preserves_invalid_utf8_ignored_and_unterminated_bytes(self):
        data = b'ignored\x00\r\nCAMOUFOX_TRACE {"bad":\xff}\nlast private byte\x80'
        outcome = self.run_bytes(data, raw_stderr_path=self.raw)
        self.assertEqual(self.raw.read_bytes(), data)
        self.assertEqual(self.raw.stat().st_mode & 0o777, 0o600)
        metadata = outcome['raw_stderr']
        self.assertEqual(metadata['status'], 'complete')
        self.assertEqual(metadata['observed_bytes'], len(data))
        self.assertEqual(metadata['captured_bytes'], len(data))
        self.assertEqual(metadata['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(outcome['ignored_stderr_lines'], 2)
        public = self.output.read_text()
        self.assertNotIn('last private byte', public)
        self.assertNotIn(str(self.raw), public)
        self.assertEqual(json.loads(public.splitlines()[0])['error_kind'], 'invalid_utf8')

    def test_raw_cap_retains_exact_prefix_and_reports_incomplete_evidence(self):
        data = b'private diagnostic' * 100
        outcome = self.run_bytes(data, raw_stderr_path=self.raw, max_raw_stderr_bytes=17)
        self.assertEqual(self.raw.read_bytes(), data[:17])
        metadata = outcome['raw_stderr']
        self.assertEqual(metadata['status'], 'byte_limit')
        self.assertEqual(metadata['max_bytes'], 17)
        self.assertEqual(metadata['observed_bytes'], len(data))
        self.assertEqual(metadata['captured_bytes'], 17)
        self.assertEqual(metadata['sha256'], hashlib.sha256(data[:17]).hexdigest())
        self.assertEqual(outcome['termination'], 'normal_exit')
        self.assertEqual(collection_exit_code(outcome, 0), 65)

    def test_exact_cap_is_complete_and_default_does_not_create_raw_file(self):
        data = b'plain stderr'
        outcome = self.run_bytes(data, raw_stderr_path=self.raw, max_raw_stderr_bytes=len(data))
        self.assertEqual(outcome['raw_stderr']['status'], 'complete')
        self.output.unlink()
        outcome = self.run_bytes(data)
        self.assertNotIn('raw_stderr', outcome)

    def test_write_failure_retains_hash_of_written_prefix_without_private_error_text(self):
        data = b'private diagnostic message'
        native_write = os.write
        calls = 0

        def failed_write(fd, pending):
            nonlocal calls
            calls += 1
            if calls == 1:
                return native_write(fd, pending[:3])
            raise OSError(errno.ENOSPC, 'sensitive diagnostic path')

        with patch('camoufox_trace_mcp.collector.os.write', side_effect=failed_write):
            outcome = self.run_bytes(data, raw_stderr_path=self.raw)
        metadata = outcome['raw_stderr']
        self.assertEqual(metadata['status'], 'write_error')
        self.assertEqual(metadata['error_errno'], errno.ENOSPC)
        self.assertEqual(metadata['captured_bytes'], 3)
        self.assertEqual(metadata['observed_bytes'], len(data))
        self.assertEqual(metadata['sha256'], hashlib.sha256(data[:3]).hexdigest())
        self.assertEqual(self.raw.read_bytes(), data[:3])
        self.assertNotIn('sensitive diagnostic path', self.output.read_text())
        self.assertEqual(collection_exit_code(outcome, 0), 65)

    def test_fsync_failure_is_persisted_before_collection_outcome(self):
        with patch('camoufox_trace_mcp.collector.os.fsync', side_effect=OSError(errno.EIO, 'private')):
            outcome = self.run_bytes(b'data', raw_stderr_path=self.raw)
        self.assertEqual(outcome['raw_stderr']['status'], 'write_error')
        saved = json.loads(self.output.read_text().splitlines()[-1])
        self.assertEqual(saved, outcome)

    def test_offsets_remain_correct_after_dropping_an_oversized_line(self):
        size = MAX_LINE_BYTES + 100000
        script = (f'import os; first=b"CAMOUFOX_TRACE "+b"x"*{size}+b"\\n"; '
                  'os.write(2, first); os.write(2, b"CAMOUFOX_TRACE {broken\\n")')
        outcome = collect([sys.executable, '-c', script], self.output, raw_stderr_path=self.raw)
        records = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertEqual(records[0]['reason'], 'line_too_long')
        self.assertEqual(records[1]['stderr_byte_offset'], len(b'CAMOUFOX_TRACE ') + size + 1)
        self.assertEqual(records[1]['stderr_line'], 2)
        self.assertEqual(outcome['raw_stderr']['captured_bytes'], self.raw.stat().st_size)

    def test_raw_file_is_exclusive_and_options_are_validated_before_launch(self):
        self.raw.write_bytes(b'existing evidence')
        with self.assertRaises(FileExistsError):
            self.run_bytes(b'new', raw_stderr_path=self.raw)
        self.assertEqual(self.raw.read_bytes(), b'existing evidence')
        self.output.unlink()
        for value in (0, -1, True, 1.5, 2**40):
            with self.assertRaises(ValueError):
                self.run_bytes(b'new', raw_stderr_path=self.raw, max_raw_stderr_bytes=value)
        with self.assertRaises(ValueError):
            self.run_bytes(b'new', raw_stderr_path=self.output)
        self.assertFalse(self.output.exists())

    def test_spawn_failure_keeps_empty_raw_evidence_explicit(self):
        outcome = collect([str(self.directory / 'missing')], self.output, raw_stderr_path=self.raw)
        self.assertEqual(outcome['raw_stderr']['status'], 'spawn_failed')
        self.assertEqual(outcome['raw_stderr']['sha256'], hashlib.sha256(b'').hexdigest())
        self.assertEqual(collection_exit_code(outcome, 0), 127)


if __name__ == '__main__':
    unittest.main()
