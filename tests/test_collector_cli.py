import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from camoufox_trace_mcp import read_capture, summarize
from camoufox_trace_mcp.collector import collect, collection_exit_code

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "pilot.jsonl"


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "capture.jsonl"

    def test_replay_keeps_only_marked_stderr_and_records_normal_exit(self):
        outcome = collect([sys.executable, str(ROOT / "fixtures" / "replay.py")], self.output)
        report = summarize(read_capture(self.output))
        self.assertEqual(outcome["termination"], "normal_exit")
        self.assertEqual(outcome["returncode"], 0)
        self.assertEqual(outcome["ignored_stderr_lines"], 1)
        self.assertEqual(outcome["trace_lines"], 4)
        self.assertEqual(report["event_count"], 3)
        self.assertNotIn("synthetic child stdout", self.output.read_text())
        self.assertNotIn("unrelated child stderr", self.output.read_text())
        self.assertEqual(report["collections"], [outcome])

    def test_literal_argv_environment_and_unterminated_last_line(self):
        value = ";$(echo SHOULD_NOT_EXECUTE)"
        script = ("import os,sys; assert os.environ['CAMOUFOX_TRACE']=='1'; "
                  f"assert sys.argv[1]=={value!r}; "
                  "sys.stderr.write('CAMOUFOX_TRACE {broken')")
        outcome = collect([sys.executable, "-c", script, value], self.output)
        self.assertEqual(outcome["termination"], "normal_exit")
        self.assertIn("malformed_lines", read_capture(self.output).flags)
        self.assertNotIn("{broken", self.output.read_text())

    def test_missing_executable_has_a_persisted_failure(self):
        outcome = collect([str(self.directory / "missing-executable")], self.output)
        self.assertEqual(outcome["termination"], "spawn_failed")
        self.assertEqual(collection_exit_code(outcome, 3), 127)
        self.assertIn("child_spawn_failed", read_capture(self.output).flags)

    def test_nonzero_and_signal_exits_are_explicit(self):
        outcome = collect([sys.executable, "-c", "raise SystemExit(7)"], self.output)
        self.assertEqual(outcome["termination"], "nonzero_exit")
        self.assertEqual(collection_exit_code(outcome, 3), 7)
        self.assertIn("child_nonzero_exit", read_capture(self.output).flags)
        other = self.directory / "signal.jsonl"
        outcome = collect([sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"], other)
        self.assertEqual(outcome["termination"], "signal_exit")
        self.assertEqual(collection_exit_code(outcome, 3), 128 + signal.SIGTERM)

    def test_timeout_kills_and_reaps_the_direct_child(self):
        pid_path = self.directory / "pid"
        script = f"import os,pathlib,time; pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid())); time.sleep(30)"
        started = time.monotonic()
        outcome = collect([sys.executable, "-c", script], self.output, timeout=0.3)
        self.assertEqual(outcome["termination"], "timeout")
        self.assertEqual(collection_exit_code(outcome, 65), 124)
        self.assertLess(time.monotonic() - started, 4)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_path.read_text()), 0)
        self.assertIn("child_timeout", read_capture(self.output).flags)

    def test_background_descendant_cannot_keep_collection_pipe_open(self):
        script = ("import subprocess,sys; "
                  "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])")
        started = time.monotonic()
        outcome = collect([sys.executable, "-c", script], self.output, timeout=5)
        self.assertEqual(outcome["termination"], "normal_exit")
        self.assertFalse(outcome["stderr_drain_incomplete"])
        self.assertLess(time.monotonic() - started, 4)

    def test_output_cap_is_bounded_and_reported(self):
        script = ("import pathlib,sys; "
                  f"lines=pathlib.Path({str(FIXTURE)!r}).read_text().splitlines(); "
                  "[print('CAMOUFOX_TRACE '+line,file=sys.stderr) for line in lines*100]")
        outcome = collect([sys.executable, "-c", script], self.output, max_output_bytes=1024)
        self.assertTrue(outcome["output_limited"])
        self.assertLess(self.output.stat().st_size, 2048)
        self.assertIn("collector_output_cap", read_capture(self.output).flags)
        self.assertEqual(collection_exit_code(outcome, 0), 65)

    def test_oversized_marked_line_is_recorded_without_retaining_payload(self):
        script = "import sys; sys.stderr.write('CAMOUFOX_TRACE '+('x'*1100000)+'\\n')"
        outcome = collect([sys.executable, "-c", script], self.output)
        self.assertEqual(outcome["trace_lines"], 1)
        self.assertIn("malformed_lines", read_capture(self.output).flags)
        self.assertLess(self.output.stat().st_size, 2048)

    def test_output_is_exclusive_and_invalid_options_do_not_create_files(self):
        self.output.write_text("keep me")
        with self.assertRaises(FileExistsError):
            collect([sys.executable, "-c", "pass"], self.output)
        self.assertEqual(self.output.read_text(), "keep me")
        for timeout in (0, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                collect([sys.executable], self.directory / "absent", timeout=timeout)
        with self.assertRaises(ValueError):
            collect([], self.directory / "absent")
        self.assertFalse((self.directory / "absent").exists())


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        return subprocess.run([sys.executable, "-m", "camoufox_trace_mcp", *map(str, args)],
                              cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)

    def test_documented_offline_commands(self):
        summary = self.run_cli("summarize", FIXTURE)
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertEqual(json.loads(summary.stdout)["event_count"], 3)
        events = self.run_cli("events", FIXTURE, "--api", "WebGLRenderingContext.getParameter", "--limit", 1)
        self.assertEqual(events.returncode, 0, events.stderr)
        self.assertEqual(json.loads(events.stdout)["matched"], 1)
        comparison = self.run_cli("compare", FIXTURE, FIXTURE)
        self.assertEqual(comparison.returncode, 0, comparison.stderr)
        self.assertTrue(all(item["delta"] == 0 for item in json.loads(comparison.stdout)["api_count_deltas"]))

    def test_collect_report_stdout_is_single_json_document(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            output = Path(directory) / "capture.jsonl"
            result = self.run_cli("collect", "--output", output, "--", sys.executable, "fixtures/replay.py")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["event_count"], 3)
            self.assertEqual(result.stderr, "")
            duplicate = self.run_cli("collect", "--output", output, "--", sys.executable, "fixtures/replay.py")
            self.assertEqual(duplicate.returncode, 2)
            self.assertEqual(duplicate.stdout, "")

    def test_exit_codes_for_empty_and_incomplete_captures(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "capture.jsonl"
            path.write_text("")
            result = self.run_cli("summarize", path)
            self.assertEqual(result.returncode, 3)
            self.assertIn("no_events", json.loads(result.stdout)["statuses"])
            path.write_text('CAMOUFOX_TRACE broken\n')
            result = self.run_cli("summarize", path)
            self.assertEqual(result.returncode, 65)
            self.assertIn("malformed_lines", json.loads(result.stdout)["statuses"])

    def test_core_runs_without_site_packages_or_mcp(self):
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        result = subprocess.run([sys.executable, "-S", "-m", "camoufox_trace_mcp", "summarize", str(FIXTURE)],
                                env=environment, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["event_count"], 3)


if __name__ == "__main__":
    unittest.main()
