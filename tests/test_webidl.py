import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from camoufox_trace_mcp import compare_captures, filter_events, read_capture, summarize
from camoufox_trace_mcp.reader import parse_lines

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "webidl.jsonl"
RECORDS = [json.loads(line) for line in FIXTURE.read_text().splitlines()]


def capture(*records):
    return parse_lines(json.dumps(record) for record in records)


class WebIDLReaderTests(unittest.TestCase):
    def test_generic_operations_and_scopes_round_trip_without_inference(self):
        result = read_capture(FIXTURE)
        self.assertEqual(result.events, RECORDS[1:])
        self.assertEqual(result.metadata[0]["coverage"], "webidl-bindings")
        self.assertEqual(summarize(result)["statuses"], [])
        self.assertEqual(result.events[1]["result"], {"type": "undefined"})
        self.assertEqual(result.events[3]["api"], "URL.constructor")
        old = read_capture(ROOT / "fixtures" / "pilot.jsonl")
        self.assertEqual(old.metadata[0]["coverage"], "binding-pilot")
        self.assertTrue(all("scope" not in event for event in old.events))

    def test_invalid_operations_and_explicit_invalid_scopes_are_reported(self):
        for change in ({"op": "observe"}, {"scope": "unknown"}, {"scope": None},
                       {"scope": []}, {"scope": False}):
            with self.subTest(change=change):
                result = capture(RECORDS[0], dict(RECORDS[1], **change))
                self.assertEqual(result.events, [])
                self.assertIn("malformed_lines", result.flags)


class WebIDLAnalysisTests(unittest.TestCase):
    def test_exact_operation_filters_and_combined_scope_pagination(self):
        result = read_capture(FIXTURE)
        for operation, count in (("get", 1), ("set", 1), ("call", 2), ("construct", 1)):
            with self.subTest(operation=operation):
                page = filter_events(result, op=operation)
                self.assertEqual(page["matched"], count)
                self.assertTrue(all(event["op"] == operation for event in page["events"]))
        page = filter_events(result, op="call", scope="instance", limit=1)
        self.assertEqual(page["matched"], 1)
        self.assertEqual(page["events"][0]["api"], "HTMLInputElement.focus")
        self.assertIsNone(page["next_offset"])
        self.assertEqual(filter_events(result, op="get", scope="static")["matched"], 0)
        self.assertEqual(filter_events(result, op="call", offset=1, limit=1)["events"], RECORDS[5:])

    def test_missing_scope_remains_unknown_and_can_be_selected(self):
        result = read_capture(ROOT / "fixtures" / "pilot.jsonl")
        page = filter_events(result, scope="unknown")
        self.assertEqual(page["matched"], 3)
        self.assertTrue(all("scope" not in event for event in page["events"]))
        self.assertEqual(filter_events(result, scope="instance")["matched"], 0)
        self.assertTrue(all(site["scope"] is None for site in summarize(result)["call_sites"]))
        self.assertEqual(compare_captures(result, result)["call_site_changes"], [])

    def test_static_instance_and_unknown_call_sites_do_not_merge(self):
        events = [dict(RECORDS[3], seq=index, api="Example.member", scope=scope)
                  for index, scope in enumerate(("instance", "static"), 1)]
        events.append(dict(RECORDS[3], seq=3, api="Example.member"))
        del events[-1]["scope"]
        events.append(dict(RECORDS[4], seq=4))
        sites = summarize(capture(RECORDS[0], *events))["call_sites"]
        self.assertEqual(len(sites), 4)
        self.assertEqual({site["scope"] for site in sites}, {None, "instance", "static", "constructor"})
        self.assertTrue(all(site["count"] == 1 for site in sites))

    def test_swapped_results_between_static_and_instance_are_detected(self):
        instance = dict(RECORDS[3], seq=1, api="Example.member", scope="instance",
                        result={"type": "string", "value": "first"})
        static = dict(instance, seq=2, scope="static", result={"type": "string", "value": "second"})
        baseline = capture(RECORDS[0], instance, static)
        candidate = capture(RECORDS[0], dict(instance, result=static["result"]),
                            dict(static, result=instance["result"]))
        changes = compare_captures(baseline, candidate)["call_site_changes"]
        self.assertEqual(len(changes), 2)
        self.assertEqual({change["scope"] for change in changes}, {"instance", "static"})
        reordered = capture(RECORDS[0], static, instance)
        self.assertEqual(compare_captures(baseline, reordered)["call_site_changes"], [])

    def test_invalid_operation_and_scope_filters_are_rejected(self):
        result = read_capture(FIXTURE)
        for kwargs in ({"op": "read"}, {"op": ""}, {"scope": "global"}, {"scope": ""}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                filter_events(result, **kwargs)


class WebIDLCliTests(unittest.TestCase):
    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, "-S", "-m", "camoufox_trace_mcp", "events",
                               str(FIXTURE), *arguments], cwd=ROOT,
                              env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
                              capture_output=True, text=True, timeout=5)

    def test_cli_operation_and_scope_options(self):
        for op, scope, api in (("set", "instance", "HTMLInputElement.value"),
                               ("construct", "constructor", "URL.constructor"),
                               ("call", "static", "URL.canParse")):
            with self.subTest(op=op, scope=scope):
                result = self.run_cli("--op", op, "--scope", scope)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["matched"], 1)
                self.assertEqual(report["events"][0]["api"], api)

    def test_cli_rejects_unknown_operations_and_scopes(self):
        for arguments in (("--op", "read"), ("--scope", "global")):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid choice", result.stderr)


if __name__ == "__main__":
    unittest.main()
