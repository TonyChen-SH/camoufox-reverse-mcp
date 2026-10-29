import copy
import io
import json
import math
import unittest
from pathlib import Path

from camoufox_trace_mcp import compare_captures, filter_events, read_capture, summarize
from camoufox_trace_mcp.analysis import analysis_exit_code
from camoufox_trace_mcp.reader import MAX_LINE_BYTES, decode_object, parse_lines, read_stream

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "pilot.jsonl"
RECORDS = [json.loads(line) for line in FIXTURE.read_text().splitlines()]


def capture(*records, **kwargs):
    return parse_lines([json.dumps(record) for record in records], **kwargs)


class ReaderTests(unittest.TestCase):
    def test_json_integer_negative_zero_preserves_its_sign_and_integer_types(self):
        record = decode_object('{"negative_zero":-0,"zero":0,"negative":-1,"positive":1}')
        self.assertIs(type(record["negative_zero"]), float)
        self.assertEqual(math.copysign(1, record["negative_zero"]), -1)
        for key in ("zero", "negative", "positive"):
            self.assertIs(type(record[key]), int)
        for token in ("-00", "-01", "+0"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                decode_object('{"value":' + token + '}')

    def test_native_negative_zero_survives_in_arguments_and_result(self):
        event = dict(RECORDS[1], args=[{"type": "number", "value": -0.0}],
                     result={"type": "number", "value": -0.0})
        payload = json.dumps(event).replace("-0.0", "-0")
        result = parse_lines([json.dumps(RECORDS[0]), payload])
        self.assertEqual(result.flags, set())
        for value in (result.events[0]["args"][0]["value"], result.events[0]["result"]["value"]):
            self.assertIs(type(value), float)
            self.assertEqual(math.copysign(1, value), -1)

    def test_native_round_trip_preserves_all_event_fields_and_column(self):
        result = read_capture(FIXTURE)
        self.assertEqual(result.events, RECORDS[1:])
        report = summarize(result)
        self.assertEqual(report["integrity"], "no_known_loss")
        self.assertEqual(report["statuses"], [])
        self.assertEqual(report["metadata"][0]["source_column"], "one-origin")
        self.assertEqual(result.events[0]["source"]["column"], 1)
        self.assertEqual(report["event_count"], 3)

    def test_prefixed_driver_lines_and_unrelated_stderr(self):
        result = parse_lines(["driver: CAMOUFOX_TRACE " + json.dumps(item) for item in RECORDS]
                             + ["normal browser stderr", '{"message":"not a trace"}',
                                "NOT_CAMOUFOX_TRACE {}"])
        self.assertEqual(len(result.events), 3)
        self.assertEqual(result.ignored_lines, 3)
        self.assertEqual(result.flags, set())

    def test_missing_events_and_metadata_are_explicit(self):
        report = summarize(parse_lines(["browser started"]))
        self.assertEqual(report["state"], "no_events")
        self.assertEqual(report["statuses"], ["no_events", "no_producer_metadata"])
        self.assertIn("do not establish absence of detection", report["interpretation"])
        self.assertEqual(analysis_exit_code(parse_lines([])), 3)

    def test_metadata_is_required_for_each_observed_pid(self):
        event = dict(RECORDS[1], pid=999)
        report = summarize(capture(RECORDS[0], event))
        self.assertEqual(report["missing_metadata_pids"], [999])
        self.assertIn("no_producer_metadata", report["statuses"])

    def test_producer_cap_and_reader_cap_preserve_limit_record(self):
        limit = {"schema": 1, "event": "limit", "pid": 4242, "emitted": 3}
        result = capture(*RECORDS, limit, max_events=1)
        report = summarize(result)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.limits, [limit])
        self.assertEqual(report["integrity"], "incomplete")
        self.assertIn("producer_event_cap", report["statuses"])
        self.assertIn("reader_event_cap", report["statuses"])
        self.assertEqual(analysis_exit_code(result), 65)

    def test_malformed_unsupported_and_unknown_records_do_not_disappear(self):
        result = parse_lines(["CAMOUFOX_TRACE {broken", '{"schema":2,"event":"api"}',
                              '{"schema":true,"event":"api"}',
                              '{"schema":1,"event":"future","pid":4}',
                              'CAMOUFOX_TRACE {"schema":1,"schema":2}'])
        self.assertEqual(result.issue_counts["malformed_lines"], 2)
        self.assertEqual(result.issue_counts["unsupported_schema"], 2)
        self.assertEqual(result.issue_counts["unknown_events"], 1)
        self.assertEqual(summarize(result)["integrity"], "incomplete")

    def test_invalid_native_fields_are_rejected(self):
        changes = [{"pid": True}, {"seq": 0}, {"threw": "false"}, {"source": {}},
                   {"source": {"url": None, "line": -1, "column": 1}},
                   {"result": {"type": "number", "value": 10 ** 500}},
                   {"args": [{"type": "object", "length": -1}]}]
        for change in changes:
            with self.subTest(change=list(change)):
                result = capture(dict(RECORDS[1], **change))
                self.assertEqual(result.events, [])
                self.assertIn("malformed_lines", result.flags)

    def test_null_source_and_formatted_stack_are_preserved(self):
        event = dict(RECORDS[1], source=None, realm_class=None, stack="probe@example.test:2:1")
        result = capture(RECORDS[0], event)
        self.assertEqual(result.events[0], event)
        self.assertIsNone(summarize(result)["sources"][0]["source"])

    def test_sequence_discontinuities_are_per_process(self):
        other = dict(RECORDS[1], pid=999)
        result = capture(RECORDS[0], RECORDS[1], other, RECORDS[2])
        self.assertNotIn("sequence_discontinuity", result.flags)
        gap = capture(RECORDS[0], RECORDS[2])
        self.assertIn("sequence_discontinuity", gap.flags)

    def test_nested_calls_may_complete_out_of_sequence(self):
        result = capture(RECORDS[0], RECORDS[2], RECORDS[1], RECORDS[3])
        self.assertNotIn("sequence_discontinuity", result.flags)
        duplicate = capture(RECORDS[0], RECORDS[1], RECORDS[1])
        self.assertIn("sequence_discontinuity", duplicate.flags)

    def test_utf8_input_caps_and_overlong_lines(self):
        invalid = read_stream(io.BytesIO(b"CAMOUFOX_TRACE \xff\n"))
        self.assertIn("malformed_lines", invalid.flags)
        capped = read_stream(io.BytesIO(FIXTURE.read_bytes()), max_input_bytes=30)
        self.assertIn("reader_input_cap", capped.flags)
        oversized = read_stream(io.BytesIO(b"x" * (MAX_LINE_BYTES + 5) + b"\n" + FIXTURE.read_bytes()))
        self.assertEqual(len(oversized.events), 3)
        self.assertEqual(oversized.issue_counts["malformed_lines"], 1)

    def test_issue_details_and_record_retention_are_bounded(self):
        result = parse_lines(["CAMOUFOX_TRACE broken"] * 80)
        self.assertEqual(len(result.issues), 50)
        self.assertEqual(result.issue_counts["malformed_lines"], 80)
        limited = capture(*RECORDS, max_records=2)
        self.assertIn("reader_record_cap", limited.flags)
        self.assertEqual(len(limited.events), 1)

    def test_truncation_of_values_is_explicit(self):
        event = copy.deepcopy(RECORDS[1])
        event["result"]["truncated"] = True
        report = summarize(capture(RECORDS[0], event))
        self.assertIn("value_truncation", report["statuses"])
        self.assertEqual(report["apis"][0]["truncated"], 1)

    def test_legacy_requires_opt_in_and_keeps_native_site_out_of_js_source(self):
        legacy = {"o": "navigator", "p": "userAgent", "v": "", "t": 0,
                  "k": 0, "u": 0, "w": 0, "q": 0, "s": "native site"}
        rejected = capture(legacy)
        self.assertIn("malformed_lines", rejected.flags)
        result = capture(legacy, allow_legacy=True)
        event = result.events[0]
        self.assertIsNone(event["source"])
        self.assertNotIn("result", event)
        self.assertEqual(event["legacy_record"], legacy)
        self.assertEqual(event["event_time_values"], "unavailable")
        self.assertIn("legacy_coverage", summarize(result)["statuses"])
        self.assertEqual(filter_events(result, source_url="native site")["matched"], 0)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.capture = read_capture(FIXTURE)

    def test_filter_pagination_and_exact_filters(self):
        page = filter_events(self.capture, source_url="https://example.test/probe.js", limit=2)
        self.assertEqual(page["matched"], 3)
        self.assertEqual(page["next_offset"], 2)
        self.assertEqual(filter_events(self.capture, offset=2)["events"], RECORDS[3:])
        self.assertEqual(filter_events(self.capture, api="Navigator.userAgent", pid=4242)["matched"], 1)
        self.assertEqual(filter_events(self.capture, threw=True)["events"], RECORDS[3:])
        self.assertEqual(filter_events(self.capture, offset=100)["events"], [])
        for kwargs in ({"limit": 0}, {"limit": 1001}, {"offset": -1}, {"pid": True}):
            with self.assertRaises(ValueError):
                filter_events(self.capture, **kwargs)

    def test_comparison_reports_count_deltas_and_each_side_status(self):
        result = compare_captures(capture(*RECORDS[:2]), self.capture)
        counts = {item["api"]: item["delta"] for item in result["api_count_deltas"]}
        self.assertEqual(counts["Navigator.userAgent"], 0)
        self.assertEqual(counts["HTMLCanvasElement.toDataURL"], 1)
        self.assertEqual(sum(item["delta"] for item in result["source_count_deltas"]), 2)
        self.assertEqual(result["baseline"]["event_count"], 1)
        self.assertIn("not matched calls", result["comparison"])

    def test_changed_return_at_same_call_site_is_visible(self):
        changed = copy.deepcopy(RECORDS)
        changed[1]["result"]["value"] = "different observed value"
        result = compare_captures(self.capture, capture(*changed))
        change = result["call_site_changes"][0]
        self.assertEqual(change["api"], "Navigator.userAgent")
        self.assertEqual(change["source"]["line"], 2)
        self.assertEqual(change["candidate"]["result_variants"][0]["result"]["value"],
                         "different observed value")

    def test_process_id_changes_do_not_invent_call_site_changes(self):
        other = [dict(item, pid=999) for item in RECORDS]
        result = compare_captures(self.capture, capture(*other))
        self.assertEqual(result["call_site_changes"], [])

    def test_tied_call_site_results_are_stable_across_arrival_order_and_process_ids(self):
        for distinct in (3, 12):
            with self.subTest(distinct=distinct):
                values = [f"variant-{index:02d}" for index in range(distinct)] + ["z-frequent"] * 2
                events = [dict(RECORDS[1], seq=index,
                               result={"type": "string", "value": value})
                          for index, value in enumerate(values, 1)]
                baseline = capture(RECORDS[0], *events)
                candidate = capture(dict(RECORDS[0], pid=999),
                                    *(dict(event, pid=999) for event in reversed(events)))
                result = compare_captures(baseline, candidate)
                before = result["baseline"]["call_sites"][0]
                after = result["candidate"]["call_sites"][0]
                expected = ["z-frequent"] + [f"variant-{index:02d}" for index in range(min(distinct, 9))]
                self.assertEqual([item["result"]["value"] for item in before["result_variants"]], expected)
                self.assertEqual(after["result_variants"], before["result_variants"])
                self.assertNotEqual(after["examples"], before["examples"])
                self.assertEqual(result["call_site_changes"], [])


if __name__ == "__main__":
    unittest.main()
