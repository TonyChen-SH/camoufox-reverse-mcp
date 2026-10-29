"""Bounded readers for protocol-1 records and explicitly enabled legacy input."""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable

MARKER = re.compile(r"(?:^|\s)CAMOUFOX_TRACE (?P<payload>.*)")
MAX_LINE_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_EVENTS = 100_000
MAX_RECORDS = 200_000
MAX_ISSUES = 50


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _summary(value: object) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        return False
    if "truncated" in value and type(value["truncated"]) is not bool:
        return False
    kind = value["type"]
    item = value.get("value")
    if kind in {"undefined", "null"}:
        return True
    if kind == "boolean":
        return type(item) is bool
    if kind == "number":
        return (type(item) is int and abs(item) <= sys.float_info.max) or (
            type(item) is float and math.isfinite(item)
        ) or (
            isinstance(item, str) and item in {"NaN", "Infinity", "-Infinity"}
        )
    if kind == "string":
        return isinstance(item, str)
    if kind == "object":
        return ("class" not in value or isinstance(value["class"], str)) and (
            "length" not in value or _integer(value["length"])
        )
    if kind == "unavailable":
        return isinstance(value.get("reason"), str)
    return False


def _native_error(record: dict) -> str | None:
    if not _integer(record.get("pid"), 1):
        return "pid must be a positive integer"
    event = record.get("event")
    if event == "meta":
        if not all(isinstance(record.get(key), str) and record[key] for key in (
            "transport", "coverage", "source_column"
        )) or not _integer(record.get("max_events")):
            return "metadata requires transport, coverage, source_column and max_events"
        return None
    if event == "limit":
        return None if _integer(record.get("emitted")) else "limit requires emitted"
    if event != "api":
        return "unknown protocol-1 event"
    required = {"seq", "mono_us", "api", "op", "source", "realm_class", "args",
                "result", "threw", "stack", "truncated"}
    if not required.issubset(record):
        return "API record is missing required fields"
    if not _integer(record["seq"], 1) or not _integer(record["mono_us"]):
        return "seq and mono_us must be nonnegative integers; seq starts at 1"
    if not all(isinstance(record[key], str) and record[key] for key in ("api", "op")):
        return "api and op must be nonempty strings"
    source = record["source"]
    if source is not None:
        if not isinstance(source, dict) or not {"url", "line", "column"}.issubset(source):
            return "source must contain url, line and column, or be null"
        if source["url"] is not None and not isinstance(source["url"], str):
            return "source.url must be a string or null"
        if any(source[key] is not None and not _integer(source[key]) for key in ("line", "column")):
            return "source line and column must be nonnegative integers or null"
    if record["realm_class"] is not None and not isinstance(record["realm_class"], str):
        return "realm_class must be a string or null"
    if not isinstance(record["args"], list) or not all(_summary(arg) for arg in record["args"]):
        return "args must contain value summaries"
    if not _summary(record["result"]):
        return "result must be a value summary"
    if type(record["threw"]) is not bool or type(record["truncated"]) is not bool:
        return "threw and truncated must be booleans"
    if record["stack"] is not None and not isinstance(record["stack"], str):
        return "stack must be a string or null"
    if "duration_us" in record and not _integer(record["duration_us"]):
        return "duration_us must be a nonnegative integer"
    return None


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode_object(payload: str) -> dict:
    def invalid_constant(value: str) -> None:
        raise ValueError("nonfinite JSON number")

    def integer(value: str) -> int | float:
        return -0.0 if value == "-0" else int(value)

    record = json.loads(payload, object_pairs_hook=_unique_object, parse_constant=invalid_constant,
                        parse_int=integer)
    if not isinstance(record, dict):
        raise ValueError("trace record must be a JSON object")
    return record


@dataclass
class Capture:
    events: list[dict] = field(default_factory=list)
    metadata: list[dict] = field(default_factory=list)
    limits: list[dict] = field(default_factory=list)
    collections: list[dict] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    issue_counts: Counter = field(default_factory=Counter)
    flags: set[str] = field(default_factory=set)
    lines: int = 0
    ignored_lines: int = 0
    records: int = 0

    def issue(self, line: int, status: str, reason: str) -> None:
        self.flags.add(status)
        self.issue_counts[status] += 1
        if len(self.issues) < MAX_ISSUES:
            self.issues.append({"line": line, "status": status, "reason": reason})


class Reader:
    def __init__(self, *, allow_legacy: bool = False, max_events: int = MAX_EVENTS,
                 max_records: int = MAX_RECORDS):
        if max_events < 1 or max_records < 1:
            raise ValueError("reader limits must be positive")
        self.capture = Capture()
        self.allow_legacy = allow_legacy
        self.max_events = max_events
        self.max_records = max_records
        self._sequences: dict[int, set[int]] = {}

    def add(self, line: str) -> bool:
        capture = self.capture
        capture.lines += 1
        line = line.rstrip("\r\n")
        marker = MARKER.search(line)
        if marker:
            payload = marker.group("payload")
        elif line.lstrip().startswith("{"):
            payload = line
        else:
            capture.ignored_lines += bool(line.strip())
            return True
        try:
            record = decode_object(payload)
        except (ValueError, RecursionError):
            capture.issue(capture.lines, "malformed_lines", "invalid JSON trace object")
            return True
        if not marker and not any(key in record for key in ("schema", "collector_schema", "o", "p")):
            capture.ignored_lines += 1
            return True
        capture.records += 1
        if capture.records > self.max_records:
            capture.flags.add("reader_record_cap")
            return False
        if "collector_schema" in record:
            self._collector(record)
            return True
        if "schema" not in record and self.allow_legacy and isinstance(record.get("o"), str) and isinstance(record.get("p"), str):
            if not {"v", "t", "k", "u", "w", "q", "s"}.issubset(record):
                capture.issue(capture.lines, "malformed_lines", "incomplete PropertyTracer record")
                return True
            self._event({"event": "legacy", "api": record["o"] + "." + record["p"],
                         "source": None, "legacy_record": record,
                         "js_provenance": "unavailable", "event_time_values": "unavailable"})
            capture.flags.update({"legacy_coverage", "missing_js_provenance", "event_time_values_unavailable"})
            return True
        schema = record.get("schema")
        if type(schema) is not int or schema != 1:
            status = "unsupported_schema" if "schema" in record else "malformed_lines"
            capture.issue(capture.lines, status, "expected native schema 1; legacy input requires --legacy")
            return True
        error = _native_error(record)
        if error:
            status = "unknown_events" if error == "unknown protocol-1 event" else "malformed_lines"
            capture.issue(capture.lines, status, error)
        elif record["event"] == "meta":
            capture.metadata.append(record)
        elif record["event"] == "limit":
            capture.limits.append(record)
            capture.flags.add("producer_event_cap")
        else:
            pid, seq = record["pid"], record["seq"]
            seen = self._sequences.setdefault(pid, set())
            if seq in seen:
                capture.issue(capture.lines, "sequence_discontinuity", "duplicate per-process sequence")
            seen.add(seq)
            self._event(record)
        return True

    def finish(self) -> Capture:
        # Native guards allocate sequence numbers on entry and write on exit.
        for pid, seen in self._sequences.items():
            if len(seen) != max(seen):
                self.capture.issue(self.capture.lines, "sequence_discontinuity",
                                   f"missing per-process sequences for pid {pid}")
        return self.capture

    def _event(self, record: dict) -> None:
        if len(self.capture.events) >= self.max_events:
            self.capture.flags.add("reader_event_cap")
        else:
            self.capture.events.append(record)

    def _collector(self, record: dict) -> None:
        capture = self.capture
        if type(record["collector_schema"]) is not int or record["collector_schema"] != 1:
            capture.issue(capture.lines, "unsupported_schema", "unsupported collector schema")
        elif record.get("event") == "invalid_trace":
            capture.issue(capture.lines, "malformed_lines", "collector encountered an invalid trace line")
        elif record.get("event") == "collection":
            terminations = {"normal_exit", "nonzero_exit", "signal_exit", "timeout", "interrupted", "spawn_failed"}
            if record.get("termination") not in terminations or (
                record.get("returncode") is not None and type(record["returncode"]) is not int
            ):
                capture.issue(capture.lines, "malformed_lines", "invalid collection outcome")
                return
            capture.collections.append(record)
            if record["termination"] != "normal_exit":
                capture.flags.add("child_" + record["termination"])
            if record.get("stderr_drain_incomplete"):
                capture.flags.add("stderr_drain_incomplete")
            if record.get("output_limited"):
                capture.flags.add("collector_output_cap")
        else:
            capture.issue(capture.lines, "unknown_events", "unknown collector record")


def parse_lines(lines: Iterable[str], *, allow_legacy: bool = False,
                max_events: int = MAX_EVENTS, max_records: int = MAX_RECORDS) -> Capture:
    reader = Reader(allow_legacy=allow_legacy, max_events=max_events, max_records=max_records)
    for line in lines:
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            reader.capture.lines += 1
            reader.capture.issue(reader.capture.lines, "malformed_lines", "trace line exceeds byte limit")
        elif not reader.add(line):
            break
    return reader.finish()


def read_stream(stream: BinaryIO, *, allow_legacy: bool = False, max_events: int = MAX_EVENTS,
                max_input_bytes: int = MAX_INPUT_BYTES) -> Capture:
    if max_input_bytes < 1:
        raise ValueError("max_input_bytes must be positive")
    reader = Reader(allow_legacy=allow_legacy, max_events=max_events)
    consumed = 0
    while True:
        chunk = stream.readline(min(MAX_LINE_BYTES + 1, max_input_bytes - consumed + 1))
        if not chunk:
            break
        consumed += len(chunk)
        if consumed > max_input_bytes:
            reader.capture.flags.add("reader_input_cap")
            break
        if len(chunk) > MAX_LINE_BYTES:
            reader.capture.lines += 1
            reader.capture.issue(reader.capture.lines, "malformed_lines", "trace line exceeds byte limit")
            while chunk and not chunk.endswith(b"\n"):
                chunk = stream.readline(min(MAX_LINE_BYTES + 1, max_input_bytes - consumed + 1))
                consumed += len(chunk)
                if consumed > max_input_bytes:
                    reader.capture.flags.add("reader_input_cap")
                    return reader.finish()
            continue
        try:
            line = chunk.decode("utf-8")
        except UnicodeDecodeError:
            reader.capture.lines += 1
            reader.capture.issue(reader.capture.lines, "malformed_lines", "invalid UTF-8 input line")
            continue
        if not reader.add(line):
            break
    return reader.finish()


def read_capture(path: str | Path, **kwargs) -> Capture:
    with Path(path).open("rb") as stream:
        return read_stream(stream, **kwargs)

