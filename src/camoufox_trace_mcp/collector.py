"""Explicit local subprocess collection; never exposed as an MCP tool."""

from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import selectors
import signal
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path

from .reader import MAX_INPUT_BYTES, MAX_LINE_BYTES, decode_object

_MARKER = re.compile(rb"(?:^|\s)CAMOUFOX_TRACE (?P<payload>.*)")
DEFAULT_OUTPUT_BYTES = MAX_INPUT_BYTES - 65536
DEFAULT_RAW_STDERR_BYTES = MAX_INPUT_BYTES


class _RawStderr:
    def __init__(self, path: str | Path, max_bytes: int):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.digest = hashlib.sha256()
        self.metadata = {"status": "complete", "observed_bytes": 0,
                         "captured_bytes": 0, "max_bytes": max_bytes,
                         "sha256": self.digest.hexdigest()}

    def write(self, data: bytes) -> None:
        state = self.metadata
        state["observed_bytes"] += len(data)
        if state["status"] == "write_error":
            return
        remaining = state["max_bytes"] - state["captured_bytes"]
        if len(data) > remaining:
            state["status"] = "byte_limit"
        pending = memoryview(data)[:remaining]
        try:
            while pending:
                count = os.write(self.fd, pending)
                if count == 0:
                    raise OSError(errno.EIO, "raw stderr write made no progress")
                self.digest.update(pending[:count])
                state["captured_bytes"] += count
                pending = pending[count:]
        except OSError as error:
            state.update(status="write_error", error_errno=error.errno)

    def finish(self, outcome: dict) -> None:
        state = self.metadata
        try:
            os.fsync(self.fd)
        except OSError as error:
            state.update(status="write_error", error_errno=error.errno)
        try:
            self.close()
        except OSError as error:
            state.update(status="write_error", error_errno=error.errno)
        if state["status"] == "complete":
            if outcome["termination"] == "spawn_failed":
                state["status"] = "spawn_failed"
            elif outcome["stderr_drain_incomplete"]:
                state["status"] = "drain_incomplete"
        state["sha256"] = self.digest.hexdigest()

    def close(self) -> None:
        if self.fd is not None:
            descriptor, self.fd = self.fd, None
            os.close(descriptor)


def collect(argv: list[str], output: str | Path, *, timeout: float = 60,
            max_output_bytes: int = DEFAULT_OUTPUT_BYTES, engine: bool = False, binding: bool = True,
            raw_stderr_path: str | Path | None = None,
            max_raw_stderr_bytes: int = DEFAULT_RAW_STDERR_BYTES) -> dict:
    """Run argv without a shell and save marked stderr plus a collection outcome.

    POSIX process groups let timeouts and interrupts clean up descendants that
    remain in the launched process group. Child stdout is deliberately discarded.
    """
    if os.name != "posix":
        raise ValueError("collect requires POSIX process-group support")
    if not argv or not all(isinstance(arg, str) and "\0" not in arg for arg in argv):
        raise ValueError("collect requires an explicit nonempty argv")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and positive")
    if type(max_output_bytes) is not int or not 1024 <= max_output_bytes <= DEFAULT_OUTPUT_BYTES:
        raise ValueError(f"max_output_bytes must be between 1024 and {DEFAULT_OUTPUT_BYTES}")
    if type(max_raw_stderr_bytes) is not int or not 1 <= max_raw_stderr_bytes <= DEFAULT_RAW_STDERR_BYTES:
        raise ValueError(f"max_raw_stderr_bytes must be between 1 and {DEFAULT_RAW_STDERR_BYTES}")
    if raw_stderr_path is not None and Path(raw_stderr_path).resolve() == Path(output).resolve():
        raise ValueError("raw stderr and JSONL output must be different files")
    outcome = {"collector_schema": 1, "event": "collection", "termination": "spawn_failed",
               "returncode": None, "stderr_lines": 0, "trace_lines": 0,
               "ignored_stderr_lines": 0, "stdout": "discarded",
               "output_limited": False, "stderr_drain_incomplete": False}
    with ExitStack() as resources:
        destination = resources.enter_context(Path(output).open("x", encoding="utf-8"))
        raw = None
        if raw_stderr_path is not None:
            raw = _RawStderr(raw_stderr_path, max_raw_stderr_bytes)
            resources.callback(raw.close)
            outcome["raw_stderr"] = raw.metadata
        written = 0

        def emit(record: dict, *, final: bool = False) -> None:
            nonlocal written
            encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
            if not final and written + len(encoded) > max_output_bytes:
                outcome["output_limited"] = True
                return
            destination.write(encoded)
            written += len(encoded)

        environment = os.environ.copy()
        environment["CAMOUFOX_TRACE"] = '1' if binding else '0'
        if engine:
            environment['CAMOUFOX_ENGINE_TRACE'] = '1'
        try:
            process = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                       env=environment, start_new_session=True)
        except OSError as error:
            outcome["spawn_errno"] = error.errno
            if raw is not None:
                raw.finish(outcome)
            emit(outcome, final=True)
            return outcome
        assert process.stderr is not None
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stderr, selectors.EVENT_READ)
        buffer = bytearray()
        buffer_offset = 0
        dropping = False
        pipe_eof = False
        timed_out = False
        interrupted = False
        deadline = time.monotonic() + timeout
        stop_started: float | None = None
        killed = False

        def signal_group(number: int) -> None:
            try:
                os.killpg(process.pid, number)
            except ProcessLookupError:
                pass

        def line_record(line: bytes, *, oversized: bool = False) -> None:
            outcome["stderr_lines"] += 1
            marker = _MARKER.search(line.rstrip(b"\r"))
            if marker is None:
                outcome["ignored_stderr_lines"] += 1
                return
            outcome["trace_lines"] += 1
            try:
                if oversized:
                    raise ValueError("oversized line")
                record = decode_object(marker.group("payload").decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError) as error:
                payload_offset = buffer_offset + marker.start("payload")
                record = {"collector_schema": 1, "event": "invalid_trace",
                          "stderr_line": outcome["stderr_lines"],
                          "stderr_byte_offset": buffer_offset,
                          "payload_byte_offset": payload_offset,
                          "reason": "line_too_long" if oversized else "invalid_json"}
                if oversized:
                    record.update(error_kind="line_too_long",
                                  error_byte_offset=buffer_offset + MAX_LINE_BYTES)
                elif isinstance(error, UnicodeDecodeError):
                    record.update(error_kind="invalid_utf8", error_byte_offset=payload_offset + error.start)
                elif isinstance(error, json.JSONDecodeError):
                    record.update(error_kind="json_syntax",
                                  error_byte_offset=payload_offset + len(error.doc[:error.pos].encode("utf-8")))
                else:
                    record["error_kind"] = "recursion_limit" if isinstance(error, RecursionError) else "invalid_json_value"
            emit(record)

        def consume(data: bytes) -> None:
            nonlocal dropping, buffer_offset
            if raw is not None:
                raw.write(data)
            buffer.extend(data)
            while buffer:
                newline = buffer.find(b"\n")
                if dropping:
                    if newline == -1:
                        buffer_offset += len(buffer)
                        buffer.clear()
                        return
                    del buffer[:newline + 1]
                    buffer_offset += newline + 1
                    dropping = False
                elif newline != -1:
                    line_record(bytes(buffer[:newline]), oversized=newline > MAX_LINE_BYTES)
                    del buffer[:newline + 1]
                    buffer_offset += newline + 1
                elif len(buffer) > MAX_LINE_BYTES:
                    line_record(bytes(buffer[:MAX_LINE_BYTES]), oversized=True)
                    buffer_offset += len(buffer)
                    buffer.clear()
                    dropping = True
                else:
                    return

        try:
            while True:
                try:
                    now = time.monotonic()
                    returncode = process.poll()
                    if returncode is None and now >= deadline:
                        timed_out = True
                    if stop_started is None and (returncode is not None or timed_out or interrupted
                                                 or outcome["output_limited"]):
                        stop_started = now
                        signal_group(signal.SIGTERM)
                    if stop_started is not None and now - stop_started >= 0.3 and not killed:
                        signal_group(signal.SIGKILL)
                        killed = True
                    if pipe_eof and process.poll() is not None:
                        break
                    if stop_started is not None and now - stop_started >= 2:
                        outcome["stderr_drain_incomplete"] = not pipe_eof
                        break
                    for key, _ in selector.select(0.05):
                        try:
                            data = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(process.stderr)
                            pipe_eof = True
                        else:
                            consume(data)
                except KeyboardInterrupt:
                    interrupted = True
        finally:
            signal_group(signal.SIGKILL)
            process.wait(timeout=2)
            selector.close()
            process.stderr.close()
        if buffer and not dropping:
            line_record(bytes(buffer))
        outcome["returncode"] = process.returncode
        if interrupted:
            outcome["termination"] = "interrupted"
        elif timed_out:
            outcome["termination"] = "timeout"
        elif process.returncode < 0:
            outcome["termination"] = "signal_exit"
        elif process.returncode:
            outcome["termination"] = "nonzero_exit"
        else:
            outcome["termination"] = "normal_exit"
        if raw is not None:
            raw.finish(outcome)
        emit(outcome, final=True)
    return outcome


def collection_exit_code(outcome: dict, analysis_code: int) -> int:
    termination = outcome["termination"]
    if termination == "timeout":
        return 124
    if termination == "interrupted":
        return 130
    if termination == "spawn_failed":
        return 127
    if outcome["output_limited"]:
        return 65
    if outcome.get("raw_stderr", {}).get("status", "complete") != "complete":
        return 65
    returncode = outcome["returncode"]
    if returncode < 0:
        return min(255, 128 - returncode)
    return min(255, returncode) if returncode else analysis_code

