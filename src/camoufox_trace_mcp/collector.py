"""Explicit local subprocess collection; never exposed as an MCP tool."""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path

from .reader import MAX_INPUT_BYTES, MAX_LINE_BYTES, decode_object

_MARKER = re.compile(rb"(?:^|\s)CAMOUFOX_TRACE (?P<payload>.*)")
DEFAULT_OUTPUT_BYTES = MAX_INPUT_BYTES - 65536


def collect(argv: list[str], output: str | Path, *, timeout: float = 60,
            max_output_bytes: int = DEFAULT_OUTPUT_BYTES, engine: bool = False, binding: bool = True) -> dict:
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
    outcome = {"collector_schema": 1, "event": "collection", "termination": "spawn_failed",
               "returncode": None, "stderr_lines": 0, "trace_lines": 0,
               "ignored_stderr_lines": 0, "stdout": "discarded",
               "output_limited": False, "stderr_drain_incomplete": False}
    with Path(output).open("x", encoding="utf-8") as destination:
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
            emit(outcome, final=True)
            return outcome
        assert process.stderr is not None
        os.set_blocking(process.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stderr, selectors.EVENT_READ)
        buffer = bytearray()
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
            except (ValueError, UnicodeDecodeError, RecursionError):
                record = {"collector_schema": 1, "event": "invalid_trace",
                          "stderr_line": outcome["stderr_lines"],
                          "reason": "line_too_long" if oversized else "invalid_json"}
            emit(record)

        def consume(data: bytes) -> None:
            nonlocal dropping
            buffer.extend(data)
            while buffer:
                newline = buffer.find(b"\n")
                if dropping:
                    if newline == -1:
                        buffer.clear()
                        return
                    del buffer[:newline + 1]
                    dropping = False
                elif newline != -1:
                    line_record(bytes(buffer[:newline]), oversized=newline > MAX_LINE_BYTES)
                    del buffer[:newline + 1]
                elif len(buffer) > MAX_LINE_BYTES:
                    line_record(bytes(buffer[:MAX_LINE_BYTES]), oversized=True)
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
    returncode = outcome["returncode"]
    if returncode < 0:
        return min(255, 128 - returncode)
    return min(255, returncode) if returncode else analysis_code

