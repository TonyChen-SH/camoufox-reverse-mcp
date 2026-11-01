# Private stderr evidence

Collection normally retains only marked trace records. To diagnose transport
corruption, opt into an additional private byte file:

```sh
camoufox-trace collect --output capture.jsonl \
  --raw-stderr private.stderr --max-raw-stderr-bytes 67108864 \
  -- python fixtures/replay.py
```

The equivalent Python options are `raw_stderr_path` and
`max_raw_stderr_bytes` on `camoufox_trace_mcp.collector.collect`.
Both output files must be new and distinct. The raw file is created with mode
0600; its parent directory must already exist. The raw limit must be a positive
integer at most 64 MiB, which is also the default. It is independent of the
JSONL output cap.

The raw file contains the exact prefix read from the launched command's stderr,
before marker matching, line splitting, UTF-8 decoding or JSON validation. It
therefore retains unrelated diagnostics, CRLF, invalid UTF-8, rejected JSON and
unterminated lines. These bytes can contain credentials, URLs and page data;
keep this file private and encrypt it before uploading diagnostic artifacts.
It is not served through MCP. No raw data or raw file path is added to reports.

The final `collection` record contains `raw_stderr` metadata:

| Field | Meaning |
| --- | --- |
| `observed_bytes` | All stderr bytes read, including bytes beyond the raw cap |
| `captured_bytes` | Bytes successfully written to the raw file |
| `max_bytes` | Configured raw file cap |
| `sha256` | SHA-256 of the bytes successfully written, including a partial prefix |
| `status` | `complete`, `byte_limit`, `write_error`, `drain_incomplete`, or `spawn_failed` |
| `error_errno` | Numeric filesystem error, when a write, sync or close fails |

A raw cap or write failure does not stop ordinary trace decoding. It makes the
collection command return 65 even if the decoded capture is otherwise complete.
Timeout, interruption and spawn failure retain their existing exit codes.
`write_error` takes priority over `byte_limit`; other collection outcome fields
still report process termination and incomplete draining. `complete` means the
observed stderr pipe reached EOF without losing raw bytes. It does not mean the
browser finished its work, nor prove that an intermediary such as Playwright
forwarded every byte the native browser originally wrote. Compare a separate
capture at the native browser's stderr boundary to diagnose upstream loss.

Rejected marked lines remain `invalid_trace` records; collection never repairs
malformed JSON. Each rejection records zero-based `stderr_byte_offset` and
`payload_byte_offset` in the original stderr stream. `error_kind` distinguishes
invalid UTF-8, JSON syntax, invalid JSON values, recursion limits and oversized
lines. `error_byte_offset` is included only when a precise location is known;
JSON character positions are converted to UTF-8 byte positions. For an oversized
line it identifies the first byte beyond the line limit. No rejected payload or
exception text appears in these records.
