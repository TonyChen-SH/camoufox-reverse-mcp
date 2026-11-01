# Reader diagnostics and grouping

`integrity: no_known_loss` means no supported loss condition was observed. It
is not proof that the final producer records reached the collector. A clean
child exit alone cannot establish tail completeness without a producer end
contract. Source availability and transport integrity remain separate.

## Loss diagnostics

The historical `issues` field retains its first 50 entries. Reports additionally
provide:

- `issue_counts`: all occurrences of each diagnostic, including those omitted
  from previews.
- `issue_samples`: the first three issues of each status. Statuses come from the
  reader's finite set of diagnostics, not from arbitrary input strings.
- `issue_samples_limited`: statuses whose occurrences exceed their samples.
- `loss_statuses`: observed statuses that make integrity incomplete.
- `first_loss_issue`: the earliest sampled loss issue by input line, or null if
  none exists. Some conditions, such as a reader cap, only set a status; consult
  `loss_statuses` even when this field is null.

Repeated `provenance_unknown` entries cannot hide a later sequence gap from
these additional fields. A `vv8_record_gap` sample includes the PID, TID,
expected record counter, observed counter and missing-record count. One gap
can cause many subsequent `vv8_missing_context` occurrences. These occurrences
are diagnostic counts, **not dropped-record counts**. A record can produce
both a missing-isolate and a missing-active-script diagnostic.

After a gap the reader preserves raw records and clears the active isolate.
It does not guess an isolate from subsequent script or origin records. An
explicit isolate record is required to establish context again; missing source
provenance stays unknown in retained events.

## Reader budgets

```python
from camoufox_trace_mcp import read_capture, summarize

capture = read_capture("capture.jsonl", max_records=400_000, max_events=150_000)
report = summarize(capture)
print(report["reader_limits"], report["loss_statuses"])
```

`read_capture` and `read_stream` accept `max_records`, `max_events`,
`max_input_bytes`, and `max_line_bytes`. Defaults remain 200,000 records,
100,000 events, 64 MiB input, and 1 MiB per line. All limits must be positive
integers. `reader_limits` reports configured reader budgets separately from
producer metadata. `parse_lines` does not impose a total byte budget and
therefore does not report one. Raw segment reads report the original shared
input budget rather than the final segment's remaining allowance.

The record budget counts JSON envelopes/control records, or raw VV8 records
for raw input. It is distinct from the retained API event budget. A cap keeps
the report incomplete; increasing a budget cannot recover bytes already lost
by the producer or collector.

Trusted application code can configure the same limits when constructing
`TraceStore(root, max_records=400_000)`. File access remains restricted to
regular files beneath the configured root. MCP request schemas are unchanged.

## Call-site context

`summarize(capture, call_site_grouping="context")` includes observed PID, TID,
isolate, script ID, origin, security token and realm class in each call-site
key. This separates identical source locations seen in distinct observed
contexts. Missing context fields remain null; this option cannot infer frame
identity when the producer did not record it.

The default `call_site_grouping="source"` retains existing aggregation behavior
and comparisons across process IDs. `compare_captures` accepts the same option;
context grouping includes process-local IDs, so restarted processes may appear
as different sites even if they execute identical source. Neither grouping
establishes which observed activity caused a server decision.
