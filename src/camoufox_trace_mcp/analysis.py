"""Descriptive observations, without detection or server-decision attribution."""

from __future__ import annotations

import json
from collections import Counter

from .reader import Capture, OPERATIONS, SCOPES

INTERPRETATION = (
    "Observed API activity only. Empty traces do not establish absence of detection. "
    "This capture cannot identify a server ban cause, recover missing call stacks or IDs, "
    "or reveal resolved promises and modified output-buffer contents."
)
LOSS_FLAGS = {"malformed_lines", "unsupported_schema", "unknown_events", "producer_event_cap",
              "reader_event_cap", "reader_record_cap", "reader_input_cap", "sequence_discontinuity",
              "child_timeout", "child_interrupted", "child_spawn_failed", "child_nonzero_exit",
              "child_signal_exit", "stderr_drain_incomplete", "collector_output_cap"}


def _truncated(value: object) -> bool:
    if isinstance(value, dict):
        return value.get("truncated") is True or any(_truncated(item) for item in value.values())
    return isinstance(value, list) and any(_truncated(item) for item in value)


def statuses(capture: Capture) -> list[str]:
    result = set(capture.flags)
    if not capture.events:
        result.add("no_events")
    producer_pids = {item["pid"] for item in capture.metadata}
    event_pids = {item["pid"] for item in capture.events if item["event"] == "api"}
    if not producer_pids or event_pids - producer_pids:
        result.add("no_producer_metadata")
    if any(_truncated(item) for item in capture.events if item["event"] == "api"):
        result.add("value_truncation")
    return sorted(result)


def _sources(capture: Capture) -> list[dict]:
    conventions: dict[int, set[str]] = {}
    for item in capture.metadata:
        conventions.setdefault(item["pid"], set()).add(item["source_column"])
    groups: Counter = Counter()
    for event in capture.events:
        units = sorted(conventions.get(event.get("pid"), {"undeclared"}))
        key = json.dumps({"source": event["source"], "column_conventions": units}, sort_keys=True)
        groups[key] += 1
    return [dict(json.loads(key), count=count) for key, count in sorted(groups.items())]


def _call_sites(capture: Capture) -> list[dict]:
    conventions = {item["pid"]: item["source_column"] for item in capture.metadata}
    groups = {}
    for event in capture.events:
        key = json.dumps({"api": event["api"], "op": event.get("op"),
                          "scope": event.get("scope"),
                          "source": event["source"],
                          "source_column": conventions.get(event.get("pid"), "undeclared")}, sort_keys=True)
        group = groups.setdefault(key, {"count": 0, "results": Counter(), "examples": []})
        group["count"] += 1
        result = {"result": event.get("result", {"type": "unavailable", "reason": "legacy"}),
                  "threw": event.get("threw"), "truncated": _truncated(event)}
        group["results"][json.dumps(result, sort_keys=True)] += 1
        if len(group["examples"]) < 3:
            group["examples"].append({"pid": event.get("pid"), "seq": event.get("seq")})
    return [dict(json.loads(key), count=group["count"], examples=group["examples"],
                 result_variants=[dict(json.loads(result), count=count)
                                  for result, count in sorted(group["results"].items(),
                                                              key=lambda item: (-item[1], item[0]))[:10]],
                 distinct_result_summaries=len(group["results"]),
                 result_variants_limited=len(group["results"]) > 10)
            for key, group in sorted(groups.items())]


def summarize(capture: Capture) -> dict:
    flags = statuses(capture)
    apis: dict[str, dict] = {}
    for event in capture.events:
        group = apis.setdefault(event["api"], {"api": event["api"], "count": 0,
                                             "threw": 0, "truncated": 0})
        group["count"] += 1
        group["threw"] += event.get("threw") is True
        group["truncated"] += event["event"] == "api" and _truncated(event)
    producer_pids = {item["pid"] for item in capture.metadata}
    event_pids = {item["pid"] for item in capture.events if item["event"] == "api"}
    return {
        "state": "observed" if capture.events else "no_events",
        "integrity": "incomplete" if set(flags) & LOSS_FLAGS else "no_known_loss",
        "statuses": flags,
        "event_count": len(capture.events),
        "native_event_count": sum(item["event"] == "api" for item in capture.events),
        "legacy_event_count": sum(item["event"] == "legacy" for item in capture.events),
        "missing_metadata_pids": sorted(event_pids - producer_pids),
        "metadata": capture.metadata,
        "limits": capture.limits,
        "collections": capture.collections,
        "input": {"lines": capture.lines, "ignored_lines": capture.ignored_lines,
                  "records": capture.records},
        "issue_counts": dict(sorted(capture.issue_counts.items())),
        "issues": capture.issues,
        "apis": [apis[key] for key in sorted(apis)],
        "sources": _sources(capture),
        "call_sites": _call_sites(capture),
        "interpretation": INTERPRETATION,
    }


def filter_events(capture: Capture, *, api: str | None = None, source_url: str | None = None,
                  pid: int | None = None, threw: bool | None = None, offset: int = 0,
                  limit: int = 100, op: str | None = None, scope: str | None = None) -> dict:
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("offset must be nonnegative and limit must be between 1 and 1000")
    if pid is not None and (type(pid) is not int or pid < 1):
        raise ValueError("pid must be a positive integer")
    if threw is not None and type(threw) is not bool:
        raise ValueError("threw must be a boolean")
    if op is not None and op not in OPERATIONS:
        raise ValueError("op must be get, set, call or construct")
    if scope is not None and scope not in (*SCOPES, "unknown"):
        raise ValueError("scope must be instance, static, constructor or unknown")
    matched = [event for event in capture.events
               if (api is None or event["api"] == api)
               and (op is None or event.get("op") == op)
               and (scope is None or event.get("scope", "unknown") == scope)
               and (source_url is None or (event["source"] or {}).get("url") == source_url)
               and (pid is None or event.get("pid") == pid)
               and (threw is None or event.get("threw") is threw)]
    end = offset + limit
    return {"statuses": statuses(capture), "matched": len(matched), "offset": offset,
            "limit": limit, "next_offset": end if end < len(matched) else None,
            "events": matched[offset:end], "interpretation": INTERPRETATION}


def compare_captures(baseline: Capture, candidate: Capture) -> dict:
    left, right = summarize(baseline), summarize(candidate)
    left_apis = {item["api"]: item["count"] for item in left["apis"]}
    right_apis = {item["api"]: item["count"] for item in right["apis"]}
    deltas = [{"api": api, "baseline": left_apis.get(api, 0), "candidate": right_apis.get(api, 0),
               "delta": right_apis.get(api, 0) - left_apis.get(api, 0)}
              for api in sorted(left_apis.keys() | right_apis.keys())]
    source_counts = []
    for report in (left, right):
        source_counts.append({json.dumps({key: value for key, value in item.items() if key != "count"},
                                        sort_keys=True): item["count"] for item in report["sources"]})
    source_deltas = [dict(json.loads(key), baseline=source_counts[0].get(key, 0),
                          candidate=source_counts[1].get(key, 0),
                          delta=source_counts[1].get(key, 0) - source_counts[0].get(key, 0))
                     for key in sorted(source_counts[0].keys() | source_counts[1].keys())]
    site_counts = []
    for report in (left, right):
        site_counts.append({json.dumps({key: item[key] for key in (
            "api", "op", "scope", "source", "source_column")}, sort_keys=True): item
            for item in report["call_sites"]})
    changes = []
    for key in sorted(site_counts[0].keys() | site_counts[1].keys()):
        before, after = site_counts[0].get(key), site_counts[1].get(key)
        comparable = lambda item: {name: value for name, value in item.items()
                                   if name != "examples"} if item else None
        if comparable(before) != comparable(after):
            changes.append(dict(json.loads(key), baseline=before, candidate=after))
    return {"baseline": left, "candidate": right, "api_count_deltas": deltas,
            "source_count_deltas": source_deltas,
            "call_site_changes": changes,
            "comparison": "Differences in observed counts and result summaries; not matched calls or evidence of detection. Identical object/string summaries do not prove equal full values.",
            "interpretation": INTERPRETATION}


def analysis_exit_code(capture: Capture) -> int:
    flags = set(statuses(capture))
    if flags & LOSS_FLAGS:
        return 65
    if "no_events" in flags:
        return 3
    return 0
