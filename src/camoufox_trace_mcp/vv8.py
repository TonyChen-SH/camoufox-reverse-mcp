"""VisibleV8 records and the bounded native stderr fragment transport."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import re
import time

ENVELOPE_BYTES = 4096
MAX_RECORD_BYTES = 64 * 1024 * 1024
DEFAULT_SEGMENT_BYTES = 1_000_000_000
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_NUMBER = re.compile(r"-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
_LOG_NAME = re.compile(r"vv8-[0-9]+-([0-9]+)-([0-9]+)-.+\.([0-9]+)\.log\Z")
_SEGMENT_NAME = re.compile(r"(vv8-.+)\.([0-9]+)\.log\Z")


def split_fields(text: str) -> list[str]:
    """Decode VV8 escapes, which do not follow JSON or CSV quoting rules."""
    fields, current = [], []
    index = 0
    while index < len(text):
        char = text[index]
        index += 1
        if char == ':':
            fields.append(''.join(current))
            current = []
        elif char != '\\':
            current.append(char)
        else:
            if index == len(text):
                raise ValueError('unfinished VV8 escape')
            escape = text[index]
            index += 1
            if escape in ':\\':
                current.append(escape)
            elif escape in 'xu':
                length = 2 if escape == 'x' else 4
                digits = text[index:index + length]
                if len(digits) != length or any(c not in '0123456789abcdefABCDEF' for c in digits):
                    raise ValueError('invalid VV8 hexadecimal escape')
                current.append(chr(int(digits, 16)))
                index += length
            else:
                raise ValueError('unknown VV8 escape')
    fields.append(''.join(current))
    return [value.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
            for value in fields]


def _quoted(value: str) -> bool:
    return len(value) >= 2 and value[0] == value[-1] == '"'


def value_summary(token: str) -> dict:
    """Best-effort value view; raw tokens remain authoritative and lossless."""
    if _quoted(token):
        return {'type': 'string', 'value': token[1:-1], 'raw': token}
    simple = {'#T': ('boolean', True), '#F': ('boolean', False),
              '#N': ('null', None), '#U': ('undefined', None)}
    if token in simple:
        kind, value = simple[token]
        result = {'type': kind, 'raw': token}
        if kind == 'boolean':
            result['value'] = value
        return result
    if _NUMBER.fullmatch(token) or token.lower() in {'nan', 'inf', '-inf', 'infinity', '-infinity'}:
        try:
            value = -0.0 if token == '-0' else int(token) if _INTEGER.fullmatch(token) else float(token)
            if isinstance(value, float) and not math.isfinite(value):
                value = 'NaN' if math.isnan(value) else '-Infinity' if value < 0 else 'Infinity'
            return {'type': 'number', 'value': value, 'raw': token}
        except ValueError:
            pass
    if token.startswith('{') and token.endswith('}'):
        body = token[1:-1]
        identity, comma, rest = body.partition(',')
        result = {'type': 'object', 'raw': token}
        if comma and identity.isascii() and identity.isdigit():
            result['identity_hash'] = identity
            body = rest
        if body and not any(char in body for char in ',:'):
            result['class'] = body
        return result
    return {'type': 'unavailable', 'reason': 'ambiguous_vv8_token', 'raw': token}


def _source_index(source: str) -> tuple[list[int], int]:
    starts, units, index = [0], 0, 0
    while index < len(source):
        char = source[index]
        index += 1
        units += 2 if ord(char) > 0xffff else 1
        if char == '\r' and index < len(source) and source[index] == '\n':
            index += 1
            units += 1
        if char in '\r\n\u2028\u2029':
            starts.append(units)
    return starts, units


def source_position(source: str, offset: int) -> tuple[int, int] | None:
    starts, length = _source_index(source)
    if type(offset) is not int or not 0 <= offset <= length:
        return None
    line = bisect_right(starts, offset) - 1
    return line + 1, offset - starts[line] + 1


@dataclass
class Stream:
    pid: int | None
    tid: int | None
    records: list[dict] = field(default_factory=list)
    last_record: int = 0
    pending_record: int | None = None
    parts: list[str] = field(default_factory=list)
    pending_bytes: int = 0
    isolate: str | None = None
    contexts: dict[str, dict] = field(default_factory=dict)
    identity_source: str = 'native'


class EngineTrace:
    def __init__(self):
        self.streams: dict[tuple[int | None, int | None], Stream] = {}
        self.scripts: list[dict] = []
        self._issue = None

    def _error(self, line: int, status: str, reason: str) -> None:
        if self._issue is not None:
            self._issue(line, status, reason)

    def stream(self, pid: int | None, tid: int | None) -> Stream:
        return self.streams.setdefault((pid, tid), Stream(pid, tid))

    def invalidate(self, pid, tid) -> None:
        if type(pid) is int and type(tid) is int:
            stream = self.streams.get((pid, tid))
            if stream is not None:
                stream.isolate = None
                stream.pending_record = None
                stream.parts.clear()
                stream.pending_bytes = 0

    def envelope(self, record: dict, line: int) -> dict | None:
        required = ('pid', 'tid', 'record', 'part')
        if any(type(record.get(key)) is not int or record[key] < (0 if key == 'part' else 1)
               for key in required) or type(record.get('final')) is not bool:
            raise ValueError('invalid VV8 envelope identifiers or final flag')
        data = record.get('data')
        if not isinstance(data, str) or not data.isascii() or any(ord(char) < 32 for char in data):
            raise ValueError('VV8 data must be printable ASCII without a terminal newline')
        if len(json.dumps(record, ensure_ascii=True, separators=(',', ':')).encode()) > ENVELOPE_BYTES:
            raise ValueError('VV8 envelope exceeds 4096 bytes')
        stream = self.stream(record['pid'], record['tid'])
        identity_source = record.get('identity_source', 'native')
        if identity_source not in ('native', 'filename', 'import_options'):
            raise ValueError('invalid VV8 identity source')
        if stream.records and stream.identity_source != identity_source:
            raise ValueError('VV8 identity source changed within one thread stream')
        stream.identity_source = identity_source
        number, part = record['record'], record['part']
        if part == 0:
            if stream.pending_record is not None:
                self._error(line, 'vv8_incomplete_record', 'a new record interrupted unfinished fragments')
                stream.parts.clear()
                stream.pending_bytes = 0
                stream.isolate = None
            if number <= stream.last_record:
                raise ValueError('duplicate or reversed VV8 record counter')
            if number != stream.last_record + 1:
                self._error(line, 'vv8_record_gap', 'nonconsecutive per-thread VV8 record counter')
                stream.isolate = None
            stream.pending_record = number
        if stream.pending_record != number or part != len(stream.parts):
            stream.parts.clear()
            stream.pending_record = None
            stream.pending_bytes = 0
            stream.isolate = None
            raise ValueError('missing, duplicate or out-of-order VV8 fragment')
        stream.parts.append(data)
        stream.pending_bytes += len(data)
        if stream.pending_bytes > MAX_RECORD_BYTES:
            stream.parts.clear()
            stream.pending_record = None
            stream.pending_bytes = 0
            raise ValueError('VV8 record exceeds the assembly byte limit')
        if not record['final']:
            return None
        raw = ''.join(stream.parts)
        stream.parts.clear()
        stream.pending_bytes = 0
        stream.pending_record = None
        stream.last_record = number
        return self.raw(raw, stream, number, line)

    def raw(self, raw: str, stream: Stream, number: int, line: int) -> dict | None:
        stream.records.append({'record': number, 'raw': raw})
        if not raw or not raw.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in raw):
            raise ValueError('VV8 records must contain printable ASCII on one line')
        kind, fields = raw[0], split_fields(raw[1:])
        if kind == '~':
            if len(fields) != 1 or not fields[0] or any(c.isspace() for c in fields[0]):
                raise ValueError('invalid isolate record')
            stream.isolate = fields[0]
            context = stream.contexts.setdefault(fields[0], {'scripts': {}, 'active': None,
                                                            'origin': None, 'security_token': None,
                                                            'explicit_unknown': False})
            context['active'] = None
            context['explicit_unknown'] = False
            return None
        if stream.isolate is None:
            self._error(line, 'vv8_missing_context', 'record has no established isolate')
            context = None
        else:
            context = stream.contexts[stream.isolate]
        if kind == '@':
            if len(fields) not in (1, 2) or not (_quoted(fields[0]) or fields == ['?']):
                raise ValueError('invalid origin record')
            if context is not None:
                context['origin'] = fields[0][1:-1] if _quoted(fields[0]) else None
                context['security_token'] = (
                    fields[1][1:-1] if _quoted(fields[1]) else fields[1]) if len(fields) == 2 else None
            return None
        if kind == '$':
            if len(fields) != 3 or not fields[0].isascii() or not fields[0].isdigit():
                raise ValueError('invalid script registration')
            if context is None:
                return None
            script_id = int(fields[0])
            if script_id in context['scripts']:
                raise ValueError('duplicate script ID in one isolate')
            parent = int(fields[1]) if fields[1].isascii() and fields[1].isdigit() else None
            if parent is not None and parent not in context['scripts']:
                self._error(line, 'vv8_unknown_parent', 'eval parent was not registered in this isolate')
            starts, length = _source_index(fields[2])
            script = {'index': len(self.scripts), 'pid': stream.pid, 'tid': stream.tid,
                      'identity_source': stream.identity_source,
                      'isolate': stream.isolate, 'script_id': script_id,
                      'url': fields[1][1:-1] if _quoted(fields[1]) else None,
                      'parent_id': parent, 'parent_unknown': fields[1] == '#?',
                      'source_name_token': fields[1], 'source': fields[2],
                      'source_sha256': hashlib.sha256(fields[2].encode('utf-8', 'surrogatepass')).hexdigest(),
                      'source_sha256_encoding': 'utf-8-surrogatepass',
                      'utf16_length': length, 'source_characters': len(fields[2]),
                      'origin': context['origin'], 'security_token': context['security_token'],
                      '_line_starts': starts}
            context['scripts'][script_id] = script
            self.scripts.append(script)
            return None
        if kind == '!':
            if len(fields) != 1 or (fields[0] != '?' and not (fields[0].isascii() and fields[0].isdigit())):
                raise ValueError('invalid active-script record')
            if context is not None:
                context['active'] = None
                context['explicit_unknown'] = fields[0] == '?'
                if fields[0] != '?':
                    script = context['scripts'].get(int(fields[0]))
                    if script is None:
                        self._error(line, 'vv8_missing_context', 'active script was not registered in this isolate')
                    context['active'] = script
            return None
        if kind not in 'gscnj' or not _INTEGER.fullmatch(fields[0]):
            raise ValueError('unknown VV8 kind or invalid source offset')
        if kind == 'j':
            if len(fields) < 3 or fields[1] not in 'gscn' or len(fields[1]) != 1:
                raise ValueError('invalid Java bridge record')
            if (fields[1] in 'gs' and len(fields) != 5) or (fields[1] == 'c' and len(fields) < 5):
                raise ValueError('invalid Java bridge fields')
            self._error(line, 'vv8_java_extension', 'Java records are retained raw; desktop API analysis excludes them')
            return None
        if (kind == 'g' and len(fields) != 3) or (kind == 's' and len(fields) != 4) or (
            kind == 'c' and len(fields) < 3) or (kind == 'n' and len(fields) < 2):
            raise ValueError('incorrect VV8 operation field count')
        script = context['active'] if context else None
        provenance_unknown = script is None and context is not None and context['explicit_unknown']
        if script is None:
            self._error(line, 'provenance_unknown' if provenance_unknown else 'vv8_missing_context',
                        'producer explicitly reported an unknown caller' if provenance_unknown
                        else 'API record has no registered active script')
        offset = int(fields[0])
        position = None
        if script is not None and 0 <= offset <= script['utf16_length']:
            index = bisect_right(script['_line_starts'], offset) - 1
            position = index + 1, offset - script['_line_starts'][index] + 1
        elif script is not None and offset >= 0:
            self._error(line, 'vv8_invalid_offset', 'API offset lies outside the registered source')
        receiver = value_summary(fields[1 if kind in 'gs' else 2]) if kind != 'n' else None
        if kind in 'gs':
            member = value_summary(fields[2])
            name = str(member.get('value', '<unknown>'))
            api = receiver.get('class', '<unknown>') + '.' + name
            args = [value_summary(fields[3])] if kind == 's' else []
        else:
            name = fields[1].removeprefix('%')
            api = name + '.constructor' if kind == 'n' else (
                receiver.get('class') + '.' + name if receiver.get('class') else name)
            args = [value_summary(token) for token in fields[2 if kind == 'n' else 3:]]
        event = {'schema': 1, 'event': 'api', 'channel': 'engine', 'pid': stream.pid, 'tid': stream.tid,
                 'identity_source': stream.identity_source,
                 'record': number, 'seq': None, 'mono_us': None, 'isolate': stream.isolate,
                 'script_id': script['script_id'] if script else None,
                 'source_sha256': script['source_sha256'] if script else None,
                 'provenance_unknown': provenance_unknown,
                 'source_offset': offset, 'source_offset_unit': 'utf16',
                 'source_column': 'one-origin-utf16', 'api': api,
                 'op': {'g': 'get', 's': 'set', 'c': 'call', 'n': 'construct'}[kind],
                 'source': {'url': script['url'], 'line': position[0] if position else None,
                            'column': position[1] if position else None} if script else None,
                 'realm_class': None, 'args': args,
                 'result': {'type': 'unavailable', 'reason': 'not_observed'}, 'threw': None,
                 'stack': None, 'truncated': False, 'receiver': receiver,
                 'origin': context['origin'] if context else None,
                 'security_token': context['security_token'] if context else None,
                 'vv8_kind': kind, 'vv8_fields': fields, 'vv8_raw': raw}
        if kind in 'gs':
            event['property'] = member
        return event

    def finish(self, line: int) -> None:
        for stream in self.streams.values():
            if stream.pending_record is not None:
                self._error(line, 'vv8_incomplete_record', 'capture ended before the final VV8 fragment')
                stream.parts.clear()
                stream.pending_record = None
                stream.pending_bytes = 0

    def summary(self) -> dict:
        return {'record_count': sum(len(stream.records) for stream in self.streams.values()),
                'script_count': len(self.scripts),
                'streams': [{'pid': stream.pid, 'tid': stream.tid, 'records': len(stream.records),
                             'identity_source': stream.identity_source}
                            for stream in self.streams.values()],
                'scripts': [script_metadata(script) for script in self.scripts[:100]],
                'scripts_limited': len(self.scripts) > 100}


def script_metadata(script: dict) -> dict:
    return {key: value for key, value in script.items() if key != 'source' and not key.startswith('_')}


def scripts_page(capture, *, offset: int = 0, limit: int = 100) -> dict:
    _page(offset, limit)
    scripts = capture.engine.scripts
    return {'scripts': [script_metadata(script) for script in scripts[offset:offset + limit]],
            'matched': len(scripts), 'offset': offset, 'limit': limit,
            'next_offset': offset + limit if offset + limit < len(scripts) else None,
            'statuses': sorted(capture.flags)}


def script_source(capture, index: int, *, offset: int = 0, limit: int = 4096) -> dict:
    _page(offset, limit, maximum=65536)
    if type(index) is not int or not 0 <= index < len(capture.engine.scripts):
        raise ValueError('script index is outside this capture')
    script = capture.engine.scripts[index]
    source = script['source']
    return dict(script_metadata(script), source=source[offset:offset + limit], offset=offset, limit=limit,
                source_page_unit='unicode_code_points',
                next_offset=offset + limit if offset + limit < len(source) else None,
                statuses=sorted(capture.flags))


def raw_records_page(capture, *, offset: int = 0, limit: int = 100,
                     pid: int | None = None, tid: int | None = None) -> dict:
    _page(offset, limit)
    for value in (pid, tid):
        if value is not None and (type(value) is not int or value < 1):
            raise ValueError('pid and tid must be positive integers')
    records = [dict(record, pid=stream.pid, tid=stream.tid)
               for stream in capture.engine.streams.values()
               if (pid is None or stream.pid == pid) and (tid is None or stream.tid == tid)
               for record in stream.records]
    return {'records': records[offset:offset + limit], 'matched': len(records),
            'offset': offset, 'limit': limit,
            'next_offset': offset + limit if offset + limit < len(records) else None,
            'statuses': sorted(capture.flags)}


def _page(offset: int, limit: int, maximum: int = 1000) -> None:
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= maximum:
        raise ValueError(f'offset must be nonnegative and limit between 1 and {maximum}')


def export_vv8(capture, destination: str | Path, *, segment_bytes: int = DEFAULT_SEGMENT_BYTES) -> dict:
    from .analysis import LOSS_FLAGS

    if capture.flags & LOSS_FLAGS:
        raise ValueError('cannot export a capture with known loss or invalid records')
    if type(segment_bytes) is not int or segment_bytes < 1:
        raise ValueError('segment_bytes must be a positive integer')
    streams = [stream for stream in capture.engine.streams.values() if stream.records]
    if not streams:
        raise ValueError('capture has no VV8 records to export')
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    files = []
    exported_at = time.time_ns() // 1_000_000
    for stream in streams:
        stem = f'vv8-{exported_at}-{stream.pid if stream.pid is not None else "unknown"}-{stream.tid if stream.tid is not None else "unknown"}-engine'
        output = None
        segment = 0
        try:
            for record in stream.records:
                if output is None or entry['bytes'] > segment_bytes:
                    if output is not None:
                        output.close()
                    name = f'{stem}.{segment}.log'
                    output = (destination / name).open('x', encoding='ascii', newline='\n')
                    entry = {'name': name, 'pid': stream.pid, 'tid': stream.tid,
                             'identity_source': stream.identity_source, 'segment': segment,
                             'records': 0, 'bytes': 0, 'first_record': record['record']}
                    files.append(entry)
                    segment += 1
                output.write(record['raw'] + '\n')
                entry['records'] += 1
                entry['bytes'] += len(record['raw']) + 1
                entry['last_record'] = record['record']
        finally:
            if output is not None:
                output.close()
    manifest = {'format': 'visiblev8', 'files': files,
                'segment_bytes': segment_bytes,
                'rollover': 'After the threshold is exceeded, start the next record in a new segment.',
                'filename_timestamp': 'export_creation_time_not_event_time',
                'identity': 'Native envelope IDs or IDs from the input filename; unknown remains unknown.',
                'statuses': sorted(capture.flags)}
    with (destination / 'manifest.json').open('x', encoding='utf-8') as output:
        json.dump(manifest, output, ensure_ascii=True, indent=2)
        output.write('\n')
    return manifest


def raw_identity(name: str | None) -> tuple[int | None, int | None]:
    match = _LOG_NAME.fullmatch(Path(name).name) if name else None
    return (int(match[1]), int(match[2])) if match else (None, None)


def _segment_clusters(paths: list[Path]) -> list[list[Path]]:
    if not paths:
        raise ValueError('import needs at least one input file')
    clusters: dict[str, dict[int, Path]] = {}
    for path in paths:
        match = _SEGMENT_NAME.fullmatch(path.name)
        if match is None:
            if len(paths) != 1:
                raise ValueError('multiple inputs require standard VV8 numeric segment filenames')
            return [[path]]
        stem, rank = match[1], int(match[2])
        ranks = clusters.setdefault(stem, {})
        if rank in ranks:
            raise ValueError(f'duplicate segment {rank} for {stem}')
        ranks[rank] = path
    result = []
    identities = set()
    for stem, ranks in sorted(clusters.items()):
        ordered = sorted(ranks)
        if ordered != list(range(len(ordered))):
            raise ValueError(f'missing segment for {stem}; segments must start at zero and be consecutive')
        identity = raw_identity(str(ranks[0]))
        if identity in identities:
            raise ValueError('distinct log clusters share a process/thread identity; import them separately')
        identities.add(identity)
        result.append([ranks[rank] for rank in ordered])
    return result


def read_vv8_segments(paths: list[str | Path]):
    """Read explicitly named raw segments with one bounded registry per producer thread."""
    from .analysis import LOSS_FLAGS
    from .reader import MAX_INPUT_BYTES, Reader, read_stream

    clusters = _segment_clusters([Path(path) for path in paths])
    reader = Reader(input_format='vv8')
    consumed = 0
    try:
        for cluster in clusters:
            for position, path in enumerate(cluster):
                reader.raw_name = str(path)
                with path.open('rb') as source:
                    if position < len(cluster) - 1:
                        source.seek(0, 2)
                        if source.tell():
                            source.seek(-1, 2)
                            if source.read(1) != b'\n':
                                raise ValueError('a nonfinal segment ends inside a raw record')
                        source.seek(0)
                    remaining = MAX_INPUT_BYTES - consumed
                    if remaining < 1:
                        if source.read(1):
                            reader.capture.flags.add('reader_input_cap')
                        break
                    read_stream(source, max_input_bytes=remaining, _reader=reader, _finalize=False)
                    consumed += source.tell()
                if reader.capture.flags & LOSS_FLAGS:
                    break
            if reader.capture.flags & LOSS_FLAGS:
                break
    finally:
        reader.finish()
    return reader.capture


def import_vv8(path: str | Path | list[str | Path], output: str | Path, *, pid: int | None = None,
               tid: int | None = None) -> dict:
    from .analysis import LOSS_FLAGS
    paths = [path] if isinstance(path, (str, Path)) else list(path)
    capture = read_vv8_segments(paths)
    if capture.flags & LOSS_FLAGS or not capture.engine.streams:
        raise ValueError('cannot import an invalid or empty VV8 stream')
    identity_source = 'filename' if pid is None and tid is None else 'import_options'
    if identity_source == 'import_options' and len(capture.engine.streams) != 1:
        raise ValueError('pid/tid overrides require one input thread cluster')
    streams = []
    for stream in capture.engine.streams.values():
        stream_pid = stream.pid if pid is None else pid
        stream_tid = stream.tid if tid is None else tid
        if any(type(value) is not int or value < 1 for value in (stream_pid, stream_tid)):
            raise ValueError('import needs positive pid/tid, from the filename or explicit options')
        streams.append((stream, stream_pid, stream_tid))
    output = Path(output)
    created = False
    try:
        with output.open('x', encoding='ascii', newline='\n') as destination:
            created = True
            for stream, stream_pid, stream_tid in streams:
                for item in stream.records:
                    raw = item['raw']
                    parts = [raw[index:index + 1024] for index in range(0, len(raw), 1024)]
                    for part, data in enumerate(parts):
                        envelope = {'schema': 1, 'event': 'vv8', 'pid': stream_pid, 'tid': stream_tid,
                                    'identity_source': identity_source,
                                    'record': item['record'], 'part': part,
                                    'final': part == len(parts) - 1, 'data': data}
                        encoded = json.dumps(envelope, ensure_ascii=True, separators=(',', ':'))
                        if len(encoded.encode('ascii')) > ENVELOPE_BYTES:
                            raise ValueError('import envelope exceeds 4096 bytes')
                        destination.write(encoded + '\n')
    except Exception:
        if created:
            output.unlink()
        raise
    summary = [{'pid': stream_pid, 'tid': stream_tid, 'records': len(stream.records)}
               for stream, stream_pid, stream_tid in streams]
    return {'output': str(output), 'pid': summary[0]['pid'] if len(summary) == 1 else None,
            'tid': summary[0]['tid'] if len(summary) == 1 else None, 'streams': summary,
            'records': sum(item['records'] for item in summary),
            'identity_source': identity_source, 'segments': len(paths)}
