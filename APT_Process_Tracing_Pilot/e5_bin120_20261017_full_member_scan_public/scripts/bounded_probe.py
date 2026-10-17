"""Budgeted entry for the existing stdlib CDM reader. Input is always data."""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import tempfile
import time

import stream_cdm20 as reader

PARSER_SHA = '594932329230a43e9cf0fa78bbb6b72a046984b06add12cdf3ee3735351ad463'
LIMITS = {'records': 250000, 'expanded_bytes': 1073741824, 'seconds': 600, 'memory_bytes': 4294967296}


class BudgetStop(Exception):
    pass


class ReaderIncompatible(Exception):
    pass


def identity(s) -> dict:
    return {'dev': s.st_dev, 'inode': s.st_ino, 'size': s.st_size, 'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns, 'mode': oct(stat.S_IMODE(s.st_mode))}


def safe_path(path: Path) -> None:
    for p in [path, *path.parents]:
        if p.is_symlink():
            raise ValueError('Symlink component forbidden')


def save(path: Path, value) -> None:
    safe_path(path)
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write(chr(10))
    path.chmod(0o600)


def utc(ns: int | None) -> str | None:
    if not isinstance(ns, int) or isinstance(ns, bool):
        return None
    try:
        seconds, nanos = divmod(ns, 1000000000)
        return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + f'.{nanos:09d}Z'
    except (OverflowError, OSError, ValueError):
        return None


def hash_file(path: Path, expected_size: int, expected_md5: str) -> dict:
    safe_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('Not a regular file')
    start = time.monotonic()
    md5, sha, count = hashlib.md5(), hashlib.sha256(), 0
    with path.open('rb') as source:
        fd0 = identity(os.fstat(source.fileno()))
        for chunk in iter(lambda: source.read(1048576), b''):
            count += len(chunk)
            md5.update(chunk)
            sha.update(chunk)
        fd1 = identity(os.fstat(source.fileno()))
    after = path.stat()
    stable = identity(before) == identity(after) == fd0 == fd1
    status = 'FILE_VERIFIED' if stable and count == expected_size and md5.hexdigest() == expected_md5 else 'INPUT_INTEGRITY_MISMATCH' if stable else 'INPUT_INCOMPLETE_OR_CHANGING'
    return {'path': str(path), 'before': identity(before), 'after': identity(after), 'stable_during_hash': stable, 'actual_size': count, 'actual_md5': md5.hexdigest(), 'actual_sha256': sha.hexdigest(), 'expected_size': expected_size, 'expected_md5': expected_md5, 'hash_seconds': time.monotonic() - start, 'status': status}


class DeliveredGzip:
    def __init__(self, source, limit: int, check) -> None:
        self.source, self.limit, self.check = source, limit, check
        self.delivered = 0

    def read(self, n: int) -> bytes:
        self.check()
        if n < 0:
            raise ValueError('Unbounded read forbidden')
        if n > self.limit - self.delivered:
            raise BudgetStop('EXPANDED_BYTE_LIMIT_WOULD_BE_EXCEEDED')
        data = self.source.read(n)
        self.delivered += len(data)
        self.check()
        return data


class BlockStream:
    """Read a null-codec block directly, without allocating its declared size."""
    def __init__(self, source: DeliveredGzip, size: int) -> None:
        self.source, self.size, self.consumed = source, size, 0

    def read(self, n: int) -> bytes:
        if n < 0 or n > self.size - self.consumed:
            raise EOFError('Datum exceeds declared block boundary')
        data = self.source.read(n)
        self.consumed += len(data)
        return data


def probe(path: Path, limits: dict, target_path: str | None = None, object_seed_ids=(), subject_seed_ids=()) -> tuple[dict, list]:
    start, deadline = time.monotonic(), time.monotonic() + limits['seconds']
    stats = {'record_count': 0, 'record_decode_attempts': 0, 'block_count_started': 0, 'block_count_fully_validated': 0, 'record_types': collections.Counter(), 'top_level_types': collections.Counter(), 'event_types': collections.Counter(), 'subject_types': collections.Counter(), 'cdm_versions': collections.Counter(), 'host_ids_all_records': collections.Counter(), 'timestamp_counts': collections.Counter(), 'host_event_ranges': {}, 'host_definition_map': {}, 'references': {}, 'parse_anomalies': [], 'file_eof_reached': False, 'gzip_crc_status': 'NOT_VERIFIED_TO_EOF', 'last_complete_record': None, 'partial_record_start': None, 'candidate_records_matched': 0, 'candidate_records_retained': 0, 'candidate_retention_limit': 512, 'B': 'B_UNRESOLVED', 'coverage_scope': 'READ_PREFIX_ONLY_UNTIL_VERIFIED_EOF', 'source_fields_used': ['type', 'CDMVersion', 'hostId', 'datum._record_type', 'datum.uuid', 'datum.type', 'datum.timestampNanos', 'datum.subject', 'datum.predicateObject', 'datum.predicateObjectPath', 'datum.predicateObject2', 'datum.predicateObject2Path', 'datum.parentSubject', 'datum.localPrincipal', 'datum.startTimestampNanos', 'datum.hostName', 'datum.baseObject.properties']}
    defined, refs, null_refs, subjects, event_ids = {}, collections.defaultdict(set), collections.Counter(), {}, {}
    object_seeds, subject_seeds = set(object_seed_ids), set(subject_seed_ids)
    candidates, target_objects = [], set(object_seeds)
    stats['path_field_availability'] = {k: dict(missing=0, null=0, empty_string=0, nonempty_string=0, other_type=0) for k in ('predicateObjectPath', 'predicateObject2Path')}
    stats['uuid_match_counts'] = dict(object_seed_events=0, subject_seed_events=0, both_seed_events=0, both_seed_read_events=0)
    stats['seed_definitions_in_read_scope'] = {}
    stats['lookup_evidence_tier'] = 'SECONDARY_NODE_LABEL_GUIDED_EXPLORATORY_NOT_PUBLISHER_EVENT_TRUTH' 
    stream, raw, current_record = None, None, None
    stopping = False
    before = identity(path.stat())

    def stop(reason: str) -> None:
        nonlocal stopping
        stopping = True
        raise BudgetStop(reason)

    def check() -> None:
        if time.monotonic() >= deadline:
            stop('WALL_CLOCK_LIMIT')
        if rss_bytes() > limits['memory_bytes']:
            stop('MEMORY_SUPERVISION_THRESHOLD')

    def alarm(_signum, _frame) -> None:
        if not stopping:
            stop('WALL_CLOCK_LIMIT')

    old_handler = signal.signal(signal.SIGALRM, alarm)
    try:
        signal.setitimer(signal.ITIMER_REAL, limits['seconds'] if limits['seconds'] > 0 else 0)
        check()
        with path.open('rb') as raw:
            stats['gzip_magic_hex'] = raw.read(2).hex()
            if stats['gzip_magic_hex'] != '1f8b':
                raise ReaderIncompatible('INPUT_NOT_ORIGINAL_GZIP')
            raw.seek(0)
            with gzip.GzipFile(fileobj=raw, mode='rb') as zipped:
                stream = DeliveredGzip(zipped, limits['expanded_bytes'], check)
                if reader.read_exact(stream, 4) != b'Obj\x01':
                    raise ReaderIncompatible('Not an Avro OCF')
                metadata = reader.read_map_bytes(stream)
                sync = reader.read_exact(stream, 16)
                schema = json.loads(metadata['avro.schema'])
                codec = metadata.get('avro.codec', b'null').decode('utf-8')
                stats.update({'ocf_magic_hex': '4f626a01', 'ocf_codec': codec, 'embedded_schema_sha256': hashlib.sha256(metadata['avro.schema']).hexdigest(), 'embedded_schema_namespace': schema.get('namespace'), 'embedded_schema_name': schema.get('name'), 'top_level_schema_fields': [f['name'] for f in schema.get('fields', [])]})
                if codec != 'null':
                    raise ReaderIncompatible('Unsupported codec; no unmetered inner decompression')
                names = {}
                reader.collect_names(schema, names)
                event_schema = names.get('Event', {})
                ts_doc = next((f.get('doc', '') for f in event_schema.get('fields', []) if f['name'] == 'timestampNanos'), '')
                stats['event_timestamp_schema_doc'] = ts_doc
                stats['timestamp_interpretation'] = 'UNIX_EPOCH_NANOSECONDS_UTC_PER_EMBEDDED_SCHEMA' if 'unix epoch' in ts_doc.lower() and 'nanosecond' in ts_doc.lower() else 'UNVERIFIED_TIMESTAMP_EPOCH_UNITS'
                while True:
                    check()
                    if stats['record_decode_attempts'] >= limits['records']:
                        raise BudgetStop('TOP_LEVEL_RECORD_LIMIT')
                    header_offset = stream.delivered
                    count = reader.maybe_long(stream)
                    if count is None:
                        stats['file_eof_reached'] = True
                        stats['gzip_crc_status'] = 'VERIFIED_TO_EOF'
                        stats['termination_reason'] = 'MEMBER_EOF'
                        break
                    size = reader.long(stream)
                    if count < 0 or size < 0 or size > 134217728:
                        raise ReaderIncompatible('Invalid or unsupported OCF block count/size')
                    stats['block_count_started'] += 1
                    block = BlockStream(stream, size)
                    for index in range(count):
                        check()
                        if stats['record_decode_attempts'] >= limits['records']:
                            raise BudgetStop('TOP_LEVEL_RECORD_LIMIT')
                        current_record = {'top_level_record_ordinal_1based': stats['record_count'] + 1, 'block_ordinal_1based': stats['block_count_started'], 'record_index_in_block_0based': index, 'ocf_uncompressed_block_header_offset': header_offset, 'uncompressed_offset_in_block': block.consumed, 'locator_note': 'Sequential OCF locator; not a random-access compressed-file offset'}
                        stats['record_decode_attempts'] += 1
                        row = reader.decode(block, schema, names)
                        stats['record_count'] += 1
                        datum = row.get('datum') or {}
                        kind = str(datum.get('_record_type', 'UNKNOWN'))
                        stats['record_types'][kind] += 1
                        stats['top_level_types'][str(row.get('type'))] += 1
                        stats['cdm_versions'][str(row.get('CDMVersion'))] += 1
                        host = row.get('hostId')
                        host = str(host) if host is not None else '__MISSING_HOST_ID__'
                        stats['host_ids_all_records'][host] += 1
                        if row.get('hostId') is not None:
                            refs['hostId'].add(host)
                        else:
                            null_refs['hostId'] += 1
                        uuid = datum.get('uuid')
                        if uuid is not None:
                            defined[str(uuid)] = kind
                        for field in ('subject', 'predicateObject', 'predicateObject2', 'parentSubject', 'localPrincipal'):
                            if field in datum:
                                value = datum[field]
                                if value is None:
                                    null_refs['datum.' + field] += 1
                                else:
                                    refs['datum.' + field].add(str(value))
                        if kind != 'Event' and str(uuid) in object_seeds | subject_seeds:
                            stats['seed_definitions_in_read_scope'][str(uuid)] = {'hostId': host, 'kind': kind, 'locator': dict(current_record), 'fields': {k: datum.get(k) for k in ('uuid', 'type', 'cid', 'parentSubject', 'startTimestampNanos', 'cmdLine', 'baseObject')}}
                        if kind == 'Host' and uuid is not None:
                            stats['host_definition_map'][str(uuid)] = {'hostName': datum.get('hostName'), 'record_locator': dict(current_record)}
                        if kind == 'Subject':
                            stats['subject_types'][str(datum.get('type'))] += 1
                            subjects[str(uuid)] = {k: datum.get(k) for k in ('uuid', 'cid', 'parentSubject', 'startTimestampNanos', 'cmdLine')}
                            subjects[str(uuid)]['record_locator'] = dict(current_record)
                        if kind == 'FileObject':
                            properties = (datum.get('baseObject') or {}).get('properties') or {}
                            if target_path is not None and isinstance(properties, dict) and target_path in properties.values():
                                target_objects.add(str(uuid))
                        if kind == 'Event':
                            for field, counts in stats['path_field_availability'].items():
                                value = datum.get(field)
                                category = 'missing' if field not in datum else 'null' if value is None else 'empty_string' if value == '' else 'nonempty_string' if isinstance(value, str) else 'other_type'
                                counts[category] += 1
                            object_match = any(str(datum.get(k)) in object_seeds for k in ('predicateObject', 'predicateObject2'))
                            subject_match = str(datum.get('subject')) in subject_seeds
                            stats['uuid_match_counts']['object_seed_events'] += int(object_match)
                            stats['uuid_match_counts']['subject_seed_events'] += int(subject_match)
                            stats['uuid_match_counts']['both_seed_events'] += int(object_match and subject_match)
                            stats['uuid_match_counts']['both_seed_read_events'] += int(object_match and subject_match and datum.get('type') == 'EVENT_READ')
                            event_type, stamp = str(datum.get('type')), datum.get('timestampNanos')
                            stats['event_types'][event_type] += 1
                            valid = isinstance(stamp, int) and not isinstance(stamp, bool)
                            stats['timestamp_counts']['event_total'] += 1
                            stats['timestamp_counts']['integer_timestamp' if valid else 'missing_or_noninteger_timestamp'] += 1
                            if valid and utc(stamp) is None:
                                stats['timestamp_counts']['integer_outside_datetime_range'] += 1
                            h = stats['host_event_ranges'].setdefault(host, {'event_count': 0, 'valid_timestamp_count': 0, 'min_ns': None, 'max_ns': None, 'first_event_ns': stamp if valid else None, 'last_event_ns': None, 'previous_valid_ns': None, 'time_regressions_in_read_order': 0, 'time_ties_in_read_order': 0, 'duplicate_event_identity_conflicts': 0})
                            h['event_count'] += 1
                            h['last_event_ns'] = stamp if valid else None
                            if valid:
                                h['valid_timestamp_count'] += 1
                                if h['previous_valid_ns'] is not None:
                                    h['time_regressions_in_read_order'] += int(stamp < h['previous_valid_ns'])
                                    h['time_ties_in_read_order'] += int(stamp == h['previous_valid_ns'])
                                h['previous_valid_ns'] = stamp
                                h['min_ns'] = stamp if h['min_ns'] is None else min(h['min_ns'], stamp)
                                h['max_ns'] = stamp if h['max_ns'] is None else max(h['max_ns'], stamp)
                            if uuid is not None:
                                fingerprint = (host, stamp, event_type)
                                if str(uuid) in event_ids and event_ids[str(uuid)] != fingerprint:
                                    h['duplicate_event_identity_conflicts'] += 1
                                event_ids[str(uuid)] = fingerprint
                            target = (target_path is not None and (datum.get('predicateObjectPath') == target_path or datum.get('predicateObject2Path') == target_path)) or str(datum.get('predicateObject')) in target_objects or str(datum.get('predicateObject2')) in target_objects or subject_match
                            if target:
                                stats['candidate_records_matched'] += 1
                                for field in ('predicateObject', 'predicateObject2'):
                                    if target_path is not None and datum.get(field + 'Path') == target_path and datum.get(field) is not None:
                                        target_objects.add(str(datum[field]))
                                if len(candidates) < 512:
                                    candidates.append({'locator': dict(current_record), 'hostId': host, **{k: datum.get(k) for k in ('uuid', 'type', 'timestampNanos', 'subject', 'predicateObject', 'predicateObjectPath', 'predicateObject2', 'predicateObject2Path')}, 'object_seed_match': object_match, 'subject_seed_match': subject_match, 'candidate_basis': 'Exact path, known object or secondary-label UUID match; not attack-instance identity'})
                        stats['last_complete_record'] = dict(current_record)
                        current_record = None
                        if stats['record_count'] % 50000 == 0:
                            print(json.dumps({'records_completed': stats['record_count'], 'expanded_bytes_delivered': stream.delivered, 'elapsed_seconds': time.monotonic() - start}), flush=True)
                    if block.consumed != size:
                        raise ValueError('Trailing bytes after declared OCF block records')
                    if reader.read_exact(stream, 16) != sync:
                        raise ValueError('OCF block sync mismatch')
                    stats['block_count_fully_validated'] += 1
                stats['compressed_source_position_including_read_ahead'] = raw.tell()
    except BudgetStop as exc:
        stopping = True
        stats['termination_reason'] = str(exc)
        stats['partial_record_start'] = current_record
    except ReaderIncompatible as exc:
        stats['termination_reason'] = 'CONTAINER_OR_READER_INCOMPATIBLE'
        stats['parse_anomalies'].append({'type': type(exc).__name__, 'message': str(exc), 'at_record': current_record})
    except (Exception, MemoryError) as exc:
        stats['termination_reason'] = 'RECORDED_PARSING_OR_RESOURCE_ERROR'
        stats['partial_record_start'] = current_record
        stats['parse_anomalies'].append({'type': type(exc).__name__, 'message': str(exc)[:500], 'at_record': current_record})
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        stats['expanded_bytes_delivered'] = stream.delivered if stream else 0
        stats['elapsed_seconds'] = time.monotonic() - start
        stats['peak_rss_bytes'] = rss_bytes()
        stats['source_identity_before'] = before
        stats['source_identity_after'] = identity(path.stat())
        stats['source_unchanged_during_probe'] = before == stats['source_identity_after']
    for host, value in stats['host_event_ranges'].items():
        value.pop('previous_valid_ns')
        for key in ('min', 'max', 'first_event', 'last_event'):
            value[key + '_utc'] = utc(value[key + '_ns']) if stats.get('timestamp_interpretation') == 'UNIX_EPOCH_NANOSECONDS_UTC_PER_EMBEDDED_SCHEMA' else None
        value['host_mapping_status'] = 'HOST_DEFINITION_OBSERVED' if host in stats['host_definition_map'] else 'HOST_NAME_UNRESOLVED_IN_READ_SCOPE'
    stats['references'] = {field: {'unique_references_seen': len(values), 'unique_references_not_defined_in_read_scope': sum(v not in defined for v in values), 'optional_null_or_missing_values': null_refs[field]} for field, values in refs.items()}
    stats['null_references_by_field'] = dict(null_refs)
    for candidate in candidates:
        candidate['subject_definition_in_read_scope'] = subjects.get(str(candidate['subject']))
        candidate['object_definition_types_in_read_scope'] = {k: defined.get(str(candidate[k])) for k in ('predicateObject', 'predicateObject2')}
        candidate['host_definition_in_read_scope'] = stats['host_definition_map'].get(candidate['hostId'])
    stats['candidate_records_retained'] = len(candidates)
    stats['candidate_retention_truncated'] = stats['candidate_records_matched'] > len(candidates)
    stats['candidate_detection_limitations'] = 'One sequential pass with exact secondary-label object and subject UUID hints; unresolved definitions remain unresolved. Paths alone do not identify the report attack. No second pass, no +4h assumption, no reverse traversal.'
    for key in ('record_types', 'top_level_types', 'event_types', 'subject_types', 'cdm_versions', 'host_ids_all_records', 'timestamp_counts'):
        stats[key] = dict(stats[key])
    stats['expanded_byte_accounting'] = 'Exact bytes returned by gzip.GzipFile.read to the CDM reader, including OCF header, record data and sync bytes. Internal gzip read-ahead/generated bytes are not measured or claimed exact. Null inner codec; no additional inner decompression. Block payloads stream directly without whole-block allocation.'
    stats['limits'] = limits
    return stats, candidates


def rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == 'darwin' else value * 1024)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', type=Path, required=True)
    ap.add_argument('--integrity-json', type=Path, required=True)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    safe_path(args.input)
    safe_path(args.output_dir)
    assert args.output_dir.is_dir() and args.output_dir.stat().st_uid == os.getuid()
    parser_path = Path(reader.__file__)
    assert hashlib.sha256(parser_path.read_bytes()).hexdigest() == PARSER_SHA
    intake = json.loads(args.integrity_json.read_text())
    actual = intake['selected_input']
    assert actual['status'] == 'FILE_VERIFIED' and Path(actual['path']) == args.input
    assert identity(args.input.stat()) == actual['after']
    assert not (args.output_dir / '03_probe_summary.json').exists()
    original_limits = resource.getrlimit(resource.RLIMIT_AS)
    memory_mode = 'PEAK_RSS_SUPERVISION_THRESHOLD'
    if sys.platform.startswith('linux'):
        hard = original_limits[1]
        resource.setrlimit(resource.RLIMIT_AS, (min(LIMITS['memory_bytes'], hard) if hard != resource.RLIM_INFINITY else LIMITS['memory_bytes'], hard))
        memory_mode = 'HARD_PROCESS_RLIMIT_AS_4GIB_PLUS_RSS_SUPERVISION'
    os.nice(10)
    contract = {'python': sys.executable, 'python_version': sys.version, 'platform': sys.platform, 'pid': os.getpid(), 'reader_sha256': PARSER_SHA, 'entry_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'source_sha256': actual['actual_sha256'], 'limits': LIMITS, 'memory_mode': memory_mode, 'rlimit_as_before': list(original_limits), 'rlimit_as_applied': list(resource.getrlimit(resource.RLIMIT_AS)), 'serial_cpu_job': True, 'niceness': os.nice(0), 'environment_no_bytecode': os.environ.get('PYTHONDONTWRITEBYTECODE'), 'new_dependencies_installed': False, 'reference_timestamp_relation': 'Report console/CDM alignment remains uncalibrated; no automatic +4h mapping', 'real_probe_attempt': 2, 'prior_records': 250000, 'maximum_cumulative_records_including_repeat': 500000}
    save(args.output_dir / '02_probe_contract_and_runtime.json', contract)
    seeds = json.loads((args.output_dir / '01_private_reference_lookup_seeds.json').read_text())
    stats, candidates = probe(args.input, dict(LIMITS), intake['target_reference']['object_path'], [seeds['published_object_hint']['normalized_fixed16_hex']], [v['normalized_fixed16_hex'] for v in seeds['nginx_subject_hints']])
    stats['source_compressed_sha256'] = actual['actual_sha256']
    stats['source_compressed_size'] = actual['actual_size']
    stats['status'] = 'PROBE_ABORTED_WITH_RECORDED_ERROR' if stats['parse_anomalies'] or not stats['source_unchanged_during_probe'] else 'FILE_VERIFIED_PROBE_REACHED_MEMBER_EOF' if stats['file_eof_reached'] else 'FILE_VERIFIED_BOUNDED_PROBE_COMPLETED_PARTIAL_SCOPE'
    save(args.output_dir / '03_probe_summary.json', stats)
    csv_path = args.output_dir / '04_hosts_event_types_and_time_ranges.csv'
    with csv_path.open('x', newline='') as out:
        writer = csv.writer(out, lineterminator=chr(10))
        writer.writerow(['category', 'host_id_or_event_type', 'count', 'min_ns', 'max_ns', 'first_event_ns', 'last_event_ns', 'min_utc', 'max_utc', 'time_regressions', 'mapping_status'])
        for host, value in stats['host_event_ranges'].items():
            writer.writerow(['host_events', host, value['event_count'], value['min_ns'], value['max_ns'], value['first_event_ns'], value['last_event_ns'], value['min_utc'], value['max_utc'], value['time_regressions_in_read_order'], value['host_mapping_status']])
        for kind, count in stats['event_types'].items():
            writer.writerow(['event_type', kind, count, '', '', '', '', '', '', '', 'READ_SCOPE_ONLY'])
    csv_path.chmod(0o600)
    if candidates:
        with (args.output_dir / 'private_candidates.jsonl').open('x') as out:
            for value in candidates:
                value['source_compressed_sha256'] = actual['actual_sha256']
                out.write(json.dumps(value, ensure_ascii=False) + chr(10))
        (args.output_dir / 'private_candidates.jsonl').chmod(0o600)
    print(json.dumps({'status': stats['status'], 'records': stats['record_count'], 'events': sum(stats['event_types'].values()), 'expanded_bytes': stats['expanded_bytes_delivered'], 'elapsed_seconds': stats['elapsed_seconds'], 'termination_reason': stats['termination_reason'], 'eof': stats['file_eof_reached'], 'candidate_count': stats['candidate_records_matched']}), flush=True)


if __name__ == '__main__':
    main()
