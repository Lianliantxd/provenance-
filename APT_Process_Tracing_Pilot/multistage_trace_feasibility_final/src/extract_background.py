"""Stream one existing CADETS member into a bounded, label-blind event table."""
from __future__ import annotations

import argparse
import collections
import csv
import gzip
import hashlib
import json
import tarfile
import time
from pathlib import Path

ARCHIVE = Path('/Users/tianxd/Documents/Transparent Computing E3/CADETS/ta1-cadets-e3-official-2.json.tar.gz')
MEMBER = 'ta1-cadets-e3-official-2.json'
HOST = '83C8ED1F-5045-DBCD-B39F-918F0DF4F851'
LO = 1523555940000000000
HI = 1523558340000000000
ORIENT = {'EVENT_READ': 'object_to_subject', 'EVENT_RECVFROM': 'object_to_subject', 'EVENT_EXECUTE': 'object_to_subject', 'EVENT_WRITE': 'subject_to_object', 'EVENT_SENDTO': 'subject_to_object', 'EVENT_CONNECT': 'subject_to_object', 'EVENT_FORK': 'subject_to_object'}
EFIELDS = 'event_uuid timestamp_ns host_uuid subject_uuid object_uuid object2_uuid operation predicate_path predicate2_path analysis_src_uuid analysis_dst_uuid direction_status sequence_raw raw_offset raw_line raw_sha256'.split()
NFIELDS = 'entity_uuid kind host_uuid path cmdline cid parent_subject local_address local_port remote_address remote_port raw_offset raw_line raw_sha256'.split()


def uid(value: object) -> str:
    return str(next(iter(value.values()), '')) if isinstance(value, dict) else ''


def scalar(value: object) -> str:
    return str(next(iter(value.values()), '')) if isinstance(value, dict) else (str(value) if value is not None else '')


def fast_time(raw: bytes) -> int | None:
    key = b'"timestampNanos":'
    p = raw.find(key)
    if p < 0:
        return None
    p += len(key)
    e = p
    while e < len(raw) and 48 <= raw[e] <= 57:
        e += 1
    return int(raw[p:e]) if e > p else None


def extract(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    counts: collections.Counter[str] = collections.Counter()
    started = time.monotonic()
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        member = archive.getmember(MEMBER)
        with archive.extractfile(member) as stream, gzip.open(out/'background_events.csv.gz', 'wt', newline='') as event_file, gzip.open(out/'entity_definitions.csv.gz', 'wt', newline='') as entity_file:
            if stream is None:
                raise ValueError('missing archive member')
            ew = csv.DictWriter(event_file, fieldnames=EFIELDS)
            nw = csv.DictWriter(entity_file, fieldnames=NFIELDS)
            ew.writeheader(); nw.writeheader()
            offset = 0
            for line_number, raw in enumerate(stream, 1):
                pos = offset
                offset += len(raw)
                counts['lines_scanned'] += 1
                if b'"datum":{"com.bbn.tc.schema.avro.cdm18.' not in raw:
                    continue
                if b'.Event"' in raw[:75]:
                    t = fast_time(raw)
                    if t is None or not LO <= t <= HI:
                        continue
                    counts['timestamped_window_events'] += 1
                    try:
                        event = json.loads(raw)['datum']['com.bbn.tc.schema.avro.cdm18.Event']
                    except (ValueError, KeyError, TypeError):
                        counts['parse_failures'] += 1
                        continue
                    if event.get('hostId') != HOST:
                        counts['other_host_window_events'] += 1
                        continue
                    subject, obj, obj2 = uid(event.get('subject')), uid(event.get('predicateObject')), uid(event.get('predicateObject2'))
                    op = event.get('type', '')
                    orientation = ORIENT.get(op, '')
                    src, dst = ((obj, subject) if orientation == 'object_to_subject' else (subject, obj)) if orientation else ('', '')
                    status = 'DIRECT_OPERATION' if orientation and src and dst else 'UNSUPPORTED_OR_MISSING_ENDPOINT'
                    ew.writerow({'event_uuid': event.get('uuid', ''), 'timestamp_ns': t, 'host_uuid': event.get('hostId', ''), 'subject_uuid': subject, 'object_uuid': obj, 'object2_uuid': obj2, 'operation': op, 'predicate_path': scalar(event.get('predicateObjectPath')), 'predicate2_path': scalar(event.get('predicateObject2Path')), 'analysis_src_uuid': src, 'analysis_dst_uuid': dst, 'direction_status': status, 'sequence_raw': json.dumps(event.get('sequence')), 'raw_offset': pos, 'raw_line': line_number, 'raw_sha256': hashlib.sha256(raw).hexdigest()})
                    counts['events_written'] += 1
                    counts['direct_operation_events' if status == 'DIRECT_OPERATION' else 'unsupported_or_missing_endpoint'] += 1
                    counts[f'op:{op}'] += 1
                elif any(kind in raw[:90] for kind in (b'.Subject"', b'.FileObject"', b'.NetFlowObject"')):
                    try:
                        kind_key, entity = next(iter(json.loads(raw)['datum'].items()))
                    except (ValueError, KeyError, TypeError, StopIteration):
                        counts['entity_parse_failures'] += 1
                        continue
                    kind = kind_key.rsplit('.', 1)[-1]
                    base = entity.get('baseObject') or {}
                    host = entity.get('hostId') or base.get('hostId', '')
                    if host != HOST:
                        continue
                    props = (entity.get('properties') or {}).get('map') or {}
                    base_props = (base.get('properties') or {}).get('map') or {}
                    nw.writerow({'entity_uuid': entity.get('uuid', ''), 'kind': kind, 'host_uuid': host, 'path': props.get('path') or base_props.get('path') or '', 'cmdline': scalar(entity.get('cmdLine')), 'cid': entity.get('cid', ''), 'parent_subject': uid(entity.get('parentSubject')), 'local_address': entity.get('localAddress', ''), 'local_port': entity.get('localPort', ''), 'remote_address': entity.get('remoteAddress', ''), 'remote_port': entity.get('remotePort', ''), 'raw_offset': pos, 'raw_line': line_number, 'raw_sha256': hashlib.sha256(raw).hexdigest()})
                    counts['entity_definitions_written'] += 1
            counts['bytes_scanned'] = offset
            counts['member_expected_bytes'] = member.size
    if counts['bytes_scanned'] != counts['member_expected_bytes']:
        raise IOError('partial archive member scan')
    counts['elapsed_seconds'] = round(time.monotonic()-started, 3)
    manifest = {'archive': str(ARCHIVE), 'archive_sha256_expected': '8d2f090d372cfb0d21bfb72dba6824884ce7870b5c8d24df34e9081b9b09c793', 'member': MEMBER, 'host_uuid': HOST, 'window_ns_inclusive': [LO, HI], 'orientation': ORIENT, 'counts': dict(counts), 'scope_rule': 'all Event records in one host/time member; no attack label or report entity filter', 'unsupported_policy': 'preserved in table with empty analysis direction; excluded from directed search'}
    (out/'background_manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'events': counts['events_written'], 'direct': counts['direct_operation_events'], 'unsupported': counts['unsupported_or_missing_endpoint'], 'entities': counts['entity_definitions_written'], 'elapsed_seconds': counts['elapsed_seconds']}))
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    extract(parser.parse_args().out)
