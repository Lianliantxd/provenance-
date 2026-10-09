"""One bounded, label-blind event inventory of an existing CADETS CDM member.

The time window comes from the published attack schedule. Labels are used only
after the inventory has been collected, for UUID joins and compact evidence.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import tarfile
from pathlib import Path

ARCHIVE = Path('/Users/tianxd/Documents/Transparent Computing E3/CADETS/ta1-cadets-e3-official-2.json.tar.gz')
MEMBER = 'ta1-cadets-e3-official-2.json'
HOST = '83C8ED1F-5045-DBCD-B39F-918F0DF4F851'
LO = 1523555940000000000  # 2018-04-12 17:59:00 UTC
HI = 1523558340000000000  # 2018-04-12 18:39:00 UTC


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


def uid(value: object) -> str:
    if isinstance(value, dict):
        return str(next(iter(value.values()), ''))
    return ''


def scan(out: Path) -> dict:
    counters: collections.Counter[str] = collections.Counter()
    # All timestamped events in the frozen host/window enter this inventory.
    # The published labels are deliberately absent from the scan predicate.
    observed: dict[str, dict] = {}
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        member = archive.getmember(MEMBER)
        with archive.extractfile(member) as stream:
            if stream is None:
                raise ValueError('missing member stream')
            offset = 0
            for line_number, raw in enumerate(stream, 1):
                pos = offset
                offset += len(raw)
                counters['lines'] += 1
                if b'"datum":{"com.bbn.tc.schema.avro.cdm18.' not in raw:
                    continue
                if b'.Event"' in raw:
                    t = fast_time(raw)
                    if t is None or not LO <= t <= HI:
                        continue
                    counters['window_event_lines'] += 1
                    try:
                        event = json.loads(raw)['datum']['com.bbn.tc.schema.avro.cdm18.Event']
                    except (ValueError, KeyError, TypeError):
                        counters['parse_failure'] += 1
                        continue
                    if event.get('hostId') != HOST:
                        counters['other_host'] += 1
                        continue
                    counters['host_window_events'] += 1
                    event_id = event.get('uuid', '')
                    op = event.get('type', '')
                    subject, obj, obj2 = uid(event.get('subject')), uid(event.get('predicateObject')), uid(event.get('predicateObject2'))
                    for entity in set(filter(None, (subject, obj, obj2))):
                        item = observed.setdefault(entity, {'event_count': 0, 'sample_events': [], 'roles': collections.Counter()})
                        item['event_count'] += 1
                        item['roles']['subject' if entity == subject else 'object'] += 1
                        if len(item['sample_events']) < 4:
                            item['sample_events'].append({'event_uuid': event_id, 'raw_offset': pos, 'raw_line': line_number, 'raw_sha256': hashlib.sha256(raw).hexdigest(), 'timestamp_nanos': t, 'operation': op})
            counters['bytes_scanned'] = offset
            counters['member_expected_bytes'] = member.size
    if counters['bytes_scanned'] != counters['member_expected_bytes']:
        raise IOError('partial member scan')
    # Join labels only after the inventory is complete; no label affects scope.
    label_dir = Path(__file__).resolve().parents[3] / 'research/sources/PIDSMaker/Ground_Truth'
    labels: set[str] = set()
    for source in ('reapr', 'orthrus'):
        with (label_dir/source/'E3-CADETS/node_Nginx_Backdoor_12.csv').open(newline='') as handle:
            labels.update(row[0].upper() for row in csv.reader(handle))
    selected = {k: {'event_count': v['event_count'], 'sample_events': v['sample_events'], 'roles': dict(v['roles'])} for k, v in observed.items() if k in labels}
    result = {'archive': str(ARCHIVE), 'member': MEMBER, 'host': HOST, 'window_ns_inclusive': [LO, HI], 'counters': dict(counters), 'total_observed_entity_uuids': len(observed), 'labelled_entities_observed': selected, 'entity_definition_status': 'NOT_INDEXED; event subject/object UUID is verified, standalone entity definition not verified'}
    out.mkdir(parents=True, exist_ok=True)
    (out/'bounded_window_index.json').write_text(json.dumps(result, ensure_ascii=False) + '\n')
    print(json.dumps({'host_window_events': counters['host_window_events'], 'observed_entities': len(observed), 'labelled_entities_observed': len(selected), 'bytes_scanned': counters['bytes_scanned']}))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    scan(parser.parse_args().out)
