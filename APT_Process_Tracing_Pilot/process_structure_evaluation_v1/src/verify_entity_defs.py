"""Targeted CDM entity-definition check for UUIDs already observed in window."""
from __future__ import annotations

import hashlib
import json
import re
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT/'outputs/bounded_window_index.json'
ARCHIVE = Path('/Users/tianxd/Documents/Transparent Computing E3/CADETS/ta1-cadets-e3-official-2.json.tar.gz')
MEMBER = 'ta1-cadets-e3-official-2.json'
UUID_RE = re.compile(rb'"uuid":"([0-9A-Fa-f-]{36})"')
KINDS = (b'.Subject"', b'.FileObject"', b'.NetFlowObject"')


def run() -> dict:
    targets = set(json.loads(INDEX.read_text())['labelled_entities_observed'])
    found: dict[str, dict] = {}
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        with archive.extractfile(MEMBER) as stream:
            if stream is None:
                raise ValueError('missing archive member')
            offset = 0
            for line_number, raw in enumerate(stream, 1):
                pos = offset
                offset += len(raw)
                kind = next((k[1:-1].decode() for k in KINDS if k in raw[:90]), None)
                if kind is None:
                    continue
                match = UUID_RE.search(raw[:180])
                if not match:
                    continue
                entity = match.group(1).decode().upper()
                if entity not in targets:
                    continue
                found[entity] = {'kind': kind, 'raw_offset': pos, 'raw_line': line_number, 'raw_sha256': hashlib.sha256(raw).hexdigest()}
    result = {'target_count': len(targets), 'definitions_matched': len(found), 'definitions': found, 'limitation': 'Only this one local archive member was checked'}
    (ROOT/'outputs/entity_definition_checks.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'target_count': len(targets), 'definitions_matched': len(found)}))
    return result


if __name__ == '__main__':
    run()
