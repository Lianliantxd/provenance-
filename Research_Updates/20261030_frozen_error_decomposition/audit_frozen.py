"""Post-evaluation descriptive audit; never changes predictions or model settings."""
from pathlib import Path
import argparse
import collections
import csv
import hashlib
import json
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fact(e):
    identity = e['native_uuid'] if 'native_uuid' in e else e['key'].split('|', 1)[0]
    return (identity,
            e['u'], e['v'], e['t'], e['op'])


def write_csv(path, rows):
    with path.open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--reference-sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    start = time.monotonic()
    reads = {}

    def read(name):
        p = root / name
        b = p.read_bytes()
        reads[name] = {'bytes': len(b), 'sha256': sha(b)}
        return b

    def load(name):
        return json.loads(read(name))

    state = load('RETRIEVAL_EVALUATION_STATUS.json')
    assert state['status'] == 'POST_FREEZE_EVALUATION_COMPLETE'
    freeze = load('retrieval_predictions/PREDICTION_FREEZE.json')
    outputs = {}
    for name, expected in freeze.items():
        b = read('retrieval_predictions/' + name)
        assert sha(b) == expected, name
        outputs[name] = json.loads(b)
    assert len(outputs) == state['predictions_checked'] == 148
    scores = load('NODE_SCORES.json')
    mapping = {int(k): v[0] for k, v in load('private_node_uuid_map.json').items()}
    scored = {row['node_uuid'] for row in scores}
    q = {row['node_uuid'] for row in load('Q.json')}
    candidate_records = {v: load('retrieval_predictions/CANDIDATE_RECORDS_' + v + '.json')
                         for v in ['A', 'B']}
    candidates = {v: {mapping[n] for e in es for n in (e['u'], e['v'])}
                  for v, es in candidate_records.items()}
    candidate_facts = {v: {fact(e) for e in es} for v, es in candidate_records.items()}
    metrics = {row['file']: row for row in csv.DictReader(
        read('RETRIEVAL_METRICS.csv').decode().splitlines())}
    targets = {fact(e) for e in load('EVALUATION_ONLY_EVENT_TARGETS.json')}
    reference_bytes = args.reference.read_bytes()
    assert sha(reference_bytes) == args.reference_sha256
    reference = {row[0] for row in csv.reader(reference_bytes.decode().splitlines()) if row}
    assert len(reference) == 43
    reads['REFERENCE_IDENTITY_ONLY'] = {'bytes': len(reference_bytes),
                                      'sha256': sha(reference_bytes)}
    coverage = {}
    for version, cs in candidates.items():
        assert q <= cs
        assert cs <= scored, 'Do not infer a nested coverage funnel from counts alone'
        coverage[version] = {
            'reference_total': len(reference), 'reference_scored': len(reference & scored),
            'reference_outside_scored_universe': len(reference - scored),
            'reference_in_candidates': len(reference & cs),
            'reference_scored_but_outside_candidates': len((reference & scored) - cs),
            'candidate_nodes': len(cs), 'candidate_events': len(candidate_records[version]),
            'Q_nodes': len(q), 'Q_reference_hits': len(q & reference),
            'nested_sets_verified': True}
    audit_rows, concentration, groups = [], [], {}
    for name, output in outputs.items():
        m = metrics[name]
        v, method, condition = name[:-5].split('__')
        nodes = {mapping[n] for n in output['nodes']}
        facts = {fact(e) for e in output['events']}
        assert output['status'] == m['status'] == 'PREDICTED'
        assert q <= nodes <= candidates[v]
        assert facts <= candidate_facts[v]
        assert len(nodes) == int(m['returned_nodes'])
        assert len(output['events']) == int(m['returned_events'])
        assert len(nodes & reference) == int(m['annotation_hits'])
        assert len((nodes - q) & reference) == int(m['new_annotation_hits'])
        assert len(facts & targets) == int(m['limited_event_targets_hit'])
        c = coverage[v]
        audit_rows.append({'file': name, 'input': v, 'method': method, 'condition': condition,
            'returned_nodes': len(nodes), 'returned_events': len(output['events']),
            'reference_hits': len(nodes & reference),
            'new_reference_hits': len((nodes - q) & reference),
            'limited_event_hits': len(facts & targets),
            'miss_outside_scoring': c['reference_outside_scored_universe'],
            'miss_outside_candidates': c['reference_scored_but_outside_candidates'],
            'miss_within_candidates': len((reference & candidates[v]) - nodes),
            'partition_sum_verified': (len(reference - scored) +
                len((reference & scored) - candidates[v]) +
                len((reference & candidates[v]) - nodes) + len(nodes & reference)) == 43})
        groups[(v, method, condition)] = (nodes, facts, m)
        if condition == 'n100_e500':
            pairs = collections.Counter((e['u'], e['v']) for e in output['events'])
            operations = collections.Counter(e['op'] for e in output['events'])
            n = len(output['events'])
            concentration.append({'input': v, 'method': method, 'actual_nodes': len(nodes),
                'actual_events': n, 'unique_directed_endpoint_pairs': len(pairs),
                'largest_pair_events': max(pairs.values(), default=0),
                'largest_pair_fraction': max(pairs.values(), default=0)/n if n else 0,
                'same_pair_extra_records': n - len(pairs),
                'unique_native_facts': len(facts), 'operation_types': len(operations),
                'note': 'repeated endpoint pairs are real events, not proven redundant or benign'})
    contrasts = []
    for (v, method, condition), (fn, ff, fm) in groups.items():
        if method != 'operation_plus_memory':
            continue
        for (ov, om, oc), (bn, bf, bm) in groups.items():
            if ov != v or oc != condition or om == method:
                continue
            be, fe = int(bm['returned_events']), int(fm['returned_events'])
            weak = (len(bn) <= len(fn) and be <= fe
                    and int(bm['new_annotation_hits']) >= int(fm['new_annotation_hits'])
                    and int(bm['limited_event_targets_hit']) >= int(fm['limited_event_targets_hit']))
            strict = (len(bn) < len(fn) or be < fe
                      or int(bm['new_annotation_hits']) > int(fm['new_annotation_hits'])
                      or int(bm['limited_event_targets_hit']) > int(fm['limited_event_targets_hit']))
            contrasts.append({'input': v, 'condition': condition, 'comparator': om,
                'full_nodes': len(fn), 'comparator_nodes': len(bn),
                'full_events': fe, 'comparator_events': be,
                'comparator_minus_full_hits': int(bm['annotation_hits'])-int(fm['annotation_hits']),
                'comparator_minus_full_limited_events': int(bm['limited_event_targets_hit'])-int(fm['limited_event_targets_hit']),
                'comparator_weakly_dominates': weak, 'comparator_strictly_dominates': weak and strict,
                'common_reference_hits': len(fn & bn & reference),
                'full_only_reference_hits': len((fn-bn) & reference),
                'comparator_only_reference_hits': len((bn-fn) & reference),
                'node_jaccard': len(fn & bn)/len(fn | bn),
                'event_jaccard': len(ff & bf)/len(ff | bf)})
    write_csv(out/'PER_PREDICTION_AUDIT.csv', audit_rows)
    write_csv(out/'FULL_MODULE_CONTRASTS.csv', contrasts)
    write_csv(out/'EVENT_CONCENTRATION.csv', concentration)
    (out/'COVERAGE_PARTITIONS.json').write_text(json.dumps(coverage, indent=2)+'\n')
    # Reread only frozen predictions for integrity; these byte reads are counted separately.
    integrity_bytes = 0
    for name, h in freeze.items():
        b = (root/'retrieval_predictions'/name).read_bytes()
        integrity_bytes += len(b)
        assert sha(b) == h
    receipt = {'status': 'PASS', 'prediction_files_checked': len(outputs),
        'comparison_slices': len(contrasts), 'read_files': len(reads),
        'first_read_bytes': sum(x['bytes'] for x in reads.values()),
        'integrity_reread_bytes': integrity_bytes,
        'total_tracked_read_bytes': sum(x['bytes'] for x in reads.values())+integrity_bytes,
        'wall_seconds': time.monotonic()-start,
        'predictions_unchanged': True, 'raw_log_files_read': 0,
        'model_runs': 0, 'threshold_changes': 0, 'research_llm_calls': 0,
        'independent_attacks': 1, 'statistical_inference': 'NOT_IDENTIFIABLE_WITH_ONE_EXPOSED_CASE',
        'reference_sha256': sha(reference_bytes)}
    (out/'AUDIT_RECEIPT.json').write_text(json.dumps(receipt, indent=2)+'\n')
    (out/'INPUT_SHA256.json').write_text(json.dumps(reads, indent=2)+'\n')
    print(json.dumps({'receipt': receipt, 'coverage': coverage}, indent=2))


if __name__ == '__main__':
    main()
