"""Join public positive entity labels to raw CDM UUIDs after baseline search."""
from __future__ import annotations

import ast
import collections
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parents[1]
LABEL_ROOT = WORK/'research/sources/PIDSMaker/Ground_Truth'
EVENTS = ROOT.parent/'results/cadets_20180412_q1/events.csv'
BASELINE = ROOT/'outputs/baseline_paths.json'
INDEX = ROOT/'outputs/bounded_window_index.json'
DEFS = ROOT/'outputs/entity_definition_checks.json'
FIELDS = 'label_source label_uuid label_entity_type label_entity_name label_node_id raw_entity_uuid raw_event_ids raw_event_offsets raw_event_hashes matched_host matched_time_window matching_rule number_of_matches in_raw_scope matched_cdm_definition definition_type_status in_graph in_candidate_pool is_poi_anchor evaluable_as_nonpoi_reference mapping_status exclusion_reason'.split()
RESULT_FIELDS = 'method poi_event_id search_scope output_budget candidate_event_count output_event_count selected_path_count source total_published_label_entities raw_window_observed_entities graph_observed_entities candidate_pool_entities poi_anchor_entities evaluable_nonpoi_candidate_entities output_label_entities output_nonpoi_label_entities published_attack_entity_coverage positive_reference_coverage nonpoi_reference_coverage structural_precision structural_recall structural_f1 path_time_status run_status'.split()


def read_labels(path: Path) -> list[dict]:
    rows = []
    with path.open(newline='') as handle:
        for uuid, description, node_id in csv.reader(handle):
            parsed = ast.literal_eval(description)
            if not isinstance(parsed, dict) or len(parsed) != 1:
                raise ValueError(f'invalid label description: {path}')
            entity_type, name = next(iter(parsed.items()))
            if entity_type not in {'subject', 'file', 'netflow'}:
                raise ValueError(f'unknown entity type: {entity_type}')
            rows.append({'uuid': uuid.upper(), 'type': entity_type, 'name': name, 'node_id': node_id})
    return rows


def entity_ids(event_ids: set[str], events: dict[str, dict]) -> set[str]:
    return {uuid for eid in event_ids for uuid in (events[eid]['subject_id'], events[eid]['object_id']) if uuid}


def classify_gap(raw: bool, graph: bool, candidate: bool, selected: bool, feasible: bool, independent_relation: bool) -> str:
    if not raw:
        return 'OUT_OF_CHECKED_MEMBER_WINDOW'
    if not graph:
        return 'INPUT_GRAPH_PRE_FILTERED_OR_WINDOW_TRUNCATED'
    if not candidate:
        return 'CANDIDATE_SEARCH_MISS_IN_10_SECOND_GRAPH'
    if not feasible:
        return 'OUTPUT_BUDGET_INFEASIBLE'
    if not selected:
        return 'PATH_SELECTION_MISS' if independent_relation else 'ENTITY_NOT_SELECTED_NO_STRUCTURAL_GT'
    return 'SELECTED_ENTITY_ONLY' if not independent_relation else 'RELATION_REQUIRES_SEPARATE_EDGE_CHECK'


def run() -> dict:
    window = json.loads(INDEX.read_text())
    raw_index = window['labelled_entities_observed']
    definitions = json.loads(DEFS.read_text())['definitions']
    baseline = json.loads(BASELINE.read_text())
    with EVENTS.open(newline='') as handle:
        events = {row['native_event_id']: row for row in csv.DictReader(handle)}
    if baseline['input_events_sha256'] != hashlib.sha256(EVENTS.read_bytes()).hexdigest():
        raise ValueError('baseline input mismatch')
    poi = baseline['poi_event_id']
    anchors = entity_ids({poi}, events)
    graph = entity_ids(set(events), events)
    candidate = entity_ids(set(baseline['results']['B0']['candidate_event_ids']), events)
    if not candidate <= graph:
        raise ValueError('candidate UUID outside graph')
    output_rows = []
    metric_rows = []
    summaries = {}
    diagnoses = {}
    for source in ('reapr', 'orthrus'):
        label_path = LABEL_ROOT/source/'E3-CADETS/node_Nginx_Backdoor_12.csv'
        labels = read_labels(label_path)
        ids = {item['uuid'] for item in labels}
        if len(ids) != len(labels):
            raise ValueError('duplicate UUID requires explicit resolution')
        source_rows = []
        for item in labels:
            uuid = item['uuid']
            raw = raw_index.get(uuid)
            definition = definitions.get(uuid)
            match_events = [events[eid] for eid in events if uuid in (events[eid]['subject_id'], events[eid]['object_id'])]
            expected = {'subject': 'Subject', 'file': 'FileObject', 'netflow': 'NetFlowObject'}[item['type']]
            type_status = 'MATCH' if definition and definition['kind'] == expected else ('CONFLICT' if definition else 'DEFINITION_NOT_FOUND')
            status = 'CANDIDATE_NONPOI' if uuid in candidate and uuid not in anchors else ('POI_ANCHOR' if uuid in anchors else ('GRAPH_ONLY' if uuid in graph else ('RAW_WINDOW_ONLY' if raw else 'NOT_OBSERVED_IN_THIS_MEMBER_WINDOW')))
            row = dict(zip(FIELDS, [source, uuid, item['type'], item['name'], item['node_id'], uuid if raw else '', json.dumps([e['native_event_id'] for e in match_events] or [e['event_uuid'] for e in raw['sample_events']] if raw else []), json.dumps([e['raw_uncompressed_offset'] for e in match_events] or [e['raw_offset'] for e in raw['sample_events']] if raw else []), json.dumps([e['raw_record_hash'] for e in match_events] or [e['raw_sha256'] for e in raw['sample_events']] if raw else []), window['host'] if raw else '', '2018-04-12T17:59:00Z/18:39:00Z' if raw else '', 'exact CDM subject/predicateObject/predicateObject2 UUID; event UUID never joined to label UUID', raw['event_count'] if raw else 0, bool(raw), bool(definition), type_status, uuid in graph, uuid in candidate, uuid in anchors, uuid in candidate and uuid not in anchors, status, 'only one local archive member checked' if not raw else ('entity type conflict' if type_status == 'CONFLICT' else '')]))
            source_rows.append(row)
        output_rows += source_rows
        summaries[source] = {'label_file': str(label_path), 'sha256': hashlib.sha256(label_path.read_bytes()).hexdigest(), 'rows': len(labels), 'unique_uuids': len(ids), 'entity_types': dict(collections.Counter(x['type'] for x in labels)), 'raw_window_observed': len(ids & raw_index.keys()), 'cdm_definitions_matched': sum(r['matched_cdm_definition'] for r in source_rows), 'type_conflicts': sum(r['definition_type_status'] == 'CONFLICT' for r in source_rows), 'in_graph': len(ids & graph), 'in_candidate_pool': len(ids & candidate), 'poi_anchors': len(ids & anchors), 'nonpoi_candidate': len((ids & candidate)-anchors), 'unobserved_in_member_window': len(ids-raw_index.keys())}
        for method, result in baseline['results'].items():
            selected = entity_ids(set(result['selected_event_ids']), events)
            raw_seen = ids & raw_index.keys()
            graph_seen = ids & graph
            candidate_seen = ids & candidate
            nonpoi = candidate_seen-anchors
            output_hit = ids & selected
            nonpoi_hit = nonpoi & selected
            metric_rows.append(dict(zip(RESULT_FIELDS, [method, poi, baseline['scope'], baseline['budget'], result['candidate_count'], result['output_event_count'], result['path_count'], source, len(ids), len(raw_seen), len(graph_seen), len(candidate_seen), len(ids & anchors), len(nonpoi), len(output_hit), len(nonpoi_hit), f'{len(output_hit)}/{len(ids)}', f'{len(output_hit)}/{len(graph_seen)}' if graph_seen else 'NA:NO_GRAPH_LABELS', f'{len(nonpoi_hit)}/{len(nonpoi)}' if nonpoi else 'NA:NO_NONPOI_CANDIDATE_LABELS', 'NA:NO_INDEPENDENT_RELATION_GT', 'NA:NO_INDEPENDENT_RELATION_GT', 'NA:NO_INDEPENDENT_RELATION_GT', result['time_status'], 'COMPLETED_10_SECOND_GRAPH_ONLY'])))
            diagnoses[f'{source}:{method}'] = dict(collections.Counter(classify_gap(uuid in raw_index, uuid in graph, uuid in candidate, uuid in selected, result['feasibility'] == 'FEASIBLE', False) for uuid in ids if uuid not in anchors))
    ROOT.mkdir(parents=True, exist_ok=True)
    with (ROOT/'03_LABEL_TO_RAW_MAPPING.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(output_rows)
    with (ROOT/'04_BASELINE_PROCESS_RESULTS.csv').open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(metric_rows)
    (ROOT/'outputs/label_summary.json').write_text(json.dumps(summaries, indent=2)+'\n')
    (ROOT/'outputs/gap_diagnosis.json').write_text(json.dumps(diagnoses, indent=2)+'\n')
    print(json.dumps(summaries))
    return summaries


if __name__ == '__main__':
    run()
