"""Invariant checks for the frozen CADETS label adaptation audit."""
from __future__ import annotations

import ast
import csv
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from evaluate import classify_gap, entity_ids, read_labels  # noqa: E402


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = json.loads((ROOT/'outputs/baseline_paths.json').read_text())
        cls.window = json.loads((ROOT/'outputs/bounded_window_index.json').read_text())
        cls.summary = json.loads((ROOT/'outputs/label_summary.json').read_text())
        with (ROOT/'04_BASELINE_PROCESS_RESULTS.csv').open(newline='') as handle:
            cls.results = list(csv.DictReader(handle))
        with (ROOT/'03_LABEL_TO_RAW_MAPPING.csv').open(newline='') as handle:
            cls.mapping = list(csv.DictReader(handle))

    def test_entity_uuid_is_not_event_uuid(self) -> None:
        event_ids = set(self.baseline['results']['B0']['candidate_event_ids'])
        assert not event_ids & {row['label_uuid'] for row in self.mapping}

    def test_repeated_events_do_not_duplicate_entity_coverage(self) -> None:
        events = {'a': {'subject_id': 'X', 'object_id': 'Y'}, 'b': {'subject_id': 'X', 'object_id': 'Y'}}
        self.assertEqual(entity_ids({'a', 'b'}, events), {'X', 'Y'})

    def test_poi_anchor_excluded_from_nonpoi(self) -> None:
        for row in self.mapping:
            if row['is_poi_anchor'] == 'True':
                self.assertEqual(row['evaluable_as_nonpoi_reference'], 'False')

    def test_source_denominators_independent(self) -> None:
        self.assertEqual(self.summary['reapr']['unique_uuids'], 655)
        self.assertEqual(self.summary['orthrus']['unique_uuids'], 43)
        self.assertEqual(len(self.mapping), 698)

    def test_search_module_has_no_label_input(self) -> None:
        source = (ROOT/'src/run_baselines.py').read_text()
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any('label' in ast.unparse(call).lower() for call in calls))

    def test_equal_timestamp_remains_unresolved(self) -> None:
        alternative = self.baseline['results']['B1-Alternatives']
        self.assertIn('UNRESOLVED', alternative['time_status'])
        self.assertEqual(alternative['path_count'], 3)

    def test_small_graph_not_full_background(self) -> None:
        self.assertEqual(self.window['counters']['host_window_events'], 178399)
        self.assertEqual(self.baseline['results']['B0']['candidate_count'], 162)

    def test_no_structural_reference_means_na(self) -> None:
        for row in self.results:
            for key in ('structural_precision', 'structural_recall', 'structural_f1'):
                self.assertEqual(row[key], 'NA:NO_INDEPENDENT_RELATION_GT')

    def test_record_hash_is_not_causality(self) -> None:
        self.assertTrue(self.baseline['results']['B1-Min']['raw_ref_hashes'])
        self.assertEqual(self.results[1]['structural_f1'], 'NA:NO_INDEPENDENT_RELATION_GT')

    def test_failure_stages_distinct(self) -> None:
        cases = [
            ((False, False, False, False, True, True), 'OUT_OF_CHECKED_MEMBER_WINDOW'),
            ((True, False, False, False, True, True), 'INPUT_GRAPH_PRE_FILTERED_OR_WINDOW_TRUNCATED'),
            ((True, True, False, False, True, True), 'CANDIDATE_SEARCH_MISS_IN_10_SECOND_GRAPH'),
            ((True, True, True, False, False, True), 'OUTPUT_BUDGET_INFEASIBLE'),
            ((True, True, True, False, True, True), 'PATH_SELECTION_MISS'),
            ((True, True, True, False, True, False), 'ENTITY_NOT_SELECTED_NO_STRUCTURAL_GT'),
        ]
        for args, expected in cases:
            self.assertEqual(classify_gap(*args), expected)

    def test_public_csv_is_headerless_data(self) -> None:
        label_path = Path(self.summary['orthrus']['label_file'])
        labels = read_labels(label_path)
        self.assertEqual(len(labels), 43)
        self.assertEqual(labels[0]['type'], 'file')


if __name__ == '__main__':
    unittest.main()
