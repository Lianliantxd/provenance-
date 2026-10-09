"""Executable guards for reference attribution and observation limits."""
from __future__ import annotations

import csv
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import run


class FeasibilityGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with (ROOT / "02_EVIDENCE_RELATIONS.csv").open() as f:
            cls.evidence = list(csv.DictReader(f))
        with (ROOT / "04_BASELINE_RESULTS.csv").open() as f:
            cls.results = list(csv.DictReader(f))
        cls.frozen = json.loads((ROOT / "01_FROZEN_CASES.json").read_text())

    def test_duplicate_event_counted_once(self) -> None:
        pool = {"e0", "e1"}
        out, paths, _ = run.select_paths("B1-Alternatives", {"p": [["e0", "e1"], ["e0", "e1"]]}, pool, 2)
        self.assertEqual(len(out), 2)
        self.assertEqual(len(paths), 2)

    def test_wrong_poi_not_credited(self) -> None:
        paths = [("p1", ["p1", "r"])]
        hit = any(owner == "p2" and "r" in path for owner, path in paths)
        self.assertFalse(hit)

    def test_future_event_not_upstream(self) -> None:
        seen, paths = run.backward_paths("before", [("before", "after", "PARENT_PID")])
        self.assertEqual(seen, {"before"})
        self.assertEqual(paths, [])

    def test_same_timestamp_unresolved(self) -> None:
        row = next(x for x in self.evidence if x["relation_id"] == "C_RECV_TO_SHELL")
        self.assertEqual(row["uncertainty_class"], "ORDER_UNRESOLVED")
        self.assertEqual(row["is_evaluable_as_dependency_reference"], "False")

    def test_same_subject_not_internal_flow(self) -> None:
        row = next(x for x in self.evidence if x["relation_id"] == "C_RECV_TO_LOADER")
        self.assertEqual(row["model_dependency_status"], "MODEL_POSSIBLE_DEPENDENCY")
        self.assertEqual(row["is_evaluable_as_dependency_reference"], "False")

    def test_pid_and_process_key_reuse(self) -> None:
        rows = json.loads((ROOT / "outputs/ws12_scope.json").read_text())
        a = next(x for x in rows if x["id"] == "ws12@1270525")
        b = next(x for x in rows if x["id"] == "ws12@1590222")
        self.assertEqual(a["process_key"], b["process_key"])
        self.assertNotEqual(a["pid"], b["pid"])

    def test_collection_gap_distinct_from_budget(self) -> None:
        gap = self.frozen["cases"][1]["coverage_gaps"]
        self.assertTrue(any("anomaly.json" in x for x in gap))
        rows = [x for x in self.results if x["budget_feasibility"] == "OUTPUT_BUDGET_INFEASIBLE"]
        self.assertTrue(rows)
        self.assertTrue(all(x["run_status"] == "COMPLETED_WITH_SCOPE_LIMITS" for x in rows))

    def test_infeasible_budget_not_strategy_failure(self) -> None:
        with (ROOT / "05_FAILURE_DIAGNOSIS.csv").open() as f:
            rows = list(csv.DictReader(f))
        self.assertTrue(rows)
        self.assertTrue(all(x["classification"] == "OUTPUT_BUDGET_INFEASIBLE" for x in rows))

    def test_no_edge_precision_without_closed_world_gt(self) -> None:
        self.assertNotIn("edge_precision", self.results[0])
        self.assertNotIn("edge_f1", self.results[0])

    def test_hash_not_causality(self) -> None:
        row = next(x for x in self.evidence if x["relation_id"] == "C_RECV_TO_LOADER")
        self.assertEqual(row["verified_this_run"], "True")
        self.assertNotEqual(row["attack_relation_reference_status"], "EXACT_CAUSAL_FLOW_PROVEN")

    def test_reference_excluded_from_selector(self) -> None:
        code = (ROOT / "src/run.py").read_text()
        selector = code.split("def select_paths(", 1)[1].split("\ndef run()", 1)[0]
        self.assertNotIn("CADETS_REF", selector)
        self.assertNotIn("ref_events", selector)

    def test_anomaly_only_not_background_recovery(self) -> None:
        ws = self.frozen["cases"][1]
        self.assertIn("anomaly channel", ws["sensor"])
        self.assertTrue(all("anomaly.json" in p for p in ws["source_files"]))


if __name__ == "__main__":
    unittest.main()
