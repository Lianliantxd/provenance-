import json
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from timeline import path, index_path


class Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.freeze = json.loads((ROOT / "01_PRESEARCH_FROZEN_ANCHORS.json").read_text())
        cls.t1 = json.loads((ROOT / "outputs/t1_b_only.json").read_text())
        cls.t2 = json.loads((ROOT / "outputs/t2_known_endpoints.json").read_text())
        cls.manifest = json.loads((ROOT / "outputs/background_manifest.json").read_text())
        cls.a = cls.freeze["A_evaluation_only"]["event_uuid"]
        cls.b = cls.freeze["B_query_POI"]["event_uuid"]

    def test_01_later_not_earlier_cause(self):
        self.assertLess(int(self.freeze["A_evaluation_only"]["timestamp_ns"]), int(self.freeze["B_query_POI"]["timestamp_ns"]))

    def test_02_equal_time_has_no_link(self):
        rows = {2:[{"event_uuid":"B"},{"event_uuid":"X"}],1:[{"event_uuid":"A"}]}
        self.assertEqual([r["event_uuid"] for r in path(rows,[2,1],"B")], ["B","A"])

    def test_03_event_and_entity_uuid_distinct(self):
        self.assertNotEqual(self.b,self.freeze["B_query_POI"]["subject_uuid"])

    def test_04_offset_not_index(self):
        self.assertGreater(int(self.freeze["B_query_POI"]["raw_offset"]), self.manifest["counts"]["lines_scanned"])

    def test_05_no_label_filter(self):
        self.assertEqual(self.manifest["counts"]["events_written"],178399)
        self.assertIn("no attack label",self.manifest["scope_rule"])

    def test_06_A_not_in_T1_config_or_code(self):
        cfg=(ROOT / "configs/t1_query.json").read_text()
        src=(ROOT / "src/run_t1.py").read_text()
        self.assertNotIn(self.a,cfg)
        self.assertNotIn("t2_query",src)
        self.assertNotIn("PRESEARCH_FROZEN",src)

    def test_07_T2_not_T1_success(self):
        self.assertFalse(any(self.a in [r["event_uuid"] for r in p] for p in self.t1["paths"].values()))
        self.assertEqual(self.t2["path_B_to_A"][-1]["event_uuid"],self.a)

    def test_08_coarse_links_declared(self):
        self.assertEqual(self.t2["link_types"]["MODEL_POSSIBLE_DEPENDENCY_cross_event"],37)
        self.assertFalse(self.t2["direct_only_A_to_B_connected"])

    def test_09_B0_budget_no_false_full_pool(self):
        self.assertFalse(self.t1["statuses"]["128"]["B0_pool_complete"])
        self.assertTrue(self.t1["statuses"]["512"]["B0_pool_complete"])

    def test_10_truncation_distinct_from_unreachable(self):
        self.assertEqual(self.t2["budget_status"]["32"],"BUDGET_EXCEEDED")
        self.assertEqual(self.t2["budget_status"]["128"],"PATH_VISIBLE_OBSERVATION_BOUNDARY_NOT_PROVEN_ROOT")

    def test_11_POI_not_non_POI_recovery(self):
        self.assertNotEqual(self.a,self.b)
        self.assertEqual(self.t1["paths"]["B1-Min"][0]["event_uuid"],self.b)

    def test_12_raw_hash_is_not_causality(self):
        verified=json.loads((ROOT / "outputs/raw_anchor_verification.json").read_text())
        self.assertTrue(verified[self.a]["verified"])
        self.assertFalse(self.t2["direct_only_A_to_B_connected"])

    def test_13_report_time_audited(self):
        self.assertIn("inferred EDT",self.freeze["report"]["timezone"])
        self.assertEqual(self.freeze["selection"]["B_time_utc"][:16],"2018-04-12T18:02")

    def test_14_background_not_attack_only(self):
        con=sqlite3.connect(index_path())
        all_count=con.execute("select count(*) from event").fetchone()[0]
        subject_count=con.execute("select count(*) from event where subject_uuid=?",(self.freeze["B_query_POI"]["subject_uuid"],)).fetchone()[0]
        con.close()
        self.assertGreater(all_count,subject_count)
        self.assertEqual(all_count,178399)


if __name__ == "__main__": unittest.main()
