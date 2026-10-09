import csv
import hashlib
import json
import random
import unittest
from pathlib import Path

R=Path(__file__).resolve().parents[1]
O=R/"outputs"


class GateContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f=json.loads((R/"02_PRE_REGISTERED_TASK_AND_CASES.json").read_text())
        cls.s=json.loads((O/"sensor_manifest.json").read_text())
        cls.p=json.loads((O/"pointer_measurement.json").read_text())
        cls.oracle=json.loads((O/"oracle/cases.json").read_text())
        cls.proj=[json.loads(p.read_text()) for p in sorted((O/"projected_observations").glob("*.json"))]
        with (O/"g4_coverage_risk_cost.csv").open() as h:
            cls.results=list(csv.DictReader(h))

    def test_01_time_order_not_value_flow(self):
        self.assertEqual([x["op"] for x in self.proj[0]["events"] if x["op"] in {"read","write"}],["read","write"])
        self.assertEqual(len({x["condition"] for x in self.oracle}),2)

    def test_02_question_types_separate(self):
        self.assertIn("payload value dependence",self.f["Q_semantics"])
        self.assertNotIn("request ID",self.f["Q_semantics"])

    def test_03_abstain_not_nondependence(self):
        a=next(x for x in self.results if x["strategy"]=="ALWAYS_ABSTAIN")
        self.assertEqual(a["determinate_assertions"],"0")
        self.assertEqual(a["abstentions"],"12")

    def test_04_raw_and_projection_separate(self):
        self.assertEqual(len(self.s),12)
        self.assertEqual(len(self.proj),12)
        self.assertEqual(len({x["raw_sha256"] for x in self.s}),12)
        self.assertEqual(len({x["projection_sha256"] for x in self.s}),1)

    def test_05_full_raw_not_claimed_equivalent(self):
        self.assertEqual(len({x["raw_sha256"] for x in self.s}),12)

    def test_06_same_binary_cmd_env_paths(self):
        self.assertEqual(hashlib.sha256((R/"src/f1.c").read_bytes()).hexdigest(),self.f["program_source_sha256"])
        self.assertEqual(len({x["argv_shape"] for x in self.s}),1)
        self.assertEqual(len({x["environment_sha256"] for x in self.s}),1)
        self.assertEqual({e["object"] for e in self.proj[0]["events"]},{"input.bin","output.bin"})

    def test_07_intervention_control_preserved(self):
        q={x["run_id"]:x for x in self.oracle}
        self.assertEqual(q["r01"]["condition"],q["r03"]["condition"])
        self.assertNotEqual(q["r01"]["output_hex"],q["r03"]["output_hex"])
        self.assertEqual(q["r02"]["condition"],q["r04"]["condition"])
        self.assertEqual(q["r02"]["output_hex"],q["r04"]["output_hex"])

    def test_08_oracle_not_in_predictor(self):
        src=(R/"src/evaluate_g4.py").read_text().split("def evaluate():")[0]
        self.assertNotIn("private/oracle",src)
        self.assertNotIn('"condition"',src)
        self.assertNotIn("FLOW_MODE",json.dumps(self.proj))

    def test_09_request_id_not_value_proof(self):
        lines=(R/"04_MEASUREMENT_CATALOG.csv").read_text()
        self.assertIn("Does not prove payload value dependence",lines)

    def test_10_historical_collection_not_retroactive(self):
        with (R/"04_MEASUREMENT_CATALOG.csv").open() as h: rows={x["measurement_id"]:x for x in csv.DictReader(h)}
        self.assertEqual(rows["M_VALUE_LINEAGE"]["requires_predeployment"],"yes")

    def test_11_denominators(self):
        for r in self.results:
            self.assertEqual(int(r["determinate_assertions"])+int(r["abstentions"]),12)
            self.assertEqual(int(r["correct_determinate"])+int(r["wrong_determinate"]),int(r["determinate_assertions"]))

    def test_12_same_cost_comparison(self):
        names={"FIXED_RULE_VALUE_LINEAGE","FIXED_LOW_COST","COLLECT_ALL_VALIDATED_FEASIBLE","RANDOM_SAME_BUDGET"}
        self.assertEqual({x["measurement_bytes_total"] for x in self.results if x["strategy"] in names},{"768"})

    def test_13_not_kernel_sensor(self):
        self.assertIn("application-level pointer instrumentation",(R/"04_MEASUREMENT_CATALOG.csv").read_text())

    def test_14_no_root_or_network(self):
        src=(R/"src/f1.c").read_text()
        self.assertNotIn("socket(",src)
        self.assertNotIn("setuid",src)
        self.assertIn("uid=1004",(R/"03_SENSOR_AND_ORACLE_MANIFEST.md").read_text())

    def test_15_random_copy_counterexample_is_synthetic(self):
        rng=random.Random(20261009)
        for _ in range(100):
            payload=bytes(rng.randrange(256) for _ in range(16))
            copied=bytes(bytearray(payload))
            self.assertEqual(copied,payload)
            # A copied buffer has different provenance location despite equal value.
            self.assertIsNot(copied,payload)

    def test_16_trivial_field_addition_trigger(self):
        fixed=next(x for x in self.results if x["strategy"]=="FIXED_RULE_VALUE_LINEAGE")
        all_fields=next(x for x in self.results if x["strategy"]=="COLLECT_ALL_VALIDATED_FEASIBLE")
        self.assertEqual(fixed["correct_coverage"],all_fields["correct_coverage"])
        self.assertEqual(fixed["wrong_determinate"],all_fields["wrong_determinate"])


if __name__=="__main__":unittest.main()
