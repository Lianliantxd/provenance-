"""Bounded, reference-separated audit of two existing provenance cases."""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import sys
import tarfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT.parent
WORK = PILOT.parent
CADETS_CSV = PILOT / "results/cadets_20180412_q1/events.csv"
CADETS_POOL = PILOT / "comparison_v1/outputs/frozen_pool.json"
CADETS_CFG = PILOT / "comparison_v1/configs/comparison.json"
CADETS_REF = PILOT / "comparison_v1/evaluation_refs/reference_events.csv"
WS12 = Path("/Users/tianxd/Downloads/SimulatedWS12/hw20/anomaly.json")
WS12_REF = WORK / "APT_Root_Phase3_5/CASE_NODLINK_WS12/official_annotation_excerpt.txt"
CADETS_REPORT = WORK / "APT_Root_FirstCase_Audit/reports/cadets_20180412_report_excerpt.txt"
RECV = "21944BC3-1FFB-59C4-8B2E-18AC7F2020CE"
SHELL = "E1EEC283-AA82-52C9-9677-498A5B9BE13B"
LOADER = "EBFB7595-F532-54F8-B51B-CE074AAAFE37"
WS_OFFSETS = {"cmd_a2": 1590222, "certutil": 1809315, "cmd_start": 15345869, "agent": 15375641}
EVIDENCE_FIELDS = "case_id relation_id unit_type poi_id source_event_id target_event_id subject_instance object_instance operation timestamp_start timestamp_end raw_archive raw_member raw_offset_or_line raw_hash reference_document reference_location reference_claim relation_direction_and_semantics observed_operation_status model_dependency_status attack_relation_reference_status uncertainty_class is_input_poi_anchor is_evaluable_as_event_reference is_evaluable_as_dependency_reference exclusion_reason verified_this_run".split()
RESULT_FIELDS = "case_id episode_id query_id method implementation_identity input_hash candidate_pool_hash reference_version poi_count evaluable_reference_events evaluable_reference_pairs known_event_recovered_correct_poi known_relation_supported_correct_poi path_time_status identity_uncertainty missing_relation_or_step_ids budget_feasibility expanded_events output_raw_events output_auxiliary_edges raw_refs_checked raw_refs_matched runtime memory_if_measured run_status output_budget candidate_count selected_path_count notes".split()
FAIL_FIELDS = "case_id query_id method relation_id classification raw_present graph_present candidate_present output_present correct_poi_path budget_feasible independent_reference simple_rule_avoids stage explanation".split()


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    if not rows:
        raise ValueError(f"refuse empty table: {path}")
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def load_ws_scope() -> list[dict]:
    """Freeze all starts and agent.exe file operations in a report-defined interval."""
    rows = []
    with WS12.open("rb") as f:
        while raw := f.readline():
            offset = f.tell() - len(raw)
            try:
                x = json.loads(raw)
                t = float(x.get("MSec", -1))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
            if not 117000 <= t <= 145000:
                continue
            op = x.get("EventName", "")
            if op != "Process/Start" and not (op in {"FileIO/Write", "FileIO/Read", "Image/Load"} and x.get("FileName", "").lower().endswith("agent.exe")):
                continue
            rows.append({"id": f"ws12@{offset}", "offset": offset, "line": None, "hash": hashlib.sha256(raw).hexdigest(), "time": t, "op": op, "pid": x.get("PID", ""), "parent_pid": x.get("ParentID", ""), "process_key": x.get("UniqueProcessKey", ""), "process_name": x.get("PName", ""), "file": x.get("FileName", ""), "command": x.get("CommandLine", "")})
    return sorted(rows, key=lambda x: (x["time"], x["id"]))


def freeze() -> dict:
    for path in (CADETS_CSV, CADETS_POOL, CADETS_CFG, CADETS_REF, WS12, WS12_REF, CADETS_REPORT):
        if not path.is_file():
            raise FileNotFoundError(path)
    cadets_cfg = json.loads(CADETS_CFG.read_text())
    cadets_archive = Path(read_csv(CADETS_CSV)[0]["raw_archive"])
    ws_rows = load_ws_scope()
    (ROOT / "outputs").mkdir(exist_ok=True)
    (ROOT / "outputs/ws12_scope.json").write_text(json.dumps(ws_rows, indent=2) + "\n")
    cases = [
        {"case_id": "CADETS_20180412", "attack_episode_id": "E3_CADETS_APR12", "campaign_relation": "04-13 same campaign, excluded as independent test", "case_role": "DEVELOPMENT", "host": cadets_cfg["host_id"], "sensor": "CADETS CDM18", "source_files": [str(cadets_archive), str(CADETS_CSV)], "file_hashes": {str(p): sha(p) for p in (cadets_archive, CADETS_CSV, CADETS_POOL, CADETS_REF)}, "time_window_utc": [cadets_cfg["scope_start_utc"], cadets_cfg["scope_end_utc"]], "coverage_gaps": ["10-second local extract, not full attack", "equal timestamps lack a trusted ordering rule", "process-internal information flow unobserved"], "parser_version": sha(PILOT / "src/event_io.py"), "graph_version": sha(PILOT / "src/trace.py"), "poi_ids": [LOADER, SHELL], "poi_anchor_events": [LOADER, SHELL], "reference_documents": [str(CADETS_REPORT), str(CADETS_REF)], "selection_reason": "existing report-mapped development case; selected before this run", "excluded_periods": ["2018-04-13 as independent episode"]},
        {"case_id": "NODLINK_WS12", "attack_episode_id": "NODLINK_SIMULATED_WS12", "campaign_relation": "independent simulated execution from CADETS", "case_role": "DEVELOPMENT_PRIORLY_INSPECTED", "host": "192.168.0.95", "sensor": "Windows ETW-derived JSON anomaly channel", "source_files": [str(WS12)], "file_hashes": {str(p): sha(p) for p in (WS12, WS12_REF, ROOT / "outputs/ws12_scope.json")}, "time_window_utc": "NA:ETW MSec relative time; absolute clock origin inferred, not verified", "time_window_msec": [117000, 145000], "coverage_gaps": ["only anomaly.json present; no benign/background channel", "initial intrusion precedes selected interval", "file contents and versions unavailable", "UniqueProcessKey alone reused across different PIDs"], "parser_version": sha(Path(__file__)), "graph_version": sha(Path(__file__)), "poi_ids": ["ws12@15375641", "ws12@1809315"], "poi_anchor_events": ["ws12@15375641", "ws12@1809315"], "reference_documents": [str(WS12_REF)], "selection_reason": "independent published execution with raw Process/Start and file operations; selected by data/reference availability, not method outcome", "excluded_periods": ["outside bounded A1-A2 interval", "other attack episodes"]},
    ]
    out = {"freeze_time_utc": datetime.now(timezone.utc).isoformat(), "cases": cases, "ws12_scope_count": len(ws_rows), "no_method_output_inspected_this_run_before_freeze": True, "case_b_prior_output_exposure": "Root_Phase3_5 mappings already inspected; not a held-out test"}
    (ROOT / "01_FROZEN_CASES.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    return {"cases": 2, "ws12_scope_events": len(ws_rows), "freeze_sha256": sha(ROOT / "01_FROZEN_CASES.json")}


def verify_cadets(e: dict) -> bool:
    with tarfile.open(e["raw_archive"], "r:gz") as tar:
        with tar.extractfile(e["raw_member"]) as stream:
            stream.seek(int(e["raw_uncompressed_offset"]))
            raw = stream.readline()
    if hashlib.sha256(raw).hexdigest() != e["raw_record_hash"]:
        return False
    x = next(iter(json.loads(raw)["datum"].values()))
    return x.get("uuid") == e["native_event_id"]


def verify_cadets_batch(events: list[dict]) -> dict[str, bool]:
    """Verify selected output references with one archive/member read."""
    if not events:
        return {}
    archive = events[0]["raw_archive"]
    member = events[0]["raw_member"]
    if any(e["raw_archive"] != archive or e["raw_member"] != member for e in events):
        raise ValueError("mixed CADETS archive members in batch")
    checks = {}
    with tarfile.open(archive, "r:gz") as tar:
        with tar.extractfile(member) as stream:
            for e in sorted(events, key=lambda x: int(x["raw_uncompressed_offset"])):
                stream.seek(int(e["raw_uncompressed_offset"]))
                raw = stream.readline()
                try:
                    x = next(iter(json.loads(raw)["datum"].values()))
                    checks[e["native_event_id"]] = hashlib.sha256(raw).hexdigest() == e["raw_record_hash"] and x.get("uuid") == e["native_event_id"]
                except (ValueError, KeyError, StopIteration):
                    checks[e["native_event_id"]] = False
    return checks


def verify_ws(e: dict) -> bool:
    with WS12.open("rb") as f:
        f.seek(e["offset"])
        raw = f.readline()
    return hashlib.sha256(raw).hexdigest() == e["hash"] and float(json.loads(raw)["MSec"]) == e["time"]


def evidence_row(case: str, rid: str, unit: str, poi: str, src: str, dst: str, operation: str, ts: str, raw: dict | None, ref: str, location: str, claim: str, status: str, model: str, attack: str, uncertainty: str, anchor: bool = False, event_ref: bool = False, dep_ref: bool = False, exclusion: str = "", verified: bool = False) -> dict:
    start, end = ts.split(" -> ", 1) if " -> " in ts else (ts, ts)
    return dict(zip(EVIDENCE_FIELDS, [case, rid, unit, poi, src, dst, raw.get("subject_id", raw.get("pid", "")) if raw else "", raw.get("object_id", raw.get("file", "")) if raw else "", operation, start, end, raw.get("raw_archive", str(WS12)) if raw else "", raw.get("raw_member", "") if raw else "", raw.get("raw_uncompressed_offset", raw.get("offset", "")) if raw else "", raw.get("raw_record_hash", raw.get("hash", "")) if raw else "", ref, location, claim, f"{src} -> {dst}; {unit}", status, model, attack, uncertainty, anchor, event_ref, dep_ref, exclusion, verified]))


def build_evidence(cad: dict[str, dict], ws: dict[str, dict]) -> tuple[list[dict], dict]:
    rows = []
    checks = {}
    for event_id, poi, location, role in [(RECV, LOADER, "E3 report §3.13, pp.26-28", "report-associated inbound receive"), (SHELL, SHELL, "E3 report §3.13, pp.26-28", "shellcode-address connection"), (LOADER, LOADER, "E3 report §3.13, pp.26-28", "loader-address connection")]:
        e = cad[event_id]
        ok = verify_cadets(e)
        checks[event_id] = ok
        rows.append(evidence_row("CADETS_20180412", f"C_EVENT_{event_id[:8]}", "EVENT", poi, event_id, "", e["original_operation"], e["event_time_normalized"], e, str(CADETS_REPORT), location, role, "OBSERVED_OPERATION", "NA", "REPORT_MAPPED_EVENT", "SAME_TIMESTAMP_ORDER_UNVERIFIED" if event_id != LOADER else "PROCESS_INTERNAL_FLOW_UNKNOWN", event_id == poi, event_id == RECV, False, "POI anchor" if event_id == poi else "", ok))
    for rid, a, b, unc, event_ref, reason in [("C_RECV_TO_LOADER", RECV, LOADER, "COARSE_PROCESS_DEPENDENCY", True, "report supports episode ordering, not per-event payload transfer"), ("C_RECV_TO_SHELL", RECV, SHELL, "ORDER_UNRESOLVED", False, "same CDM timestamp"), ("C_SHELL_TO_LOADER", SHELL, LOADER, "ALTERNATIVE_BRANCH", False, "separate network output; no transfer evidence")]:
        rows.append(evidence_row("CADETS_20180412", rid, "DEPENDENCY_PAIR", b, a, b, "shared nginx subject", cad[a]["event_time_normalized"] + " -> " + cad[b]["event_time_normalized"], cad[a], str(CADETS_REPORT), "§3.13 pp.26-28", reason, "TWO_OPERATIONS_VERIFIED", "MODEL_POSSIBLE_DEPENDENCY", "REPORT_SUPPORTS_STEPS_NOT_EXACT_PAIR", unc, False, event_ref, False, "no independent event-pair information-flow GT", checks[a] and checks[b]))
    for label, offset in WS_OFFSETS.items():
        e = ws[f"ws12@{offset}"]
        ok = verify_ws(e)
        checks[e["id"]] = ok
        rows.append(evidence_row("NODLINK_WS12", f"W_EVENT_{label}", "EVENT", "ws12@15375641", e["id"], "", e["op"], str(e["time"]) + " MSec", e, str(WS12_REF), "A2", "published A2 command/action mapping; exact absolute time not verified", "OBSERVED_OPERATION", "NA", "REPORT_MAPPED_STEP", "RELATIVE_TIME_ONLY", label in {"certutil", "agent"}, label in {"cmd_a2", "cmd_start"}, False, "POI anchor" if label in {"certutil", "agent"} else "", ok))
    writes = [x for x in ws.values() if x["op"] == "FileIO/Write" and x["pid"] == "3268" and x["file"].lower().endswith("agent.exe")]
    reads = [x for x in ws.values() if x["op"] == "FileIO/Read" and x["pid"] == "4360" and x["file"].lower().endswith("agent.exe")]
    for label, events in [("write", writes), ("read", reads)]:
        for e in events:
            ok = verify_ws(e)
            checks[e["id"]] = ok
            rows.append(evidence_row("NODLINK_WS12", f"W_EVENT_{label}_{e['offset']}", "OPERATION_EDGE", "ws12@15375641", e["id"], "", e["op"], str(e["time"]) + " MSec", e, str(WS12_REF), "A2", "same file path named in command; content/version not recorded", "OBSERVED_OPERATION", "DIRECTLY_RECORDED_RELATION:process-to-file", "REPORT_SUPPORTS_STEP_ONLY", "FILE_VERSION_UNKNOWN", False, True, False, "", ok))
    cmd, cert, launch, agent = [ws[f"ws12@{WS_OFFSETS[k]}"] for k in ("cmd_a2", "certutil", "cmd_start", "agent")]
    for rid, a, b, model, attack, unc, dep_eval in [("W_CMD_CERT_PARENT", cmd, cert, "DIRECTLY_RECORDED_RELATION:ParentID", "REPORT_SUPPORTS_A2_SEQUENCE", "PARENT_PID_INSTANCE_RESOLVED_IN_WINDOW", True), ("W_LAUNCH_AGENT_PARENT", launch, agent, "DIRECTLY_RECORDED_RELATION:ParentID", "REPORT_SUPPORTS_A2_SEQUENCE", "PARENT_PID_INSTANCE_RESOLVED_IN_WINDOW", True)]:
        rows.append(evidence_row("NODLINK_WS12", rid, "DEPENDENCY_PAIR", b["id"], a["id"], b["id"], "Process/Start parent-child", f"{a['time']} -> {b['time']} MSec", b, str(WS12_REF), "A2", "ParentID directly records PID link; unique instance checked in bounded window", "OBSERVED_OPERATION", model, attack, unc, False, True, dep_eval, "direct parent relation only; no broader attack causal chain", checks[a["id"]] and checks[b["id"]]))
    if writes and reads:
        a, b = writes[-1], reads[0]
        rows.append(evidence_row("NODLINK_WS12", "W_WRITE_READ_FILE", "DEPENDENCY_PAIR", agent["id"], a["id"], b["id"], "same path write then read", f"{a['time']} -> {b['time']} MSec", b, str(WS12_REF), "A2", "A2 has download/launch command; bytes and file version not recorded", "TWO_OPERATIONS_VERIFIED", "MODEL_POSSIBLE_DEPENDENCY", "REPORT_SUPPORTS_STEP_ONLY", "FILE_VERSION_UNKNOWN", False, True, False, "not exact byte-flow GT", checks[a["id"]] and checks[b["id"]]))
    return rows, {"raw_refs_checked": len(checks), "raw_refs_matched": sum(checks.values()), "write_events": len(writes), "read_events": len(reads)}


def cadets_paths(pool: dict, poi: str) -> list[list[str]]:
    return [p for p in pool["searches"][poi]["paths"] if len(p) > 1]


def ws_edges(rows: list[dict]) -> list[tuple[str, str, str]]:
    starts = [r for r in rows if r["op"] == "Process/Start"]
    starts_by_pid = defaultdict(list)
    for r in starts:
        starts_by_pid[r["pid"]].append(r)
    edges = []
    for child in starts:
        parents = [p for p in starts_by_pid[child["parent_pid"]] if p["time"] < child["time"]]
        if parents:
            parent = max(parents, key=lambda x: x["time"])
            edges.append((parent["id"], child["id"], "PARENT_PID"))
    for op in rows:
        if op["op"] == "Process/Start":
            continue
        own = [p for p in starts_by_pid[op["pid"]] if p["time"] <= op["time"]]
        if own:
            edges.append((max(own, key=lambda x: x["time"])["id"], op["id"], "PROCESS_OPERATION"))
    writes = [r for r in rows if r["op"] == "FileIO/Write"]
    reads = [r for r in rows if r["op"] == "FileIO/Read"]
    for w in writes:
        for r in reads:
            if w["file"].lower() == r["file"].lower() and w["time"] < r["time"]:
                edges.append((w["id"], r["id"], "SAME_FILE_PATH_POSSIBLE"))
    for r in reads:
        later = [s for s in starts_by_pid[r["pid"]] if s["time"] < r["time"]]
        if later:
            for child in starts:
                if child["parent_pid"] == r["pid"] and child["time"] > r["time"]:
                    edges.append((r["id"], child["id"], "SAME_PROCESS_POSSIBLE"))
    return sorted(set(edges))


def backward_paths(poi: str, edges: list[tuple[str, str, str]], limit: int = 3) -> tuple[set[str], list[list[str]]]:
    incoming = defaultdict(list)
    for a, b, _ in edges:
        incoming[b].append(a)
    seen = {poi}
    stack = [[poi]]
    paths = []
    while stack and len(paths) < 1000:
        p = stack.pop()
        parents = [x for x in incoming[p[-1]] if x not in p]
        if not parents or len(p) >= 5:
            if len(p) > 1:
                paths.append(p)
        else:
            for a in parents:
                seen.add(a)
                stack.append(p + [a])
    paths.sort(key=lambda p: (len(p), tuple(reversed(p))))
    return seen, paths[:limit]


def select_paths(method: str, paths: dict[str, list[list[str]]], pool: set[str], budget: int) -> tuple[set[str], list[tuple[str, list[str]]], str]:
    if method == "B0":
        return (set(pool), [], "FULL_POOL_EXCEEDS_OUTPUT_BUDGET" if len(pool) > budget else "FEASIBLE")
    rank_limit = 1 if method == "B1-Min" else 3
    chosen = []
    used = set()
    for rank in range(rank_limit):
        for poi in sorted(paths):
            if rank >= len(paths[poi]):
                continue
            p = paths[poi][rank]
            if len(used | set(p)) <= budget:
                chosen.append((poi, p))
                used.update(p)
    options = [p for p in paths.values() if p]
    min_cost = min((len({event for path in combo for event in path}) for combo in itertools.product(*options)), default=0)
    status = "OUTPUT_BUDGET_INFEASIBLE" if min_cost > budget else "FEASIBLE"
    return used, chosen, status


def run() -> dict:
    frozen = json.loads((ROOT / "01_FROZEN_CASES.json").read_text())
    cad_rows = read_csv(CADETS_CSV)
    cad = {r["native_event_id"]: r for r in cad_rows}
    old_pool = json.loads(CADETS_POOL.read_text())
    if old_pool["event_csv_sha256"] != sha(CADETS_CSV):
        raise ValueError("CADETS frozen pool/input mismatch")
    ws_rows = json.loads((ROOT / "outputs/ws12_scope.json").read_text())
    ws = {r["id"]: r for r in ws_rows}
    evidence, checks = build_evidence(cad, ws)
    if checks["raw_refs_checked"] != checks["raw_refs_matched"]:
        raise ValueError("raw event verification failed")
    write_csv(ROOT / "02_EVIDENCE_RELATIONS.csv", evidence, EVIDENCE_FIELDS)
    (ROOT / "outputs/raw_verification.json").write_text(json.dumps(checks, indent=2) + "\n")
    results = []
    failures = []
    selected_outputs: list[tuple[str, set[str]]] = []
    cad_queries = {"Q12_LOADER_CONNECT": [LOADER], "Q12_SHELLCODE_CONNECT": [SHELL], "Q12_TWO_CONNECTIONS": [LOADER, SHELL]}
    ws_edges_all = ws_edges(ws_rows)
    (ROOT / "outputs/ws12_candidate_edges.csv").parent.mkdir(exist_ok=True)
    write_csv(ROOT / "outputs/ws12_candidate_edges.csv", [{"source": a, "target": b, "semantics": s} for a, b, s in ws_edges_all], ["source", "target", "semantics"])
    ws_queries = {"W_CERTUTIL": ["ws12@1809315"], "W_AGENT": ["ws12@15375641"], "W_BOTH": ["ws12@1809315", "ws12@15375641"]}
    for case_id, queries, budgets in [("CADETS_20180412", cad_queries, [2, 8, 200]), ("NODLINK_WS12", ws_queries, [2, 8, 64])]:
        for query_id, pois in queries.items():
            if case_id == "CADETS_20180412":
                pool = set(old_pool["bundles"][query_id]["event_ids"])
                paths = {p: cadets_paths(old_pool, p)[:3] for p in pois}
                input_hash = sha(CADETS_CSV)
                ref_events = {LOADER: {RECV}, SHELL: set()}
                ref_pairs = {}
                events_lookup = cad
                search_truncated = any(old_pool["searches"][p]["search_truncated"] for p in pois)
            else:
                paths = {}
                pool = set()
                for p in pois:
                    found, ps = backward_paths(p, ws_edges_all)
                    pool.update(found)
                    paths[p] = ps
                input_hash = sha(ROOT / "outputs/ws12_scope.json")
                ref_events = {"ws12@1809315": {"ws12@1590222"}, "ws12@15375641": {"ws12@15345869"}}
                ref_pairs = {"ws12@1809315": {("ws12@1590222", "ws12@1809315")}, "ws12@15375641": {("ws12@15345869", "ws12@15375641")}}
                events_lookup = ws
                search_truncated = False
            pool_hash = digest(sorted(pool))
            for budget in budgets:
                for method in ("B0", "B1-Min", "B1-Alternatives"):
                    t0 = time.perf_counter()
                    output, selected, feasible = select_paths(method, paths, pool, budget)
                    elapsed = time.perf_counter() - t0
                    correct = 0
                    pair_hit = 0
                    missing = []
                    for poi in pois:
                        selected_paths = [p for owner, p in selected if owner == poi] if method != "B0" else paths[poi]
                        for ref in ref_events.get(poi, set()):
                            hit = any(ref in p and set(p) <= output for p in selected_paths)
                            correct += int(hit)
                            if not hit:
                                missing.append(ref + "->" + poi)
                                failures.append({"case_id": case_id, "query_id": query_id, "method": method, "relation_id": ref + "->" + poi, "classification": "OUTPUT_BUDGET_INFEASIBLE" if feasible != "FEASIBLE" else ("PATH_SELECTION_MISS_WITH_FEASIBLE_POOL" if ref in pool else "CANDIDATE_SEARCH_MISS"), "raw_present": ref in events_lookup, "graph_present": ref in events_lookup, "candidate_present": ref in pool, "output_present": ref in output, "correct_poi_path": False, "budget_feasible": feasible == "FEASIBLE", "independent_reference": "event/step only; no exact dependency GT", "simple_rule_avoids": "no path can fit this output budget" if feasible != "FEASIBLE" else ("retain alternatives" if method == "B1-Min" else "unknown"), "stage": "selection/display" if ref in pool else "search", "explanation": "Reference event absent from a complete correct-POI output path; not an independently validated information-flow pair."})
                        for pair in ref_pairs.get(poi, set()):
                            pair_hit += int(any(pair[0] in p and pair[1] in p and set(p) <= output for p in selected_paths))
                    selected_ids = sorted(output)
                    selected_outputs.append((case_id, set(output)))
                    out_path = ROOT / "outputs" / case_id / query_id / method / str(budget)
                    out_path.mkdir(parents=True, exist_ok=True)
                    (out_path / "selected_paths.json").write_text(json.dumps({"paths": [{"poi": p, "event_ids": e} for p, e in selected], "event_ids": selected_ids, "pool_hash": pool_hash}, indent=2) + "\n")
                    ts = "ORDER_UNRESOLVED_OR_COARSE" if case_id == "CADETS_20180412" else "RELATIVE_TIME_ORDER_ONLY"
                    results.append({"case_id": case_id, "episode_id": frozen["cases"][0 if case_id == "CADETS_20180412" else 1]["attack_episode_id"], "query_id": query_id, "method": method, "implementation_identity": "OWN_TRANSPARENT_FROZEN_POOL" if case_id == "CADETS_20180412" else "OWN_TRANSPARENT_ANOMALY_ONLY_ADAPTER", "input_hash": input_hash, "candidate_pool_hash": pool_hash, "reference_version": sha(CADETS_REF if case_id == "CADETS_20180412" else WS12_REF), "poi_count": len(pois), "evaluable_reference_events": sum(len(ref_events.get(p, set())) for p in pois), "evaluable_reference_pairs": sum(len(ref_pairs.get(p, set())) for p in pois), "known_event_recovered_correct_poi": correct, "known_relation_supported_correct_poi": pair_hit if ref_pairs else "NA:NO_INDEPENDENT_PAIR_GT", "path_time_status": ts, "identity_uncertainty": "CDM subject UUID stable, lifecycle unknown" if case_id == "CADETS_20180412" else "PID start constrained; UniqueProcessKey reuse observed", "missing_relation_or_step_ids": ";".join(missing), "budget_feasibility": feasible, "expanded_events": len(pool), "output_raw_events": len(output), "output_auxiliary_edges": 0, "raw_refs_checked": 0, "raw_refs_matched": 0, "runtime": elapsed, "memory_if_measured": "NA:not_measured", "run_status": "COMPLETED_WITH_SCOPE_LIMITS" if method != "B0" or feasible == "FEASIBLE" else "FULL_POOL_OVER_BUDGET", "output_budget": budget, "candidate_count": len(pool), "selected_path_count": len(selected), "notes": "B0 displays full time/direction candidate pool; no ranking" if method == "B0" else "path selection uses no evaluation references"})
    cad_selected = {event for case, events in selected_outputs if case == "CADETS_20180412" for event in events}
    ws_selected = {event for case, events in selected_outputs if case == "NODLINK_WS12" for event in events}
    output_checks = verify_cadets_batch([cad[e] for e in cad_selected])
    output_checks.update({e: verify_ws(ws[e]) for e in ws_selected})
    if not all(output_checks.values()):
        raise ValueError("one or more selected output raw references failed")
    for row, (_, events) in zip(results, selected_outputs):
        row["raw_refs_checked"] = len(events)
        row["raw_refs_matched"] = sum(output_checks[e] for e in events)
    (ROOT / "outputs/output_raw_verification.json").write_text(json.dumps({"unique_output_refs_checked": len(output_checks), "unique_output_refs_matched": sum(output_checks.values()), "cadets_refs": len(cad_selected), "ws12_refs": len(ws_selected)}, indent=2) + "\n")
    write_csv(ROOT / "04_BASELINE_RESULTS.csv", results, RESULT_FIELDS)
    if failures:
        write_csv(ROOT / "05_FAILURE_DIAGNOSIS.csv", failures, FAIL_FIELDS)
    (ROOT / "outputs/run_summary.json").write_text(json.dumps({"result_rows": len(results), "failure_rows": len(failures), "targeted_raw_verification": checks, "output_unique_raw_refs_checked": len(output_checks), "output_unique_raw_refs_matched": sum(output_checks.values()), "ws_candidate_edges": len(ws_edges_all), "run_time_utc": datetime.now(timezone.utc).isoformat()}, indent=2) + "\n")
    return {"result_rows": len(results), "failure_rows": len(failures), "targeted_raw": checks, "output_raw_refs": len(output_checks), "ws_edges": len(ws_edges_all)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["freeze", "run"])
    args = ap.parse_args()
    t = time.perf_counter()
    try:
        result = freeze() if args.phase == "freeze" else run()
        code = 0
        print(json.dumps(result))
    except Exception as exc:
        code = 1
        result = {"error": type(exc).__name__ + ": " + str(exc)}
        print(result, file=sys.stderr)
        raise
    finally:
        (ROOT / "outputs").mkdir(exist_ok=True)
        with (ROOT / "outputs/execution_log.jsonl").open("a") as f:
            f.write(json.dumps({"phase": args.phase, "command": sys.argv, "utc": datetime.now(timezone.utc).isoformat(), "exit_code": code, "duration_seconds": time.perf_counter() - t, "script_sha256": sha(Path(__file__)), "result": result}) + "\n")


if __name__ == "__main__":
    main()
