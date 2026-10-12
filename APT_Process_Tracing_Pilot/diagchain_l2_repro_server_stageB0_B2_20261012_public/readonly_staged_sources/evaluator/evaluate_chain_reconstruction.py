#!/usr/bin/env python3
"""Evaluate structured attack-chain reconstruction predictions.

The MVP evaluator keeps two complementary views:
  1. order-aligned metrics: strict chain-position comparison
  2. best-match metrics: optimally pair predicted and gold steps by evidence,
     ATT&CK mapping, entities, and text similarity

Order alignment is useful for measuring temporal reconstruction. Best matching is
more forgiving when a model recovers the right action but places it at a slightly
different position, or when it outputs fewer/more steps than the gold chain.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from difflib import SequenceMatcher
from itertools import permutations
from pathlib import Path
from typing import Any

try:
    from scipy.optimize import linear_sum_assignment
except Exception:  # noqa: BLE001 - scipy is optional for lightweight use.
    linear_sum_assignment = None

from cluster_metrics import compare_clusterings, prefixed

ROOT = Path(__file__).resolve().parent
BEST_MATCH_THRESHOLD = 0.20
BEST_MATCH_SCORING_VERSION = "legacy_anchor_gated_v3_precision_sensitive"
CLUSTERING_METRICS_VERSION = "evidence_cluster_metrics_v1"
CEAF_ALIGNMENT_VERSION = "evidence_ceaf_step_alignment_v1"
SCORECARD_VERSION = "capability_scorecard_v3_agentic_no_labeling"
MAX_EXACT_MATCH_STEPS = 18
UNKNOWN_LABELS = {"", "unknown", "none", "n/a", "na", "null"}
BACKGROUND_CLUSTER = "__background__"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize(s: Any) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())


def tokens(s: Any) -> list[str]:
    return [tok for tok in re.split(r"[^a-z0-9._/-]+", normalize(s)) if tok]


def token_f1(pred: Any, gold: Any) -> float:
    p = tokens(pred)
    g = tokens(gold)
    if not p and not g:
        return 1.0
    if not p or not g:
        return 0.0
    cp = Counter(p)
    cg = Counter(g)
    common = sum((cp & cg).values())
    if common == 0:
        return 0.0
    precision = common / len(p)
    recall = common / len(g)
    return 2 * precision * recall / (precision + recall)


def token_jaccard(pred: Any, gold: Any) -> float:
    p = set(tokens(pred))
    g = set(tokens(gold))
    if not p and not g:
        return 1.0
    if not p or not g:
        return 0.0
    return len(p & g) / len(p | g)


def action_text(step: dict[str, Any]) -> str:
    return " ".join(
        str(step.get(key) or "")
        for key in ["attack_step", "step_description"]
    )


def action_text_similarity(pred: dict[str, Any], gold: dict[str, Any]) -> float:
    pred_text = action_text(pred)
    gold_text = action_text(gold)
    if not normalize(pred_text) and not normalize(gold_text):
        return 1.0
    if not normalize(pred_text) or not normalize(gold_text):
        return 0.0
    f1 = token_f1(pred_text, gold_text)
    jaccard = token_jaccard(pred_text, gold_text)
    seq = SequenceMatcher(None, normalize(pred_text), normalize(gold_text)).ratio()
    return 0.55 * f1 + 0.25 * jaccard + 0.20 * seq


def set_f1(pred: set[str], gold: set[str]) -> tuple[float, float, float]:
    if not pred and not gold:
        return 1.0, 1.0, 1.0
    if not pred:
        return 0.0, 0.0, 0.0
    if not gold:
        return 0.0, 0.0, 0.0
    common = len(pred & gold)
    precision = common / len(pred)
    recall = common / len(gold)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return precision, recall, f1


def known_label(value: Any) -> bool:
    return normalize(value) not in UNKNOWN_LABELS


def exact_label_match(pred: Any, gold: Any) -> float:
    return 1.0 if normalize(pred) == normalize(gold) else 0.0


def known_only_label_match(pred: Any, gold: Any) -> float:
    if not known_label(pred) or not known_label(gold):
        return 0.0
    return exact_label_match(pred, gold)


def canonical_entity_key(key: Any) -> str:
    norm = normalize(key).replace("-", "_")
    mapping = {
        "account": "accounts",
        "accounts": "accounts",
        "user": "accounts",
        "users": "accounts",
        "host": "hosts",
        "hosts": "hosts",
        "hostname": "hosts",
        "device": "hosts",
        "devices": "hosts",
        "ip": "ips",
        "ips": "ips",
        "ip_address": "ips",
        "process": "processes",
        "processes": "processes",
        "proc": "processes",
        "file": "files",
        "files": "files",
        "path": "files",
        "paths": "files",
        "url": "urls",
        "urls": "urls",
        "endpoint": "urls",
        "endpoints": "urls",
        "service": "services",
        "services": "services",
        "syscall": "syscalls",
        "syscalls": "syscalls",
    }
    return mapping.get(norm, norm)


def entity_slots(step: dict[str, Any]) -> dict[str, set[str]]:
    entities = step.get("entities") or {}
    out: dict[str, set[str]] = {}
    if not isinstance(entities, dict):
        return out
    for key, value in entities.items():
        slot = canonical_entity_key(key)
        values = value if isinstance(value, list) else [value]
        for item in values:
            item_norm = normalize(item)
            if item_norm:
                out.setdefault(slot, set()).add(item_norm)
    return out


def flatten_entities(step: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for values in entity_slots(step).values():
        out.update(values)
    return out


def entity_slot_f1(pred: dict[str, Any], gold: dict[str, Any]) -> tuple[float, float, float]:
    pred_slots = entity_slots(pred)
    gold_slots = entity_slots(gold)
    pred_flat = {f"{slot}:{value}" for slot, values in pred_slots.items() for value in values}
    gold_flat = {f"{slot}:{value}" for slot, values in gold_slots.items() for value in values}
    return set_f1(pred_flat, gold_flat)


def canonical_evidence_ids(step: dict[str, Any]) -> list[str]:
    raw = step.get("supporting_evidence", step.get("evidence", []))
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    ids = []
    for item in raw:
        if isinstance(item, dict):
            val = item.get("evidence_id") or item.get("id") or item.get("record_id")
        else:
            val = item
        if val:
            ids.append(str(val))
    return ids


def evidence_card_index(incident_input: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not incident_input:
        return {}
    return {
        str(card.get("evidence_id")): card
        for card in incident_input.get("evidence_cards", [])
        if card.get("evidence_id") is not None
    }


def parse_card_content(card: dict[str, Any]) -> dict[str, Any]:
    content = card.get("content")
    if not isinstance(content, str):
        return {}
    try:
        parsed = json.loads(content)
    except Exception:  # noqa: BLE001 - cards may contain free-form text.
        return {}
    return parsed if isinstance(parsed, dict) else {}


def card_visible_anchors(card: dict[str, Any]) -> set[str]:
    anchors: set[str] = set()
    parsed = parse_card_content(card)
    for key in ["visible_anchor", "alert_node_id", "alert_id", "node_id"]:
        value = parsed.get(key) or card.get(key)
        if value is not None and normalize(value):
            anchors.add(f"{key}:{normalize(value)}")
    origin = str(card.get("origin") or "")
    node_match = re.search(r"#node=([^#\s]+)", origin)
    if node_match:
        anchors.add(f"alert_node_id:{normalize(node_match.group(1))}")
    return anchors


def step_visible_anchors(step: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> set[str]:
    anchors: set[str] = set()
    for key in ["visible_anchor", "source_alert_node_id", "source_step_id", "alert_node_id"]:
        value = step.get(key)
        if value is not None and normalize(value):
            anchors.add(f"{key}:{normalize(value)}")
    metadata = step.get("metadata") if isinstance(step.get("metadata"), dict) else {}
    for key in ["visible_anchor", "source_alert_node_id", "alert_node_id"]:
        value = metadata.get(key)
        if value is not None and normalize(value):
            anchors.add(f"{key}:{normalize(value)}")
    for eid in canonical_evidence_ids(step):
        card = evidence_by_id.get(str(eid))
        if card:
            anchors.update(card_visible_anchors(card))
    return anchors


def step_context(step: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]], known_evidence_ids: set[str]) -> dict[str, Any]:
    ev_ids = set(canonical_evidence_ids(step))
    slots = entity_slots(step)
    return {
        "evidence_ids": ev_ids,
        "known_evidence_ids": ev_ids & known_evidence_ids if known_evidence_ids else ev_ids,
        "unknown_evidence_ids": ev_ids - known_evidence_ids if known_evidence_ids else set(),
        "anchors": step_visible_anchors(step, evidence_by_id),
        "entity_slots": slots,
        "entities_flat": {value for values in slots.values() for value in values},
        "hosts": slots.get("hosts", set()),
        "action_text": action_text(step),
    }


def selected_evidence_ids(prediction: dict[str, Any]) -> set[str]:
    metadata = prediction.get("metadata") if isinstance(prediction.get("metadata"), dict) else {}
    retrieval_note = metadata.get("retrieval_note") if isinstance(metadata.get("retrieval_note"), dict) else {}
    selected = retrieval_note.get("selected_evidence_ids") or retrieval_note.get("selected_ids") or []
    if not isinstance(selected, list):
        return set()
    return {str(item) for item in selected if item}


def sorted_steps(chain_obj: dict[str, Any]) -> list[dict[str, Any]]:
    steps = chain_obj.get("attack_chain", chain_obj.get("selected_steps", []))
    return sorted(steps, key=lambda s: (s.get("order", s.get("temporal_order", 10**9)), str(s.get("step_id", ""))))


def load_prediction(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = load_json(path)
    except Exception as exc:  # noqa: BLE001 - report parse failure as metric
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "Prediction root is not a JSON object."
    return data, None


def validate_prediction_schema(prediction: dict[str, Any]) -> list[str]:
    """Lightweight schema check for model outputs.

    This intentionally avoids a runtime jsonschema dependency. It separates
    syntactically valid JSON from outputs that are not attack-chain answers.
    """
    errors: list[str] = []
    root_required = ["incident_summary", "attack_chain", "causal_edges"]
    for key in root_required:
        if key not in prediction:
            errors.append(f"missing root field: {key}")
    if "incident_summary" in prediction and not isinstance(prediction.get("incident_summary"), str):
        errors.append("incident_summary must be a string")
    if "attack_chain" in prediction and not isinstance(prediction.get("attack_chain"), list):
        errors.append("attack_chain must be a list")
    if "causal_edges" in prediction and not isinstance(prediction.get("causal_edges"), list):
        errors.append("causal_edges must be a list")

    step_required = [
        "step_id",
        "order",
        "attack_step",
        "step_description",
        "tactic",
        "technique_id",
        "technique_name",
        "entities",
        "supporting_evidence",
        "confidence",
    ]
    confidence_values = {"low", "medium", "high"}
    for idx, step in enumerate(prediction.get("attack_chain", []) or []):
        prefix = f"attack_chain[{idx}]"
        if not isinstance(step, dict):
            errors.append(f"{prefix} must be an object")
            continue
        for key in step_required:
            if key not in step:
                errors.append(f"{prefix} missing field: {key}")
        if "order" in step and not isinstance(step.get("order"), int):
            errors.append(f"{prefix}.order must be an integer")
        for key in ["step_id", "attack_step", "step_description", "tactic", "technique_id", "technique_name"]:
            if key in step and not isinstance(step.get(key), str):
                errors.append(f"{prefix}.{key} must be a string")
        if "entities" in step and not isinstance(step.get("entities"), dict):
            errors.append(f"{prefix}.entities must be an object")
        evidence = step.get("supporting_evidence")
        if "supporting_evidence" in step and (
            not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence)
        ):
            errors.append(f"{prefix}.supporting_evidence must be a list of strings")
        if "confidence" in step and step.get("confidence") not in confidence_values:
            errors.append(f"{prefix}.confidence must be one of low|medium|high")

    edge_required = ["source", "target", "relation", "supporting_evidence"]
    for idx, edge in enumerate(prediction.get("causal_edges", []) or []):
        prefix = f"causal_edges[{idx}]"
        if not isinstance(edge, dict):
            errors.append(f"{prefix} must be an object")
            continue
        for key in edge_required:
            if key not in edge:
                errors.append(f"{prefix} missing field: {key}")
        for key in ["source", "target", "relation"]:
            if key in edge and not isinstance(edge.get(key), str):
                errors.append(f"{prefix}.{key} must be a string")
        evidence = edge.get("supporting_evidence")
        if "supporting_evidence" in edge and (
            not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence)
        ):
            errors.append(f"{prefix}.supporting_evidence must be a list of strings")
    return errors


def edge_positions(edges: list[dict[str, Any]], steps: list[dict[str, Any]]) -> set[tuple[int, int]]:
    id_to_pos = {str(step.get("step_id")): idx for idx, step in enumerate(steps)}
    out: set[tuple[int, int]] = set()
    for edge in edges or []:
        src = str(edge.get("source", ""))
        dst = str(edge.get("target", ""))
        if src in id_to_pos and dst in id_to_pos:
            out.add((id_to_pos[src], id_to_pos[dst]))
    return out


def step_pair_features(
    pred: dict[str, Any],
    gold: dict[str, Any],
    pred_ctx: dict[str, Any] | None = None,
    gold_ctx: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pred_ctx = pred_ctx or {}
    gold_ctx = gold_ctx or {}
    pred_ev = set(pred_ctx.get("evidence_ids") or canonical_evidence_ids(pred))
    gold_ev = set(gold_ctx.get("evidence_ids") or canonical_evidence_ids(gold))
    ev_p, ev_r, ev_f = set_f1(pred_ev, gold_ev)
    pred_anchors = set(pred_ctx.get("anchors") or set())
    gold_anchors = set(gold_ctx.get("anchors") or set())
    anchor_p, anchor_r, anchor_f = set_f1(pred_anchors, gold_anchors)
    anchor_signals = []
    if pred_ev or gold_ev:
        anchor_signals.append(ev_f)
    if pred_anchors or gold_anchors:
        anchor_signals.append(anchor_f)
    evidence_anchor_score = sum(anchor_signals) / len(anchor_signals) if anchor_signals else 0.0

    ent_p, ent_r, ent_f = set_f1(flatten_entities(pred), flatten_entities(gold))
    slot_p, slot_r, slot_f = entity_slot_f1(pred, gold)
    title_f = token_f1(pred.get("attack_step"), gold.get("attack_step"))
    desc_f = token_f1(pred.get("step_description"), gold.get("step_description"))
    text_f = (title_f + desc_f) / 2
    action_sim = action_text_similarity(pred, gold)
    technique = exact_label_match(pred.get("technique_id"), gold.get("technique_id"))
    tactic = exact_label_match(pred.get("tactic"), gold.get("tactic"))
    known_technique = known_only_label_match(pred.get("technique_id"), gold.get("technique_id"))
    known_tactic = known_only_label_match(pred.get("tactic"), gold.get("tactic"))

    gate_reasons: list[str] = []
    pred_unknown_only = bool(pred_ev) and not pred_ctx.get("known_evidence_ids", pred_ev)
    if pred_unknown_only:
        gate_reasons.append("predicted_step_uses_only_unknown_evidence")
    if pred_anchors and gold_anchors and not (pred_anchors & gold_anchors) and action_sim < 0.75:
        gate_reasons.append("visible_anchor_conflict")
    pred_hosts = set(pred_ctx.get("hosts") or set())
    gold_hosts = set(gold_ctx.get("hosts") or set())
    if pred_hosts and gold_hosts and not (pred_hosts & gold_hosts) and evidence_anchor_score == 0 and action_sim < 0.75:
        gate_reasons.append("host_conflict_without_evidence_anchor")

    legacy_score = 0.45 * ev_f + 0.20 * ent_f + 0.20 * text_f + 0.10 * technique + 0.05 * tactic
    score = (
        0.50 * evidence_anchor_score
        + 0.20 * slot_f
        + 0.20 * action_sim
        + 0.05 * known_technique
        + 0.05 * known_tactic
    )
    if gate_reasons:
        score = 0.0
    return {
        "score": score,
        "legacy_score": legacy_score,
        "eligible": 0.0 if gate_reasons else 1.0,
        "gate_reasons": gate_reasons,
        "evidence_anchor_score": evidence_anchor_score,
        "evidence_precision": ev_p,
        "evidence_recall": ev_r,
        "evidence_f1": ev_f,
        "anchor_precision": anchor_p,
        "anchor_recall": anchor_r,
        "anchor_f1": anchor_f,
        "entity_precision": ent_p,
        "entity_recall": ent_r,
        "entity_f1": ent_f,
        "entity_slot_precision": slot_p,
        "entity_slot_recall": slot_r,
        "entity_slot_f1": slot_f,
        "title_f1": title_f,
        "description_f1": desc_f,
        "text_f1": text_f,
        "action_text_similarity": action_sim,
        "technique_match": technique,
        "tactic_match": tactic,
        "known_only_technique_match": known_technique,
        "known_only_tactic_match": known_tactic,
    }


def build_match(
    pi: int,
    gi: int,
    pred_steps: list[dict[str, Any]],
    gold_steps: list[dict[str, Any]],
    features: dict[str, Any],
) -> dict[str, Any]:
    return {
        "pred_index": pi,
        "gold_index": gi,
        "pred_step_id": pred_steps[pi].get("step_id"),
        "gold_step_id": gold_steps[gi].get("step_id"),
        "pred_attack_step": pred_steps[pi].get("attack_step"),
        "gold_attack_step": gold_steps[gi].get("attack_step"),
        "pred_tactic": pred_steps[pi].get("tactic"),
        "gold_tactic": gold_steps[gi].get("tactic"),
        "pred_technique_id": pred_steps[pi].get("technique_id"),
        "gold_technique_id": gold_steps[gi].get("technique_id"),
        **features,
    }


def best_step_matching(
    pred_steps: list[dict[str, Any]],
    gold_steps: list[dict[str, Any]],
    incident_input: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str, dict[tuple[int, int], dict[str, Any]]]:
    """Find a maximum-score one-to-one matching with optional skips.

    The v2 scorer is evidence/anchor-first and uses soft task-native
    similarities after hard eligibility gates. Weak pairs are skipped so
    precision/recall reflect missing or extra steps instead of forcing every
    prediction to some gold step.
    """
    if not pred_steps or not gold_steps:
        return [], "empty", {}

    evidence_by_id = evidence_card_index(incident_input)
    known_evidence_ids = set(evidence_by_id)
    pred_contexts = [step_context(step, evidence_by_id, known_evidence_ids) for step in pred_steps]
    gold_contexts = [step_context(step, evidence_by_id, known_evidence_ids) for step in gold_steps]
    pair_features: dict[tuple[int, int], dict[str, Any]] = {}
    for pi, pred in enumerate(pred_steps):
        for gi, gold in enumerate(gold_steps):
            pair_features[(pi, gi)] = step_pair_features(pred, gold, pred_contexts[pi], gold_contexts[gi])

    if linear_sum_assignment is not None:
        n = max(len(pred_steps), len(gold_steps))
        cost = [[0.0 for _ in range(n)] for _ in range(n)]
        for pi in range(len(pred_steps)):
            for gi in range(len(gold_steps)):
                score = pair_features[(pi, gi)]["score"]
                cost[pi][gi] = -score if score >= BEST_MATCH_THRESHOLD else 0.0
        row_ind, col_ind = linear_sum_assignment(cost)
        pairs = [
            (int(pi), int(gi))
            for pi, gi in zip(row_ind, col_ind, strict=False)
            if pi < len(pred_steps)
            and gi < len(gold_steps)
            and pair_features[(int(pi), int(gi))]["score"] >= BEST_MATCH_THRESHOLD
        ]
        matches = [build_match(pi, gi, pred_steps, gold_steps, pair_features[(pi, gi)]) for pi, gi in pairs]
        matches.sort(key=lambda item: item["pred_index"])
        return matches, "hungarian_optional_scipy", pair_features

    if max(len(pred_steps), len(gold_steps)) > MAX_EXACT_MATCH_STEPS:
        # The exact bitmask DP is exponential in the number of gold steps and is
        # only suitable for short MVP chains. ExCyTIn incidents can contain
        # dozens of alert-derived steps, so use a deterministic maximum-score
        # greedy fallback to keep evaluation practical.
        candidates: list[tuple[float, int, int]] = []
        for (pi, gi), features in pair_features.items():
            score = features["score"]
            if score >= BEST_MATCH_THRESHOLD:
                candidates.append((score, pi, gi))
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        used_pred: set[int] = set()
        used_gold: set[int] = set()
        greedy_pairs: list[tuple[int, int]] = []
        for _, pi, gi in candidates:
            if pi in used_pred or gi in used_gold:
                continue
            used_pred.add(pi)
            used_gold.add(gi)
            greedy_pairs.append((pi, gi))

        matches = [build_match(pi, gi, pred_steps, gold_steps, pair_features[(pi, gi)]) for pi, gi in greedy_pairs]
        matches.sort(key=lambda item: item["pred_index"])
        return matches, "greedy_max_score", pair_features

    memo: dict[tuple[int, int], tuple[float, list[tuple[int, int]]]] = {}

    def dp(pi: int, used_mask: int) -> tuple[float, list[tuple[int, int]]]:
        key = (pi, used_mask)
        if key in memo:
            return memo[key]
        if pi >= len(pred_steps):
            return 0.0, []

        best_score, best_pairs = dp(pi + 1, used_mask)
        for gi in range(len(gold_steps)):
            if used_mask & (1 << gi):
                continue
            score = pair_features[(pi, gi)]["score"]
            if score < BEST_MATCH_THRESHOLD:
                continue
            rest_score, rest_pairs = dp(pi + 1, used_mask | (1 << gi))
            candidate_score = score + rest_score
            if candidate_score > best_score:
                best_score = candidate_score
                best_pairs = [(pi, gi), *rest_pairs]

        memo[key] = (best_score, best_pairs)
        return memo[key]

    _, pairs = dp(0, 0)
    matches = [build_match(pi, gi, pred_steps, gold_steps, pair_features[(pi, gi)]) for pi, gi in pairs]
    matches.sort(key=lambda item: item["pred_index"])
    return matches, "exact_bitmask_dp", pair_features


def pairwise_order_accuracy(matches: list[dict[str, Any]]) -> float:
    if len(matches) < 2:
        return 1.0 if matches else 0.0
    total = 0
    correct = 0
    for i in range(len(matches)):
        for j in range(i + 1, len(matches)):
            total += 1
            pred_order = matches[i]["pred_index"] < matches[j]["pred_index"]
            gold_order = matches[i]["gold_index"] < matches[j]["gold_index"]
            if pred_order == gold_order:
                correct += 1
    return correct / total if total else 0.0


def levenshtein_distance(a: list[str], b: list[str]) -> int:
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, aval in enumerate(a, start=1):
        cur = [i]
        for j, bval in enumerate(b, start=1):
            cur.append(
                min(
                    prev[j] + 1,
                    cur[j - 1] + 1,
                    prev[j - 1] + (0 if aval == bval else 1),
                )
            )
        prev = cur
    return prev[-1]


def lcs_length(a: list[int], b: list[int]) -> int:
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    for aval in a:
        cur = [0]
        for j, bval in enumerate(b, start=1):
            cur.append(prev[j - 1] + 1 if aval == bval else max(prev[j], cur[j - 1]))
        prev = cur
    return prev[-1]


def sequence_metrics(matches: list[dict[str, Any]], n_pred: int, n_gold: int) -> dict[str, float]:
    match_by_pred = {int(match["pred_index"]): int(match["gold_index"]) for match in matches}
    pred_sequence = [
        f"G{match_by_pred[pi]}" if pi in match_by_pred else f"P_EXTRA_{pi}"
        for pi in range(n_pred)
    ]
    gold_sequence = [f"G{gi}" for gi in range(n_gold)]
    denom = max(len(pred_sequence), len(gold_sequence))
    edit_distance = levenshtein_distance(pred_sequence, gold_sequence)
    normalized = edit_distance / denom if denom else 0.0
    matched_gold_in_pred_order = [match_by_pred[pi] for pi in range(n_pred) if pi in match_by_pred]
    lcs = lcs_length(matched_gold_in_pred_order, list(range(n_gold)))
    return {
        "chain_edit_distance": float(edit_distance),
        "normalized_chain_edit_distance": normalized,
        "chain_edit_similarity": 1.0 - normalized,
        "lcs_matched_step_count": float(lcs),
        "lcs_step_coverage": lcs / n_gold if n_gold else 1.0,
    }


def matching_diagnostics(
    pair_features: dict[tuple[int, int], dict[str, Any]],
    n_pred: int,
    n_gold: int,
) -> dict[str, float]:
    gate_rejects = 0
    total_pairs = n_pred * n_gold
    for features in pair_features.values():
        if features.get("eligible", 1.0) == 0.0:
            gate_rejects += 1
    return {
        "bestmatch_gate_reject_rate": gate_rejects / total_pairs if total_pairs else 0.0,
        "bestmatch_gate_reject_count": float(gate_rejects),
    }


def evidence_bundle_metrics(pred_steps: list[dict[str, Any]]) -> dict[str, float]:
    bundles = [canonical_evidence_ids(step) for step in pred_steps]
    total_refs = sum(len(bundle) for bundle in bundles)
    unique_refs = len({eid for bundle in bundles for eid in bundle})
    empty_steps = sum(1 for bundle in bundles if not bundle)
    return {
        "mean_evidence_bundle_size": total_refs / len(bundles) if bundles else 0.0,
        "total_evidence_references": float(total_refs),
        "unique_evidence_references": float(unique_refs),
        "evidence_reuse_rate": (total_refs - unique_refs) / total_refs if total_refs else 0.0,
        "empty_evidence_step_rate": empty_steps / len(bundles) if bundles else 1.0,
    }


def steps_to_evidence_clusters(
    steps: list[dict[str, Any]],
    *,
    prefix: str,
    known_evidence_ids: set[str] | None = None,
) -> tuple[dict[str, str], int, int]:
    """Project step evidence citations into a non-overlapping clustering.

    Current GT uses non-overlapping evidence support.  If a prediction cites the
    same evidence in several steps, keep the first assignment and report the
    duplicate count so the ambiguity is visible instead of silently ignored.
    """
    mapping: dict[str, str] = {}
    duplicate_refs = 0
    filtered_unknown_refs = 0
    for idx, step in enumerate(steps):
        raw_step_id = step.get("step_id") or f"step_{idx + 1}"
        cluster_id = f"{prefix}{raw_step_id}"
        for evidence_id in canonical_evidence_ids(step):
            evidence_id = str(evidence_id)
            if known_evidence_ids is not None and evidence_id not in known_evidence_ids:
                filtered_unknown_refs += 1
                continue
            if evidence_id in mapping:
                duplicate_refs += 1
                continue
            mapping[evidence_id] = cluster_id
    return mapping, duplicate_refs, filtered_unknown_refs


def step_evidence_clusters(
    steps: list[dict[str, Any]],
    *,
    prefix: str,
    known_evidence_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    """Return non-overlapping step evidence clusters for CEAF alignment."""
    assigned: set[str] = set()
    clusters: list[dict[str, Any]] = []
    duplicate_refs = 0
    filtered_unknown_refs = 0
    for idx, step in enumerate(steps):
        raw_step_id = step.get("step_id") or f"step_{idx + 1}"
        evidence_ids: list[str] = []
        for evidence_id in canonical_evidence_ids(step):
            evidence_id = str(evidence_id)
            if known_evidence_ids is not None and evidence_id not in known_evidence_ids:
                filtered_unknown_refs += 1
                continue
            if evidence_id in assigned:
                duplicate_refs += 1
                continue
            assigned.add(evidence_id)
            evidence_ids.append(evidence_id)
        if evidence_ids:
            clusters.append(
                {
                    "cluster_id": f"{prefix}{raw_step_id}",
                    "step_id": str(raw_step_id),
                    "step_index": idx,
                    "evidence_ids": set(evidence_ids),
                }
            )
    return clusters, duplicate_refs, filtered_unknown_refs


def max_overlap_assignment(similarity: list[list[int]]) -> tuple[list[tuple[int, int]], str]:
    """Solve CEAF-style max-overlap cluster assignment without a score threshold."""
    n_rows = len(similarity)
    n_cols = len(similarity[0]) if similarity else 0
    if not n_rows or not n_cols:
        return [], "empty"

    if linear_sum_assignment is not None:
        n = max(n_rows, n_cols)
        cost = [[0 for _ in range(n)] for _ in range(n)]
        for i in range(n_rows):
            for j in range(n_cols):
                cost[i][j] = -similarity[i][j]
        row_ind, col_ind = linear_sum_assignment(cost)
        pairs = [
            (int(i), int(j))
            for i, j in zip(row_ind, col_ind, strict=False)
            if int(i) < n_rows and int(j) < n_cols
        ]
        return pairs, "hungarian_optional_scipy_no_threshold"

    if max(n_rows, n_cols) <= 9:
        best_score = -1
        best_pairs: list[tuple[int, int]] = []
        if n_rows <= n_cols:
            for perm in permutations(range(n_cols), n_rows):
                pairs = [(i, perm[i]) for i in range(n_rows)]
                score = sum(similarity[i][j] for i, j in pairs)
                if score > best_score:
                    best_score = score
                    best_pairs = pairs
        else:
            for perm in permutations(range(n_rows), n_cols):
                pairs = [(perm[j], j) for j in range(n_cols)]
                score = sum(similarity[i][j] for i, j in pairs)
                if score > best_score:
                    best_score = score
                    best_pairs = pairs
        return best_pairs, "exact_permutation_no_threshold"

    candidates = [
        (similarity[i][j], i, j)
        for i in range(n_rows)
        for j in range(n_cols)
    ]
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    used_pred: set[int] = set()
    used_gold: set[int] = set()
    pairs: list[tuple[int, int]] = []
    for _, i, j in candidates:
        if i in used_pred or j in used_gold:
            continue
        used_pred.add(i)
        used_gold.add(j)
        pairs.append((i, j))
    return pairs, "greedy_no_threshold_no_scipy"


def ceaf_step_alignment_metrics(
    pred_steps: list[dict[str, Any]],
    gold_steps: list[dict[str, Any]],
    incident_input: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Align predicted/gold steps by CEAF-style evidence-cluster overlap.

    This is the primary alignment used by the capability scorecard.  The legacy
    best-match matcher is still computed separately for appendix comparison.
    """
    evidence_by_id = evidence_card_index(incident_input)
    known_evidence_ids = set(evidence_by_id) if evidence_by_id else None
    pred_clusters, pred_duplicate_refs, pred_unknown_refs = step_evidence_clusters(
        pred_steps,
        prefix="pred:",
        known_evidence_ids=known_evidence_ids,
    )
    gold_clusters, gold_duplicate_refs, gold_unknown_refs = step_evidence_clusters(
        gold_steps,
        prefix="gold:",
        known_evidence_ids=known_evidence_ids,
    )

    similarity = [
        [len(pred["evidence_ids"] & gold["evidence_ids"]) for gold in gold_clusters]
        for pred in pred_clusters
    ]
    assignment, algorithm = max_overlap_assignment(similarity)
    matched_pairs = [
        (pi, gi)
        for pi, gi in assignment
        if similarity and similarity[pi][gi] > 0
    ]

    matches: list[dict[str, Any]] = []
    for pred_cluster_idx, gold_cluster_idx in matched_pairs:
        pred_cluster = pred_clusters[pred_cluster_idx]
        gold_cluster = gold_clusters[gold_cluster_idx]
        pred_step = pred_steps[int(pred_cluster["step_index"])]
        gold_step = gold_steps[int(gold_cluster["step_index"])]
        pred_ev = set(pred_cluster["evidence_ids"])
        gold_ev = set(gold_cluster["evidence_ids"])
        ev_p, ev_r, ev_f = set_f1(pred_ev, gold_ev)
        matches.append(
            {
                "pred_index": int(pred_cluster["step_index"]),
                "gold_index": int(gold_cluster["step_index"]),
                "pred_step_id": pred_step.get("step_id"),
                "gold_step_id": gold_step.get("step_id"),
                "pred_attack_step": pred_step.get("attack_step"),
                "gold_attack_step": gold_step.get("attack_step"),
                "pred_tactic": pred_step.get("tactic"),
                "gold_tactic": gold_step.get("tactic"),
                "pred_technique_id": pred_step.get("technique_id"),
                "gold_technique_id": gold_step.get("technique_id"),
                "evidence_overlap": float(len(pred_ev & gold_ev)),
                "evidence_precision": ev_p,
                "evidence_recall": ev_r,
                "evidence_f1": ev_f,
                "tactic_match": exact_label_match(pred_step.get("tactic"), gold_step.get("tactic")),
                "technique_match": exact_label_match(pred_step.get("technique_id"), gold_step.get("technique_id")),
                "known_only_tactic_match": known_only_label_match(pred_step.get("tactic"), gold_step.get("tactic")),
                "known_only_technique_match": known_only_label_match(
                    pred_step.get("technique_id"),
                    gold_step.get("technique_id"),
                ),
            }
        )
    matches.sort(key=lambda item: item["pred_index"])

    similarity_total = sum(float(match["evidence_overlap"]) for match in matches)
    pred_mentions = sum(len(cluster["evidence_ids"]) for cluster in pred_clusters)
    gold_mentions = sum(len(cluster["evidence_ids"]) for cluster in gold_clusters)
    ceaf_precision = similarity_total / pred_mentions if pred_mentions else (1.0 if not gold_mentions else 0.0)
    ceaf_recall = similarity_total / gold_mentions if gold_mentions else (1.0 if not pred_mentions else 0.0)
    ceaf_f1 = 0.0 if ceaf_precision + ceaf_recall == 0 else 2 * ceaf_precision * ceaf_recall / (ceaf_precision + ceaf_recall)

    step_precision = len(matches) / len(pred_steps) if pred_steps else 0.0
    step_recall = len(matches) / len(gold_steps) if gold_steps else 0.0
    step_f1 = 0.0 if step_precision + step_recall == 0 else 2 * step_precision * step_recall / (step_precision + step_recall)
    known_tech_matches = [
        float(match.get("known_only_technique_match", 0.0))
        for match in matches
        if known_label(match.get("gold_technique_id"))
    ]
    known_tactic_matches = [
        float(match.get("known_only_tactic_match", 0.0))
        for match in matches
        if known_label(match.get("gold_tactic"))
    ]

    metrics: dict[str, Any] = {
        "ceaf_alignment_version": CEAF_ALIGNMENT_VERSION,
        "ceaf_alignment_algorithm": algorithm,
        "ceaf_aligned_steps": float(len(matches)),
        "ceaf_pred_clusters": float(len(pred_clusters)),
        "ceaf_gold_clusters": float(len(gold_clusters)),
        "ceaf_evidence_overlap_total": similarity_total,
        "ceaf_evidence_precision": ceaf_precision,
        "ceaf_evidence_recall": ceaf_recall,
        "ceaf_evidence_f1": ceaf_f1,
        "ceaf_step_precision": step_precision,
        "ceaf_step_recall": step_recall,
        "ceaf_step_f1": step_f1,
        "ceaf_pairwise_order_accuracy": pairwise_order_accuracy(matches),
        "ceaf_tactic_accuracy": avg([float(match["tactic_match"]) for match in matches]),
        "ceaf_technique_accuracy": avg([float(match["technique_match"]) for match in matches]),
        "ceaf_known_only_tactic_accuracy": avg(known_tactic_matches),
        "ceaf_known_only_technique_accuracy": avg(known_tech_matches),
        "ceaf_step_evidence_precision": avg([float(match["evidence_precision"]) for match in matches]),
        "ceaf_step_evidence_recall": avg([float(match["evidence_recall"]) for match in matches]),
        "ceaf_step_evidence_f1": avg([float(match["evidence_f1"]) for match in matches]),
        "ceaf_pred_duplicate_evidence_refs": float(pred_duplicate_refs),
        "ceaf_gold_duplicate_evidence_refs": float(gold_duplicate_refs),
        "ceaf_pred_unknown_refs_filtered": float(pred_unknown_refs),
        "ceaf_gold_unknown_refs_filtered": float(gold_unknown_refs),
    }
    metrics.update({f"ceaf_{key}": value for key, value in sequence_metrics(matches, len(pred_steps), len(gold_steps)).items()})
    return metrics, matches


def granularity_direction_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    precision = metrics.get("attack_clustering_bcubed_precision")
    recall = metrics.get("attack_clustering_bcubed_recall")
    if precision is None or recall is None:
        return {}
    precision = float(precision)
    recall = float(recall)
    merge_gap = max(0.0, recall - precision)
    split_gap = max(0.0, precision - recall)
    return {
        "merge_split_diagnostic_source": "attack_bcubed_precision_recall_direction",
        "granularity_overmerge_gap": merge_gap,
        "granularity_oversplit_gap": split_gap,
        "merge_error_rate": merge_gap,
        "split_error_rate": split_gap,
        "potential_merge_pred_steps": None,
        "potential_split_gold_steps": None,
    }


def fill_background(mapping: dict[str, str], universe_ids: set[str]) -> dict[str, str]:
    return {evidence_id: mapping.get(evidence_id, BACKGROUND_CLUSTER) for evidence_id in universe_ids}


def evidence_clustering_metrics(
    pred_steps: list[dict[str, Any]],
    gold_steps: list[dict[str, Any]],
    incident_input: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence_by_id = evidence_card_index(incident_input)
    input_ids = set(evidence_by_id)
    pred_mapping, pred_duplicate_refs, pred_filtered_unknown_refs = steps_to_evidence_clusters(
        pred_steps,
        prefix="pred:",
        known_evidence_ids=input_ids if input_ids else None,
    )
    gold_mapping, gold_duplicate_refs, gold_filtered_unknown_refs = steps_to_evidence_clusters(
        gold_steps,
        prefix="gold:",
        known_evidence_ids=input_ids if input_ids else None,
    )

    if input_ids:
        full_universe = set(input_ids)
    else:
        full_universe = set(pred_mapping) | set(gold_mapping)
    attack_universe = set(pred_mapping) | set(gold_mapping)

    full_metrics = compare_clusterings(
        fill_background(pred_mapping, full_universe),
        fill_background(gold_mapping, full_universe),
        universe_ids=full_universe,
        pred_missing_label=BACKGROUND_CLUSTER,
        gold_missing_label=BACKGROUND_CLUSTER,
    )
    attack_metrics = compare_clusterings(
        fill_background(pred_mapping, attack_universe),
        fill_background(gold_mapping, attack_universe),
        universe_ids=attack_universe,
        pred_missing_label=BACKGROUND_CLUSTER,
        gold_missing_label=BACKGROUND_CLUSTER,
    )

    metrics: dict[str, Any] = {
        "clustering_metrics_version": CLUSTERING_METRICS_VERSION,
        "clustering_background_policy": "unreferenced_input_cards_share_background_cluster",
        "clustering_pred_duplicate_evidence_refs": float(pred_duplicate_refs),
        "clustering_gold_duplicate_evidence_refs": float(gold_duplicate_refs),
        "clustering_pred_unknown_refs_filtered": float(pred_filtered_unknown_refs),
        "clustering_gold_unknown_refs_filtered": float(gold_filtered_unknown_refs),
        "clustering_attack_universe_items": float(len(attack_universe)),
        "clustering_full_universe_items": float(len(full_universe)),
    }
    metrics.update(prefixed("clustering_", full_metrics))
    metrics.update(prefixed("attack_clustering_", attack_metrics))
    return metrics


def exposure_metrics(
    prediction: dict[str, Any],
    gold_steps: list[dict[str, Any]],
    incident_input: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence_by_id = evidence_card_index(incident_input)
    input_ids = set(evidence_by_id)
    all_gold_ev = {eid for step in gold_steps for eid in canonical_evidence_ids(step)}
    gold_steps_with_evidence = [set(canonical_evidence_ids(step)) for step in gold_steps]

    def ev_recall(candidates: set[str]) -> float | None:
        if not all_gold_ev:
            return None
        return len(candidates & all_gold_ev) / len(all_gold_ev)

    def step_coverage(candidates: set[str]) -> float | None:
        if not gold_steps_with_evidence:
            return None
        covered = sum(1 for evs in gold_steps_with_evidence if evs and (evs & candidates))
        coverable = sum(1 for evs in gold_steps_with_evidence if evs)
        return covered / coverable if coverable else None

    selected = selected_evidence_ids(prediction)
    selected_hits = len(selected & all_gold_ev)
    return {
        "input_gold_evidence_recall": ev_recall(input_ids),
        "input_gold_step_coverage": step_coverage(input_ids),
        "retrieved_evidence_count": float(len(selected)) if selected else None,
        "retrieved_gold_evidence_recall": ev_recall(selected) if selected else None,
        "retrieved_gold_evidence_precision": selected_hits / len(selected) if selected else None,
        "retrieved_step_coverage": step_coverage(selected) if selected else None,
        "retrieved_distractor_rate": 1.0 - (selected_hits / len(selected)) if selected else None,
    }


def attribution_gap_metrics(
    prediction: dict[str, Any],
    gold_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Measure observed-but-unused gold evidence for agentic runs.

    Agentic predictions store the union of evidence observed through retrieval in
    `metadata.retrieval_note.selected_evidence_ids`. The attribution gap is the
    subset of observed gold evidence that was not cited in the final chain.
    Non-agentic predictions generally lack selected evidence metadata, so these
    metrics become empty/zero rather than penalizing the run.
    """
    observed = selected_evidence_ids(prediction)
    gold = {eid for step in gold_steps for eid in canonical_evidence_ids(step)}
    cited = {
        eid
        for step in sorted_steps(prediction)
        for eid in canonical_evidence_ids(step)
    }
    for edge in prediction.get("causal_edges", []):
        if isinstance(edge, dict):
            cited.update(canonical_evidence_ids(edge))
    observed_gold = observed & gold
    cited_observed_gold = cited & observed_gold
    gap_ids = sorted(observed_gold - cited_observed_gold)
    return {
        "agentic_gold_evidence_total": len(gold),
        "agentic_observed_evidence_count": len(observed),
        "agentic_observed_gold_evidence": len(observed_gold),
        "agentic_cited_observed_gold_evidence": len(cited_observed_gold),
        "agentic_attribution_gap_count": len(gap_ids),
        "agentic_retrieved_gold_evidence_recall": (len(observed_gold) / len(gold)) if gold else None,
        "agentic_attribution_gap_rate": (len(gap_ids) / len(observed_gold)) if observed_gold else 0.0,
        "agentic_attribution_gap_evidence_ids": gap_ids,
    }


def avg(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def pick_first(metrics: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = metrics.get(key)
        if value is not None:
            return value
    return None


def metric_subset(metrics: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: metrics.get(key) for key in keys if key in metrics}


def prefixed_metric_subset(metrics: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {key: value for key, value in metrics.items() if key.startswith(prefix)}


def build_scorecard(metrics: dict[str, Any]) -> dict[str, Any]:
    """Build a capability-aligned scorecard from the flat metrics dict.

    This is intentionally a pure regrouping layer: all legacy metrics continue
    to be computed and returned under `metrics` for backward compatibility.
    """
    valid_json = float(metrics.get("valid_json", 0.0) or 0.0)
    schema_valid = float(metrics.get("schema_valid", 0.0) or 0.0)
    retrieval_step_coverage = pick_first(metrics, ["retrieved_step_coverage", "input_gold_step_coverage"])
    retrieval_source = "retrieved_step_coverage" if metrics.get("retrieved_step_coverage") is not None else "input_gold_step_coverage"

    scorecard = {
        "scorecard_version": SCORECARD_VERSION,
        "format_pass": bool(valid_json == 1.0 and schema_valid == 1.0),
        "format_valid_json": metrics.get("valid_json"),
        "format_schema_valid": metrics.get("schema_valid"),
        "retrieval_step_coverage": retrieval_step_coverage,
        "retrieval_source": retrieval_source,
        "grouping_bcubed_f1": metrics.get("attack_clustering_bcubed_f1"),
        "grouping_bcubed_precision": metrics.get("attack_clustering_bcubed_precision"),
        "grouping_bcubed_recall": metrics.get("attack_clustering_bcubed_recall"),
        "ordering_pairwise_accuracy": metrics.get("ceaf_pairwise_order_accuracy"),
        "ordering_alignment_source": "ceaf_evidence_cluster_alignment",
        "grounding_step_evidence_f1": metrics.get("ceaf_step_evidence_f1"),
        "grounding_step_evidence_precision": metrics.get("ceaf_step_evidence_precision"),
        "grounding_step_evidence_recall": metrics.get("ceaf_step_evidence_recall"),
        "grounding_alignment_source": "ceaf_evidence_cluster_alignment",
        "unsupported_step_rate": metrics.get("unsupported_step_rate"),
        "attribution_gap_rate": metrics.get("agentic_attribution_gap_rate"),
        "attribution_gap_count": metrics.get("agentic_attribution_gap_count"),
        "observed_gold_evidence_recall": metrics.get("agentic_retrieved_gold_evidence_recall"),
    }

    diagnostics = {
        "format": metric_subset(metrics, ["valid_json", "schema_valid", "schema_error_count"]),
        "retrieval": metric_subset(
            metrics,
            [
                "input_gold_evidence_recall",
                "input_gold_step_coverage",
                "retrieved_evidence_count",
                "retrieved_gold_evidence_recall",
                "retrieved_gold_evidence_precision",
                "retrieved_step_coverage",
                "retrieved_distractor_rate",
                "agentic_gold_evidence_total",
                "agentic_observed_evidence_count",
                "agentic_observed_gold_evidence",
                "agentic_cited_observed_gold_evidence",
                "agentic_retrieved_gold_evidence_recall",
            ],
        ),
        "grouping": metric_subset(
            metrics,
            [
                "attack_clustering_bcubed_precision",
                "attack_clustering_bcubed_recall",
                "attack_clustering_bcubed_f1",
                "attack_clustering_ceafe_f1",
                "merge_split_diagnostic_source",
                "granularity_overmerge_gap",
                "granularity_oversplit_gap",
                "merge_error_rate",
                "split_error_rate",
                "clustering_bcubed_precision",
                "clustering_bcubed_recall",
                "clustering_bcubed_f1",
                "clustering_attack_universe_items",
                "clustering_full_universe_items",
                "clustering_pred_duplicate_evidence_refs",
                "clustering_pred_unknown_refs_filtered",
            ],
        ),
        "grouping_robustness": {
            **metric_subset(
                metrics,
                [
                    "attack_clustering_muc_f1",
                    "attack_clustering_blanc_f1",
                    "attack_clustering_v_measure",
                    "clustering_muc_f1",
                    "clustering_blanc_f1",
                    "clustering_v_measure",
                ],
            ),
        },
        "ordering": metric_subset(
            metrics,
            [
                "ceaf_alignment_version",
                "ceaf_alignment_algorithm",
                "ceaf_aligned_steps",
                "ceaf_pairwise_order_accuracy",
                "ceaf_chain_edit_distance",
                "ceaf_normalized_chain_edit_distance",
                "ceaf_chain_edit_similarity",
                "ceaf_lcs_matched_step_count",
                "ceaf_lcs_step_coverage",
            ],
        ),
        "labeling": metric_subset(
            metrics,
            [
                "ceaf_known_only_tactic_accuracy",
                "ceaf_known_only_technique_accuracy",
                "ceaf_tactic_accuracy",
                "ceaf_technique_accuracy",
                "pred_unknown_technique_rate",
                "gold_unknown_technique_rate",
            ],
        ),
        "grounding": metric_subset(
            metrics,
            [
                "ceaf_step_evidence_precision",
                "ceaf_step_evidence_recall",
                "ceaf_step_evidence_f1",
                "ceaf_evidence_precision",
                "ceaf_evidence_recall",
                "ceaf_evidence_f1",
                "evidence_precision",
                "evidence_recall",
                "evidence_f1",
                "order_aligned_step_evidence_precision",
                "order_aligned_step_evidence_recall",
                "order_aligned_step_evidence_f1",
                "unsupported_step_rate",
                "unknown_evidence_id_count",
                "mean_evidence_bundle_size",
                "total_evidence_references",
                "unique_evidence_references",
                "evidence_reuse_rate",
                "empty_evidence_step_rate",
                "agentic_attribution_gap_count",
                "agentic_attribution_gap_rate",
                "agentic_attribution_gap_evidence_ids",
            ],
        ),
    }

    appendix = {
        "legacy_bestmatch": {
            **prefixed_metric_subset(metrics, "bestmatch_"),
            **prefixed_metric_subset(metrics, "legacy_bestmatch_"),
        },
        "ceaf_alignment": prefixed_metric_subset(metrics, "ceaf_"),
        "raw_clustering_attack_universe": prefixed_metric_subset(metrics, "attack_clustering_"),
        "raw_clustering_full_universe": {
            key: value
            for key, value in prefixed_metric_subset(metrics, "clustering_").items()
            if not key.startswith("clustering_attack_")
        },
        "raw_edge_aliases": metric_subset(
            metrics,
            [
                "bestmatch_edge_precision",
                "bestmatch_edge_recall",
                "bestmatch_edge_f1",
                "bestmatch_causal_edge_precision",
                "bestmatch_causal_edge_recall",
                "bestmatch_causal_edge_f1",
                "bestmatch_temporal_edge_precision",
                "bestmatch_temporal_edge_recall",
                "bestmatch_temporal_edge_f1",
            ],
        ),
    }
    return {"scorecard": scorecard, "diagnostics": diagnostics, "appendix": appendix}


def evaluate(prediction: dict[str, Any], gt: dict[str, Any], incident_input: dict[str, Any] | None = None) -> dict[str, Any]:
    schema_errors = validate_prediction_schema(prediction)
    pred_steps = sorted_steps(prediction)
    gold_steps = sorted_steps(gt)
    aligned_n = min(len(pred_steps), len(gold_steps))

    tactic_hits = []
    technique_hits = []
    step_title_f1 = []
    step_description_f1 = []
    step_evidence_f1 = []
    step_evidence_precision = []
    step_evidence_recall = []
    unsupported_steps = 0

    for i in range(aligned_n):
        pred = pred_steps[i]
        gold = gold_steps[i]
        tactic_hits.append(1.0 if normalize(pred.get("tactic")) == normalize(gold.get("tactic")) else 0.0)
        technique_hits.append(1.0 if normalize(pred.get("technique_id")) == normalize(gold.get("technique_id")) else 0.0)
        step_title_f1.append(token_f1(pred.get("attack_step"), gold.get("attack_step")))
        step_description_f1.append(token_f1(pred.get("step_description"), gold.get("step_description")))
        pred_ev = set(canonical_evidence_ids(pred))
        gold_ev = set(canonical_evidence_ids(gold))
        p, r, f = set_f1(pred_ev, gold_ev)
        step_evidence_precision.append(p)
        step_evidence_recall.append(r)
        step_evidence_f1.append(f)
    unsupported_steps = sum(1 for step in pred_steps if not canonical_evidence_ids(step))

    all_pred_ev = {eid for step in pred_steps for eid in canonical_evidence_ids(step)}
    all_gold_ev = {eid for step in gold_steps for eid in canonical_evidence_ids(step)}
    ev_p, ev_r, ev_f1 = set_f1(all_pred_ev, all_gold_ev)

    known_evidence_ids: set[str] = set()
    if incident_input:
        known_evidence_ids = {str(card.get("evidence_id")) for card in incident_input.get("evidence_cards", [])}
    unknown_evidence_ids = sorted(all_pred_ev - known_evidence_ids) if known_evidence_ids else []

    gold_edges = edge_positions(gt.get("causal_edges", []), gold_steps)
    pred_edges = edge_positions(prediction.get("causal_edges", []), pred_steps)
    edge_p, edge_r, edge_f1 = set_f1(pred_edges, gold_edges)

    matches, bestmatch_algorithm, pair_features = best_step_matching(pred_steps, gold_steps, incident_input)
    bm_step_precision = len(matches) / len(pred_steps) if pred_steps else 0.0
    bm_step_recall = len(matches) / len(gold_steps) if gold_steps else 0.0
    bm_step_f1 = (
        0.0
        if bm_step_precision + bm_step_recall == 0
        else 2 * bm_step_precision * bm_step_recall / (bm_step_precision + bm_step_recall)
    )

    matched_gold_edges = {
        (match["gold_index"], next_match["gold_index"])
        for match in matches
        for next_match in matches
        if match["pred_index"] < next_match["pred_index"]
        and (match["pred_index"], next_match["pred_index"]) in pred_edges
    }
    gold_edge_indices = {(src, dst) for src, dst in gold_edges}
    bm_edge_p, bm_edge_r, bm_edge_f1 = set_f1(matched_gold_edges, gold_edge_indices)

    coverable_gold_indices = {
        idx for idx, step in enumerate(gold_steps)
        if canonical_evidence_ids(step)
    } or set(range(len(gold_steps)))
    matched_coverable_gold = {
        int(match["gold_index"])
        for match in matches
        if int(match["gold_index"]) in coverable_gold_indices
    }
    step_coverage_score = (
        len(matched_coverable_gold) / len(coverable_gold_indices)
        if coverable_gold_indices
        else 1.0
    )
    step_count_ratio = len(pred_steps) / len(gold_steps) if gold_steps else 0.0
    matched_gold_indices = {int(match["gold_index"]) for match in matches}
    unmatched_gold_step_rate = (len(gold_steps) - len(matched_gold_indices)) / len(gold_steps) if gold_steps else 0.0
    extra_pred_step_rate = (len(pred_steps) - len(matches)) / len(pred_steps) if pred_steps else 0.0
    known_tech_matches = [
        float(match.get("known_only_technique_match", 0.0))
        for match in matches
        if known_label(match.get("gold_technique_id"))
    ]
    known_tactic_matches = [
        float(match.get("known_only_tactic_match", 0.0))
        for match in matches
        if known_label(match.get("gold_tactic"))
    ]
    pred_unknown_tech_rate = (
        sum(1 for step in pred_steps if not known_label(step.get("technique_id"))) / len(pred_steps)
        if pred_steps
        else 0.0
    )
    gold_unknown_tech_rate = (
        sum(1 for step in gold_steps if not known_label(step.get("technique_id"))) / len(gold_steps)
        if gold_steps
        else 0.0
    )

    ceaf_metrics, ceaf_matches = ceaf_step_alignment_metrics(pred_steps, gold_steps, incident_input)
    extra_metrics: dict[str, Any] = {}
    extra_metrics.update(ceaf_metrics)
    extra_metrics.update({f"bestmatch_{key}": value for key, value in sequence_metrics(matches, len(pred_steps), len(gold_steps)).items()})
    extra_metrics.update({f"legacy_{key}": value for key, value in matching_diagnostics(pair_features, len(pred_steps), len(gold_steps)).items()})
    extra_metrics.update(evidence_bundle_metrics(pred_steps))
    extra_metrics.update(evidence_clustering_metrics(pred_steps, gold_steps, incident_input))
    extra_metrics.update(granularity_direction_metrics(extra_metrics))
    extra_metrics.update(exposure_metrics(prediction, gold_steps, incident_input))
    extra_metrics.update(attribution_gap_metrics(prediction, gold_steps))

    metrics = {
        "valid_json": 1.0,
        "schema_valid": 1.0 if not schema_errors else 0.0,
        "schema_error_count": len(schema_errors),
        "n_gold_steps": len(gold_steps),
        "n_pred_steps": len(pred_steps),
        "aligned_steps": aligned_n,
        "step_count_exact": 1.0 if len(pred_steps) == len(gold_steps) else 0.0,
        "step_count_ratio": step_count_ratio,
        "coverable_gold_steps": len(coverable_gold_indices),
        "step_coverage_score": step_coverage_score,
        "unmatched_gold_step_rate": unmatched_gold_step_rate,
        "extra_pred_step_rate": extra_pred_step_rate,
        "position_tactic_accuracy": avg(tactic_hits),
        "position_technique_accuracy": avg(technique_hits),
        "attack_step_title_token_f1": avg(step_title_f1),
        "step_description_token_f1": avg(step_description_f1),
        "evidence_precision": ev_p,
        "evidence_recall": ev_r,
        "evidence_f1": ev_f1,
        "order_aligned_step_evidence_precision": avg(step_evidence_precision),
        "order_aligned_step_evidence_recall": avg(step_evidence_recall),
        "order_aligned_step_evidence_f1": avg(step_evidence_f1),
        "causal_edge_precision_order_aligned": edge_p,
        "causal_edge_recall_order_aligned": edge_r,
        "causal_edge_f1_order_aligned": edge_f1,
        "unsupported_step_rate": unsupported_steps / len(pred_steps) if pred_steps else 1.0,
        "unknown_evidence_id_count": len(unknown_evidence_ids),
        "bestmatch_scoring_version": BEST_MATCH_SCORING_VERSION,
        "bestmatch_threshold": BEST_MATCH_THRESHOLD,
        "bestmatch_algorithm": bestmatch_algorithm,
        "bestmatch_matched_steps": len(matches),
        "bestmatch_step_precision": bm_step_precision,
        "bestmatch_step_recall": bm_step_recall,
        "bestmatch_step_f1": bm_step_f1,
        "bestmatch_avg_match_score": avg([m["score"] for m in matches]),
        "bestmatch_avg_legacy_score": avg([m["legacy_score"] for m in matches]),
        "bestmatch_avg_evidence_anchor_score": avg([m["evidence_anchor_score"] for m in matches]),
        "bestmatch_avg_action_text_similarity": avg([m["action_text_similarity"] for m in matches]),
        "bestmatch_avg_entity_slot_f1": avg([m["entity_slot_f1"] for m in matches]),
        "bestmatch_tactic_accuracy": avg([m["tactic_match"] for m in matches]),
        "bestmatch_technique_accuracy": avg([m["technique_match"] for m in matches]),
        "bestmatch_known_only_tactic_accuracy": avg(known_tactic_matches),
        "bestmatch_known_only_technique_accuracy": avg(known_tech_matches),
        "pred_unknown_technique_rate": pred_unknown_tech_rate,
        "gold_unknown_technique_rate": gold_unknown_tech_rate,
        "bestmatch_attack_step_title_token_f1": avg([m["title_f1"] for m in matches]),
        "bestmatch_step_description_token_f1": avg([m["description_f1"] for m in matches]),
        "bestmatch_entity_f1": avg([m["entity_f1"] for m in matches]),
        "bestmatch_entity_slot_f1": avg([m["entity_slot_f1"] for m in matches]),
        "bestmatch_step_evidence_precision": avg([m["evidence_precision"] for m in matches]),
        "bestmatch_step_evidence_recall": avg([m["evidence_recall"] for m in matches]),
        "bestmatch_step_evidence_f1": avg([m["evidence_f1"] for m in matches]),
        "bestmatch_pairwise_order_accuracy": pairwise_order_accuracy(matches),
        "bestmatch_edge_precision": bm_edge_p,
        "bestmatch_edge_recall": bm_edge_r,
        "bestmatch_edge_f1": bm_edge_f1,
        "bestmatch_causal_edge_precision": bm_edge_p,
        "bestmatch_causal_edge_recall": bm_edge_r,
        "bestmatch_causal_edge_f1": bm_edge_f1,
        "bestmatch_temporal_edge_precision": bm_edge_p,
        "bestmatch_temporal_edge_recall": bm_edge_r,
        "bestmatch_temporal_edge_f1": bm_edge_f1,
        **extra_metrics,
    }
    scorecard_layers = build_scorecard(metrics)
    return {
        "metrics": metrics,
        **scorecard_layers,
        "schema_errors": schema_errors,
        "unknown_evidence_ids": unknown_evidence_ids,
        "ceaf_matches": ceaf_matches,
        "best_matches": matches,
    }


def write_csv_row(path: Path, metrics: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(metrics.keys()))
        writer.writeheader()
        writer.writerow(metrics)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prediction", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, default=ROOT / "data/ground_truth/python-demo.gt.json")
    parser.add_argument("--incident-input", type=Path, default=ROOT / "data/incidents/python-demo.input.json")
    parser.add_argument("--out-json", type=Path, default=ROOT / "results/eval_metrics.json")
    parser.add_argument("--out-csv", type=Path, default=ROOT / "results/eval_metrics.csv")
    args = parser.parse_args()

    gt = load_json(args.ground_truth)
    incident_input = load_json(args.incident_input) if args.incident_input.exists() else None
    prediction, error = load_prediction(args.prediction)
    if error:
        metrics = {"valid_json": 0.0, "schema_valid": 0.0, "schema_error_count": 1}
        result = {"metrics": metrics, **build_scorecard(metrics), "error": error}
    else:
        result = evaluate(prediction, gt, incident_input)

    write_json(args.out_json, result)
    write_csv_row(args.out_csv, result["metrics"])
    print(json.dumps(result["metrics"], ensure_ascii=False, indent=2))
    print(f"WROTE {args.out_json}")
    print(f"WROTE {args.out_csv}")


if __name__ == "__main__":
    main()
