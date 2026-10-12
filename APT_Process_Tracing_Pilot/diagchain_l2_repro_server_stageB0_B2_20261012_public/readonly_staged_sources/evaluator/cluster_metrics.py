#!/usr/bin/env python3
"""Cluster metrics for evidence-level attack-chain evaluation.

The evaluator can project both a prediction and a gold chain into the same
object: evidence_id -> cluster_id.  These metrics then score whether evidence
cards are grouped into the same attack-action units without depending on step
names or exact step counts.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from itertools import permutations
from typing import Any

try:
    from scipy.optimize import linear_sum_assignment
except Exception:  # noqa: BLE001 - keep metrics usable without scipy.
    linear_sum_assignment = None


def f1(precision: float, recall: float) -> float:
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def choose2(n: int) -> int:
    return n * (n - 1) // 2


def normalize_label(value: Any) -> str:
    return str(value if value is not None else "__missing__")


def labels_for_universe(
    mapping: dict[str, Any],
    universe_ids: list[str] | set[str] | tuple[str, ...],
    *,
    missing_label: str,
) -> dict[str, str]:
    return {
        str(evidence_id): normalize_label(mapping.get(str(evidence_id), missing_label))
        for evidence_id in universe_ids
    }


def clusters_from_labels(labels: dict[str, str]) -> dict[str, set[str]]:
    clusters: dict[str, set[str]] = defaultdict(set)
    for evidence_id, label in labels.items():
        clusters[label].add(evidence_id)
    return dict(clusters)


def contingency_counts(pred_labels: dict[str, str], gold_labels: dict[str, str]) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for evidence_id in pred_labels:
        counts[(pred_labels[evidence_id], gold_labels[evidence_id])] += 1
    return dict(counts)


def bcubed(pred_labels: dict[str, str], gold_labels: dict[str, str]) -> dict[str, float]:
    if not pred_labels:
        return {"bcubed_precision": 1.0, "bcubed_recall": 1.0, "bcubed_f1": 1.0}
    pred_clusters = clusters_from_labels(pred_labels)
    gold_clusters = clusters_from_labels(gold_labels)
    intersections = contingency_counts(pred_labels, gold_labels)

    precisions = []
    recalls = []
    for evidence_id, pred_label in pred_labels.items():
        gold_label = gold_labels[evidence_id]
        same_both = intersections[(pred_label, gold_label)]
        precisions.append(same_both / len(pred_clusters[pred_label]))
        recalls.append(same_both / len(gold_clusters[gold_label]))
    precision = sum(precisions) / len(precisions)
    recall = sum(recalls) / len(recalls)
    return {"bcubed_precision": precision, "bcubed_recall": recall, "bcubed_f1": f1(precision, recall)}


def muc(pred_labels: dict[str, str], gold_labels: dict[str, str]) -> dict[str, float]:
    def score(key_labels: dict[str, str], response_labels: dict[str, str]) -> tuple[int, int]:
        key_clusters = clusters_from_labels(key_labels)
        numerator = 0
        denominator = 0
        for members in key_clusters.values():
            if len(members) <= 1:
                continue
            response_parts = {response_labels[evidence_id] for evidence_id in members}
            numerator += len(members) - len(response_parts)
            denominator += len(members) - 1
        return numerator, denominator

    recall_num, recall_den = score(gold_labels, pred_labels)
    precision_num, precision_den = score(pred_labels, gold_labels)
    precision = precision_num / precision_den if precision_den else 1.0
    recall = recall_num / recall_den if recall_den else 1.0
    return {"muc_precision": precision, "muc_recall": recall, "muc_f1": f1(precision, recall)}


def ceafe(pred_labels: dict[str, str], gold_labels: dict[str, str]) -> dict[str, float]:
    pred_clusters = list(clusters_from_labels(pred_labels).values())
    gold_clusters = list(clusters_from_labels(gold_labels).values())
    if not pred_clusters and not gold_clusters:
        return {"ceafe_precision": 1.0, "ceafe_recall": 1.0, "ceafe_f1": 1.0}
    if not pred_clusters or not gold_clusters:
        return {"ceafe_precision": 0.0, "ceafe_recall": 0.0, "ceafe_f1": 0.0}

    sim = [[len(pred & gold) for gold in gold_clusters] for pred in pred_clusters]
    if linear_sum_assignment is not None:
        n_rows = len(pred_clusters)
        n_cols = len(gold_clusters)
        n = max(n_rows, n_cols)
        cost = [[0 for _ in range(n)] for _ in range(n)]
        for i in range(n_rows):
            for j in range(n_cols):
                cost[i][j] = -sim[i][j]
        row_ind, col_ind = linear_sum_assignment(cost)
        similarity = sum(
            sim[int(i)][int(j)]
            for i, j in zip(row_ind, col_ind, strict=False)
            if int(i) < n_rows and int(j) < n_cols
        )
    elif max(len(pred_clusters), len(gold_clusters)) <= 9:
        # Exact fallback for tiny unit tests.
        if len(pred_clusters) <= len(gold_clusters):
            similarity = max(
                sum(sim[i][perm[i]] for i in range(len(pred_clusters)))
                for perm in permutations(range(len(gold_clusters)), len(pred_clusters))
            )
        else:
            similarity = max(
                sum(sim[perm[j]][j] for j in range(len(gold_clusters)))
                for perm in permutations(range(len(pred_clusters)), len(gold_clusters))
            )
    else:
        # Deterministic greedy fallback.  This is only used if scipy is absent.
        candidates = [
            (sim[i][j], i, j)
            for i in range(len(pred_clusters))
            for j in range(len(gold_clusters))
        ]
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        used_pred: set[int] = set()
        used_gold: set[int] = set()
        similarity = 0
        for score, i, j in candidates:
            if i in used_pred or j in used_gold:
                continue
            used_pred.add(i)
            used_gold.add(j)
            similarity += score

    n_pred_mentions = sum(len(cluster) for cluster in pred_clusters)
    n_gold_mentions = sum(len(cluster) for cluster in gold_clusters)
    precision = similarity / n_pred_mentions if n_pred_mentions else 1.0
    recall = similarity / n_gold_mentions if n_gold_mentions else 1.0
    return {"ceafe_precision": precision, "ceafe_recall": recall, "ceafe_f1": f1(precision, recall)}


def blanc(pred_labels: dict[str, str], gold_labels: dict[str, str]) -> dict[str, float]:
    n = len(pred_labels)
    total_pairs = choose2(n)
    if total_pairs == 0:
        return {
            "blanc_coref_precision": 1.0,
            "blanc_coref_recall": 1.0,
            "blanc_coref_f1": 1.0,
            "blanc_noncoref_precision": 1.0,
            "blanc_noncoref_recall": 1.0,
            "blanc_noncoref_f1": 1.0,
            "blanc_precision": 1.0,
            "blanc_recall": 1.0,
            "blanc_f1": 1.0,
        }

    pred_positive = sum(choose2(len(members)) for members in clusters_from_labels(pred_labels).values())
    gold_positive = sum(choose2(len(members)) for members in clusters_from_labels(gold_labels).values())
    true_positive = sum(choose2(count) for count in contingency_counts(pred_labels, gold_labels).values())
    false_positive = pred_positive - true_positive
    false_negative = gold_positive - true_positive
    true_negative = total_pairs - true_positive - false_positive - false_negative

    coref_precision = true_positive / pred_positive if pred_positive else (1.0 if gold_positive == 0 else 0.0)
    coref_recall = true_positive / gold_positive if gold_positive else (1.0 if pred_positive == 0 else 0.0)
    noncoref_predicted = total_pairs - pred_positive
    noncoref_gold = total_pairs - gold_positive
    noncoref_precision = true_negative / noncoref_predicted if noncoref_predicted else (1.0 if noncoref_gold == 0 else 0.0)
    noncoref_recall = true_negative / noncoref_gold if noncoref_gold else (1.0 if noncoref_predicted == 0 else 0.0)

    coref_f1 = f1(coref_precision, coref_recall)
    noncoref_f1 = f1(noncoref_precision, noncoref_recall)
    precision = (coref_precision + noncoref_precision) / 2
    recall = (coref_recall + noncoref_recall) / 2
    return {
        "blanc_coref_precision": coref_precision,
        "blanc_coref_recall": coref_recall,
        "blanc_coref_f1": coref_f1,
        "blanc_noncoref_precision": noncoref_precision,
        "blanc_noncoref_recall": noncoref_recall,
        "blanc_noncoref_f1": noncoref_f1,
        "blanc_precision": precision,
        "blanc_recall": recall,
        "blanc_f1": (coref_f1 + noncoref_f1) / 2,
    }


def entropy(counts: list[int], total: int) -> float:
    if total == 0:
        return 0.0
    value = 0.0
    for count in counts:
        if count <= 0:
            continue
        p = count / total
        value -= p * math.log(p)
    return value


def conditional_entropy(group_labels: dict[str, str], conditioned_on: dict[str, str]) -> float:
    n = len(group_labels)
    if n == 0:
        return 0.0
    by_condition: dict[str, Counter[str]] = defaultdict(Counter)
    for evidence_id, label in group_labels.items():
        by_condition[conditioned_on[evidence_id]][label] += 1
    value = 0.0
    for counts in by_condition.values():
        subtotal = sum(counts.values())
        value += (subtotal / n) * entropy(list(counts.values()), subtotal)
    return value


def v_measure(pred_labels: dict[str, str], gold_labels: dict[str, str]) -> dict[str, float]:
    n = len(pred_labels)
    if n == 0:
        return {"homogeneity": 1.0, "completeness": 1.0, "v_measure": 1.0}
    pred_counts = Counter(pred_labels.values())
    gold_counts = Counter(gold_labels.values())
    h_gold = entropy(list(gold_counts.values()), n)
    h_pred = entropy(list(pred_counts.values()), n)
    h_gold_given_pred = conditional_entropy(gold_labels, pred_labels)
    h_pred_given_gold = conditional_entropy(pred_labels, gold_labels)
    homogeneity = 1.0 if h_gold == 0 else 1.0 - h_gold_given_pred / h_gold
    completeness = 1.0 if h_pred == 0 else 1.0 - h_pred_given_gold / h_pred
    return {
        "homogeneity": homogeneity,
        "completeness": completeness,
        "v_measure": f1(homogeneity, completeness),
    }


def compare_clusterings(
    pred_mapping: dict[str, Any],
    gold_mapping: dict[str, Any],
    *,
    universe_ids: list[str] | set[str] | tuple[str, ...] | None = None,
    pred_missing_label: str = "__pred_unassigned__",
    gold_missing_label: str = "__gold_unassigned__",
) -> dict[str, float]:
    """Compare two non-overlapping evidence clusterings.

    Missing elements are assigned explicit labels instead of being dropped.  This
    makes missed gold evidence and predicted background evidence visible to the
    score rather than silently disappearing.
    """
    if universe_ids is None:
        universe_ids = sorted(set(pred_mapping) | set(gold_mapping))
    else:
        universe_ids = sorted(str(item) for item in universe_ids)
    pred_labels = labels_for_universe(pred_mapping, universe_ids, missing_label=pred_missing_label)
    gold_labels = labels_for_universe(gold_mapping, universe_ids, missing_label=gold_missing_label)

    metrics: dict[str, float] = {"n_items": float(len(universe_ids))}
    metrics.update(bcubed(pred_labels, gold_labels))
    metrics.update(ceafe(pred_labels, gold_labels))
    metrics.update(muc(pred_labels, gold_labels))
    metrics.update(blanc(pred_labels, gold_labels))
    metrics.update(v_measure(pred_labels, gold_labels))
    return metrics


def prefixed(prefix: str, metrics: dict[str, float]) -> dict[str, float]:
    return {f"{prefix}{key}": value for key, value in metrics.items()}
