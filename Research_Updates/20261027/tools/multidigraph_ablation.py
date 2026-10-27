"""Payload-free publication adaptation of the frozen graph ablation program.

Requires an existing NetworkX installation. Does not install packages, read Gold,
invoke a model, or reinterpret topological reachability as attack causality.
The published aggregate results came from the original frozen program, not this
adaptation. Use only with graph and edge lists you are authorized to access.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


def remove_instances(graph, rows: list[dict]):
    result = graph.copy()
    seen: set[tuple] = set()
    for row in rows:
        source, target = row["source"], row["target"]
        key = row["author_key"]
        if not graph.has_edge(source, target, key):
            key = int(key)
        instance = source, target, key
        if instance in seen or not graph.has_edge(*instance):
            raise ValueError("Duplicate or absent edge instance")
        seen.add(instance)
        result.remove_edge(*instance)
    if set(graph) != set(result):
        raise AssertionError("Deletion changed node membership")
    return result


def metrics(graph, poi: str) -> dict:
    import networkx as nx
    if poi not in graph:
        raise ValueError("POI absent from graph")
    weak = list(nx.weakly_connected_components(graph))
    strong = list(nx.strongly_connected_components(graph))
    return {
        "nodes": len(graph), "edges": graph.number_of_edges(),
        "weak_components": len(weak), "strong_components": len(strong),
        "largest_weak_component": max(map(len, weak)),
        "largest_strong_component": max(map(len, strong)),
        "isolates": len(list(nx.isolates(graph))),
        "poi_weak_component": len(next(c for c in weak if poi in c)),
        "poi_descendants": len(nx.descendants(graph, poi)),
        "poi_ancestors": len(nx.ancestors(graph, poi)),
        "interpretation": "GRAPH_TOPOLOGY_ONLY_NOT_ATTACK_FLOW",
    }


def main() -> None:
    import networkx as nx
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--edges", type=Path, required=True, help="Frozen CSV: source,target,author_key,relation_type")
    parser.add_argument("--controls", type=Path, required=True, help="Fixed non-added edge CSV")
    parser.add_argument("--poi", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.graph.read_bytes()
    if hashlib.sha256(data).hexdigest() != args.expected_sha256:
        raise ValueError("Graph hash mismatch")
    graph = nx.node_link_graph(json.loads(data))
    if not graph.is_directed() or not graph.is_multigraph():
        raise ValueError("Expected a directed multigraph")
    with args.edges.open(newline="") as stream:
        added = [r for r in csv.DictReader(stream) if r["relation_type"] == "added"]
    with args.controls.open(newline="") as stream:
        controls = list(csv.DictReader(stream))
    if len(added) != len(controls):
        raise ValueError("Unequal deletion budgets")
    report = {"G0": metrics(graph, args.poi),
              "G1_REMOVE_ADDED": metrics(remove_instances(graph, added), args.poi),
              "G2_REMOVE_FIXED_CONTROLS": metrics(remove_instances(graph, controls), args.poi)}
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
