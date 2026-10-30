"""Small tested primitives for a future event-retrieval experiment, not a new model."""
from __future__ import annotations

import math
import random
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple


def unambiguous_adjacent_pairs(
    events: Iterable[Tuple[int, str]], max_gap_ns: int
) -> Tuple[List[Tuple[str, str]], int]:
    """Compare adjacent time GROUPS, abstaining if either contains a tie.

    Ambiguous groups remain in the timeline: dropping them and bridging the
    remaining groups would invent a new adjacency. Caller retains entity scope.
    """
    groups: Dict[int, List[str]] = defaultdict(list)
    seen = set()
    for timestamp, event_id in events:
        if not isinstance(timestamp, int):
            raise TypeError('timestamp must be exact integer nanoseconds')
        if event_id in seen:
            raise ValueError('duplicate event identity')
        seen.add(event_id)
        groups[timestamp].append(event_id)
    if max_gap_ns < 0:
        raise ValueError('negative gap')
    times = sorted(groups)
    pairs, abstained = [], 0
    for earlier, later in zip(times, times[1:]):
        if later - earlier > max_gap_ns:
            continue
        if len(groups[earlier]) != 1 or len(groups[later]) != 1:
            abstained += 1
            continue
        pairs.append((groups[earlier][0], groups[later][0]))
    return pairs, abstained


def shuffle_row(weights: List[float], seed: int) -> List[float]:
    """Permute existing candidate weights; preserve row mass, not global occupancy."""
    if any(not math.isfinite(w) or w < 0 for w in weights):
        raise ValueError('invalid transition weight')
    if math.fsum(weights) > 1 + 1e-12:
        raise ValueError('row mass exceeds one')
    result = list(weights)
    random.Random(seed).shuffle(result)
    return result


def effective_restart(weights: List[float], alpha: float = 0.2) -> float:
    if not 0 < alpha <= 1:
        raise ValueError('alpha out of range')
    shuffle_row(weights, 0)  # validate substochastic weights
    return 1 - (1 - alpha) * math.fsum(weights)


def induced_neighbors(original: Dict[str, List[str]], retained: set) -> Dict[str, List[str]]:
    """Restrict a frozen candidate relation, never replace a missing neighbor."""
    return {event: [n for n in original.get(event, []) if n in retained]
            for event in sorted(retained)}
