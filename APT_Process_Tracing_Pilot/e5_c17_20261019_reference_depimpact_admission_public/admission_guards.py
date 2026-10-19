"""Decision guards only: no CDM conversion, file loading, or investigation scoring."""
from typing import Mapping, Any
import re
PROJECTION = ('source_sha', 'ordinal', 'host', 'event_uuid', 'actor', 'object', 'type', 'timestamp_ns')
def validate_projection(record: Mapping[str, Any]) -> None:
    if set(record) != set(PROJECTION):
        raise ValueError('missing or unexpected projection fields')
    if any(record[k] is None for k in PROJECTION):
        raise ValueError('unknown reference must remain explicit; no fill-in allowed')
    if type(record['ordinal']) is not int or record['ordinal'] < 1:
        raise ValueError('invalid source ordinal')
    if type(record['timestamp_ns']) is not int:
        raise ValueError('timestamp must preserve integer nanoseconds')
def require_unique(records: list[Mapping[str, Any]]) -> None:
    seen = set()
    for record in records:
        validate_projection(record)
        key = (record['source_sha'], record['ordinal'])
        if key in seen:
            raise ValueError('duplicate source position')
        seen.add(key)
def reference_admissible(*, host_anchor: bool, clock_anchor: bool,
                         execution_anchor: bool, uniquely_bound: bool) -> bool:
    # No graph reachability, ranking, application name, or fitted time-offset input.
    return all((host_anchor, clock_anchor, execution_anchor, uniquely_bound))
def require_same_task(*, poi_kind: str, event_uuid_selector: bool,
                      identity_fidelity: bool, direction_fidelity: bool,
                      time_fidelity: bool, source_layer_equivalence: bool) -> None:
    if poi_kind != 'event' or not all((event_uuid_selector, identity_fidelity,
                                     direction_fidelity, time_fidelity,
                                     source_layer_equivalence)):
        raise ValueError('FORMAT_LOSSY_OR_POI_MISMATCH')
def metrics_status(*, source_reference: bool, path_reference: bool) -> dict[str, str]:
    return {'source': 'REFERENCE_REQUIRED_BEFORE_SCORING' if source_reference else 'NOT_ESTIMABLE',
            'path': 'REFERENCE_REQUIRED_BEFORE_SCORING' if path_reference else 'NOT_ESTIMABLE'}
