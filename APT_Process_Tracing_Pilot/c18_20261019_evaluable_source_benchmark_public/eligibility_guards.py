"""Pure admission checks; these functions do not generate truth or run a baseline."""
from typing import Mapping, Any
import re
MAIN_SOURCE_LEVELS = {'session', 'inbound_connection'}
def validate_event(event: Mapping[str, Any]) -> None:
    required = {'source_sha256', 'host', 'timestamp_ns', 'actor', 'object'}
    if not required.issubset(event) or any(event[k] is None for k in required):
        raise ValueError('missing observed identity or role; no default fill-in')
    if not re.fullmatch(r'[0-9a-f]{64}', str(event['source_sha256'])):
        raise ValueError('source digest required')
    if not (event.get('event_uuid') or type(event.get('record_ordinal')) is int and event['record_ordinal'] > 0):
        raise ValueError('unique event locator required')
    if type(event['timestamp_ns']) is not int:
        raise ValueError('integer native time required')
def pilot_status(*, b_level: str, a_level: str, source_level: str,
                 same_execution: bool, independent_reference: bool,
                 universe_ids: list[str] | None, reference_a_ids: list[str],
                 observations_available: bool) -> str:
    if b_level != 'B2_INDEPENDENTLY_MAPPED_EVENT':
        return 'C18_REFERENCE_NOT_EVENT_MAPPABLE'
    if a_level != 'A2_RAW_INSTANCE_MAPPED' or source_level not in MAIN_SOURCE_LEVELS:
        return 'C18_B_EVENT_ONLY_NO_SOURCE_INSTANCE'
    if not same_execution or not independent_reference:
        return 'C18_B_EVENT_ONLY_NO_SOURCE_INSTANCE'
    if universe_ids is None or len(set(universe_ids)) < 2 or not observations_available:
        return 'C18_PILOT_REFERENCE_FOUND_GRAPH_COVERAGE_LIMITED'
    if not reference_a_ids or not set(reference_a_ids).issubset(universe_ids):
        raise ValueError('reference and predefined candidate scope conflict')
    return 'C18_EVALUABLE_SOURCE_PILOT_GO'
def baseline_may_run(status: str) -> bool:
    return status == 'C18_EVALUABLE_SOURCE_PILOT_GO'
def source_metrics_ready(status: str) -> bool:
    return baseline_may_run(status)
def path_metrics_ready(path_grade: str) -> bool:
    return path_grade == 'P2_INDEPENDENT_EDGE_REFERENCE'
def control_grade(independent_benign_proof: bool) -> str:
    return 'BENIGN_GOLD' if independent_benign_proof else 'UNLABELED_CONTROL'
