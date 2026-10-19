"""Conservative evidence gate; no dataset identities and no inference model."""
REQUIRED = ('scoped_instance_identity', 'receiver_lifecycle', 'inbound_control_direction',
            'independent_B_binding', 'raw_locator', 'competitors_resolved')

def qualifies_a2(evidence):
    return all(evidence.get(k) is True for k in REQUIRED)

def ranking_ready(b2, a2_evidence, universe_complete, nontrivial):
    return b2 is True and qualifies_a2(a2_evidence) and universe_complete is True and nontrivial is True

def coverage_state(error, fetched, cap):
    if error:
        return 'QUERY_FAILED_OR_PARTIAL'
    return 'BUDGET_PARTIAL' if fetched > cap else 'QUERY_RESULT_COMPLETE_ONLY'
