"""Versioned continuation of pending units; original frozen batch runner untouched."""
from __future__ import annotations
import argparse, os
from pathlib import Path
from c15_common import *
from c15_transport_compat import CompatParser, VERSION
import recovery_runner
import c15_run_batch as native_batch
from safe_paths import ExclusiveLease

def verify_continuation(root: Path) -> dict:
    frozen_check(root)
    receipt = read(root/'authorization/CONTINUATION_01.json')
    frozen = root/'17_transport_compat_freeze.json'
    if receipt.get('state') != 'USER_AUTHORIZED_CONTINUE_WITH_MINIMAL_TRANSPORT_COMPAT' or not receipt.get('direct_user_message_locator'):
        raise SafetyError('CONTINUATION_AUTHORIZATION_MISSING')
    if receipt.get('compat_freeze_sha256') != sha(frozen.read_bytes()) or receipt.get('original_limits') != LIMITS:
        raise SafetyError('CONTINUATION_SCOPE_CHANGED')
    for item in read(frozen)['files']:
        if sha(safe_path(root,item['path']).read_bytes()) != item['sha256']:
            raise SafetyError('TRANSPORT_COMPAT_FROZEN_FILE_CHANGED')
    require_batch_authorization(root,read(root/'authorization/BATCH_APPROVAL.json'))
    return receipt

def run(root: Path, quota: Path) -> dict:
    receipt = verify_continuation(root)
    recovery_runner.JsonlParser = CompatParser
    original = native_batch.run_one
    versions = root/'transport_versions';versions.mkdir(mode=0o700,exist_ok=True)
    def versioned_run(root: Path, unit: dict, gate: dict, plan: dict) -> dict:
        if unit['run_unit_id'] not in receipt['remaining_unit_ids']:
            raise SafetyError('CONTINUATION_CAN_ONLY_START_ORIGINAL_PENDING_UNITS')
        atomic_create(versions,unit['run_unit_id']+'.json',{'version':VERSION,'run_unit_id':unit['run_unit_id'],
            'compat_freeze_sha256':receipt['compat_freeze_sha256'],'original_batch_freeze_sha256':gate['approved_protocol_sha256'],
            'prior_failed_or_completed_runs_not_replaced':True,'utc':utc()})
        return original(root,unit,gate,plan)
    native_batch.run_one = versioned_run
    with ExclusiveLease(root,'BATCH_EXECUTION_LOCK'):
        return native_batch.run_block(root,quota)

if __name__ == '__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');parser.add_argument('--quota-receipt',type=Path)
    args=parser.parse_args()
    try:
        if args.check:
            verify_continuation(ROOT);result={'state':'TRANSPORT_COMPAT_CONTINUATION_CHECK_PASS','new_model_calls':0}
        elif args.quota_receipt:result=run(ROOT,args.quota_receipt)
        else:raise SafetyError('CURRENT_QUOTA_RECEIPT_REQUIRED')
        print(json.dumps(result,ensure_ascii=False))
    except SafetyError as error:
        print(json.dumps({'state':str(error),'new_model_calls_from_gate_failure':0}));raise SystemExit(3)
