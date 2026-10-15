"""Unmodified native Controller + deterministic fake text backend; zero model calls."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

ROOT = Path(__file__).absolute().parents[1]
NATIVE = ROOT / 'author_tree' / 'benchmark'
sys.path.insert(0,str(ROOT/'src'))
from safe_paths import atomic_create,private_dir,sha
from strict_exchange_validator import phase_of,validate_request,validate_response,make_response
from bridge_state_machine import Budget,ExchangeState
from jsonl_final_message_parser import parse_final
sys.path.insert(0, str(NATIVE))
DENIALS: list[dict[str, str]] = []
RUNTIME_ROOTS = (Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve(),
                 Path('/System'), Path('/Library'), Path('/usr'), Path('/opt/homebrew'))


def within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def audit(event: str, args: tuple[Any, ...]) -> None:
    if event in ('socket.connect', 'socket.getaddrinfo', 'subprocess.Popen', 'os.system'):
        DENIALS.append({'event': event, 'reason': 'network/process execution disabled'})
        raise PermissionError('network/subprocess disabled in synthetic native harness')
    if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
        p = Path(os.fsdecode(args[0])).absolute().resolve()
        allowed = within(p, ROOT) or any(within(p, q) for q in RUNTIME_ROOTS) or str(p) in ('/dev/null', '/dev/urandom')
        mode = args[1] if len(args) > 1 else 'r'
        flags = args[2] if len(args) > 2 else 0
        writing = isinstance(mode, str) and any(x in mode for x in 'wax+')
        writing = writing or isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR))
        if not allowed or writing and not within(p, ROOT):
            DENIALS.append({'event': event, 'path': str(p), 'reason': 'outside synthetic run'})
            raise PermissionError('outside synthetic run file access denied')


sys.addaudithook(audit)
assert not (NATIVE.parent / '.env.local').exists()
import agentic_reconstruction as native
import run_chain_reconstruction_paper_systems as systems
from build_reconstruction_benchmark import write_input_graph, write_retrieval_docs


def refuse_model(*args: Any, **kwargs: Any) -> str:
    raise AssertionError('real backend call forbidden')


native.call_model = refuse_model
systems.call_model = refuse_model


def create_private(path: Path, value: Any) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def fixture(directory: Path) -> Any:
    directory.mkdir(mode=0o700)
    cards = [
        {'evidence_id': 'E0001', 'card_type': 'log_observation', 'source_type': 'autolabel_log',
         'timestamp': '2026-01-01T00:00:00Z', 'content': 'SYNTHETIC process alpha wrote file beta on synthetic host.',
         'extracted_clues': {'processes': ['alpha'], 'files': ['beta']}},
        {'evidence_id': 'E0002', 'card_type': 'log_observation', 'source_type': 'autolabel_log',
         'timestamp': '2026-01-01T00:01:00Z', 'content': 'SYNTHETIC process alpha read file beta on synthetic host.',
         'extracted_clues': {'processes': ['alpha'], 'files': ['beta']}},
    ]
    incident = {'incident_id': 'SYNTHETIC_NATIVE_ONLY', 'incident_brief': 'Pure synthetic protocol fixture.',
                'task_instruction': 'Reconstruct only the synthetic observations.', 'evidence_cards': cards}
    ip, dp, gp = (directory / n for n in ('synthetic.input.json', 'synthetic.docs.jsonl', 'synthetic.input_graph.json'))
    create_private(ip, incident)
    write_retrieval_docs(dp, cards)
    write_input_graph(gp, cards)
    os.chmod(dp, 0o600); os.chmod(gp, 0o600)
    return systems.build_state(ip, dp, gp)


class FakeTransport:
    def __init__(self, directory: Path, mode: str) -> None:
        self.directory, self.mode = directory, mode
        self.budget=Budget(directory/'budget',total_limit=23,per_case_limit=23,total_wall=3600,case_wall=1800,worker_wait=360,synthetic=True)
        self.budget.begin_case('SYNTHETIC_NATIVE_'+mode)
        self.rows: list[dict[str, Any]] = []
        self.counts = dict(controller=0, reflection=0, repair=0, synthesis=0)
        self.chain = {'incident_summary': 'Synthetic observations only.', 'attack_chain': [
            {'step_id': 'S1', 'description': 'Synthetic process alpha wrote file beta.',
             'supporting_evidence': ['E0001'], 'confidence': 'low'}], 'causal_edges': []}

    def __call__(self, prompt: str, **unused) -> str:
        prefixes = {'reflection': 'You are doing the reflection step',
                    'repair': 'The previous controller response was not valid JSON',
                    'synthesis': 'You are finalizing an AGENTIC attack-chain',
                    'controller': 'You are operating in AGENTIC attack-chain'}
        phase = next((k for k, p in prefixes.items() if prompt.startswith(p)), None)
        if phase is None:
            raise AssertionError('unrecognized native phase; no fallback')
        if len(self.rows) >= 46:
            raise AssertionError('fake phase-inclusive message budget exhausted')
        self.counts[phase] += 1
        if phase == 'reflection':
            obj = {'reflection': {'issues': [], 'changes': [], 'confidence': 'low'}, 'working_chain': self.chain}
        elif phase == 'synthesis':
            obj = {'synthesis': {'reason': 'synthetic evidence exhausted', 'confidence': 'low'}, 'working_chain': self.chain}
        else:
            if phase == 'repair' or self.mode == 'synthesis' or self.counts['controller'] == 1:
                action, chain = 'query_evidence', native.empty_chain()
            else:
                action, chain = 'submit', self.chain
            obj = {'thought': 'synthetic fake response', 'action': action,
                   'query_intent': 'synthetic alpha beta', 'working_chain': chain}
        raw = '{malformed synthetic JSON' if self.mode == 'repair' and phase == 'controller' and self.counts[phase] == 1 else json.dumps(obj, ensure_ascii=False)
        seq = len(self.rows) + 1
        req = {'run_id':'SYNTHETIC_NATIVE_'+self.mode,'attempt_id':'SYNTHETIC_ATTEMPT_'+self.mode,
               'case_id':'SYNTHETIC_NATIVE_'+self.mode,'seq':seq,'phase':phase,'controller_turn':max(1,self.counts['controller']),
               'prompt_utf8':prompt,'prompt_sha256':sha(prompt),'data_class':'SYNTHETIC_ONLY'}
        validate_request(req,synthetic=True);self.budget.reserve(req)
        x=private_dir(self.directory,'exchange_'+str(seq));journal=ExchangeState(x/'state',req)
        atomic_create(x,'request.json',req);journal.transition('REQUEST_SENT',{'source':'FAKE_WORKER_NO_NETWORK'})
        events=[{'type':'thread.started'},{'type':'turn.started'},
                {'type':'item.completed','item':{'id':'early','type':'agent_message','text':'Synthetic commentary'}},
                {'type':'item.completed','item':{'id':'final','type':'agent_message','text':raw}},
                {'type':'turn.completed','usage':{'input_tokens':0,'output_tokens':0}}]
        wire=('\n'.join(json.dumps(e,ensure_ascii=False) for e in events)+'\n').encode()
        receipt=parse_final(wire,raw.encode(),0)
        res=make_response(req,raw,source='FAKE_WORKER',parser_receipt=receipt)
        validate_response(req,res,synthetic=True);atomic_create(x,'fake_jsonl.raw',wire);atomic_create(x,'response.json',res)
        journal.transition('RESPONSE_RECEIVED');journal.transition('RESPONSE_VALIDATED');journal.transition('SERVER_ACCEPTED',{'synthetic_only':True});journal.transition('CONTROLLER_CONTINUED')
        systems.LAST_MODEL_CALL_TELEMETRY={'provider':'FAKE_WORKER','model':'gpt-6-luna','prompt_chars':len(prompt),'output_chars':len(raw),'prompt_tokens':0,'output_tokens':0}
        self.rows.append({'seq':seq,'phase':phase,'prompt_sha256':req['prompt_sha256'],'reply_sha256':res['reply_sha256'],'author_json_status':receipt['author_json_status'],'new_real_model_calls':0})
        return raw


def main() -> None:
    os.umask(0o077)
    os.chdir(ROOT)  # dir_fd atomic temporary names stay within this synthetic package.
    outcomes = []
    for mode in ['submit_reflection', 'repair', 'synthesis']:
        d = ROOT / 'synthetic_exchange' / ('native_'+mode+'_'+uuid.uuid4().hex)
        state = fixture(d)
        config = native.AgenticRunConfig(retrieval_kernel='ECRAG', planner='llm',
            working_memory_mode='structured_attack_chain', oracle_mode='none', agent_method='reflection',
            action_mode='typed', investigation_memory=True, support_audit=True, grounding_check=True,
            max_turns=15, top_k_per_query=32, temperature=0, model='gpt-6-luna', provider='FAKE_TEXT_BRIDGE',
            no_new_evidence_patience=3)
        kernel = native.PaperRetrievalKernel('ECRAG', state, top_k=32)
        controller = native.AgenticController(state, kernel, config)
        transport = FakeTransport(d, mode)
        native.call_model = transport
        prediction, trace = controller.run()
        create_private(d / 'synthetic_prediction_NOT_REAL.json', prediction)
        create_private(d / 'synthetic_trace_NOT_REAL.json', trace)
        create_private(d / 'fake_message_ledger.json', {'counts': transport.counts, 'rows': transport.rows, 'real_model_calls': 0})
        checks = {'has_controller': transport.counts['controller'] > 0,
                  'native_output_dicts': isinstance(prediction, dict) and isinstance(trace, dict),
                  'native_trace_turns': isinstance(trace.get('turns'), list),
                  'all_hash_bindings_saved': len(transport.rows) == sum(transport.counts.values())}
        if mode == 'submit_reflection': checks['reflection_called'] = transport.counts['reflection'] > 0
        if mode == 'repair': checks['repair_called'] = transport.counts['repair'] > 0
        if mode == 'synthesis': checks['synthesis_called'] = transport.counts['synthesis'] > 0
        outcomes.append({'mode': mode, 'counts': transport.counts, 'checks': checks,
                         'termination_reason': prediction.get('metadata', {}).get('termination_reason'),
                         'fake_messages': len(transport.rows), 'real_model_calls': 0})
    create_private(ROOT / 'logs/native_integration_results.json', {'utc': datetime.now(timezone.utc).isoformat(),
        'outcomes': outcomes, 'checks': sum(len(x['checks']) for x in outcomes),
        'passed': sum(sum(x['checks'].values()) for x in outcomes), 'audit_denials': DENIALS,
        'native_sources_modified': False, 'real_model_calls': 0, 'Gold_read': False})
    print(json.dumps({'outcomes':outcomes,'new_real_model_calls':0}, ensure_ascii=False))
    if not all(all(x['checks'].values()) for x in outcomes): raise SystemExit(1)


if __name__ == '__main__':
    main()
