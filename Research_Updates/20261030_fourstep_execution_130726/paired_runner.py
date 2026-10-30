"""Controlled ORTHRUS adaptation. Private outputs stay in a new project run.

No author evaluator, database, attack labels, networking, GPU or package install.
Raw metadata are taken from each retained event, never from final database labels.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import gc
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import resource
import sqlite3
import sys
import time
import traceback

START = time.monotonic()
OLD = Path(os.environ['ORTHRUS_FROZEN_RUN']).resolve()
SPLITS = {'train': ['graph_3', 'graph_4'], 'val': ['graph_5'], 'test': ['graph_12']}
OUT: Path


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(2**20), b''):
            h.update(chunk)
    return h.hexdigest()


def save(name: str, value: object) -> None:
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    tmp.replace(path)


def stage(name: str, **kw: object) -> None:
    value = {'stage': name, 'pid': os.getpid(), 'utc': dt.datetime.now(dt.timezone.utc).isoformat(),
             'wall_seconds': time.monotonic() - START, **kw}
    save('STATUS.json', value)
    print(json.dumps(value, ensure_ascii=False), flush=True)


def unwrap(value):
    while isinstance(value, dict) and len(value) == 1:
        value = next(iter(value.values()))
    return value


def current_text(value) -> str:
    value = unwrap(value)
    return value if isinstance(value, str) and value not in ('<unknown>', 'null', 'None') else ''


def event_key(eid: str, timestamp: int, operation: str) -> str:
    return str(eid) + '|' + str(int(timestamp)) + '|' + str(operation)


def main_imports():
    os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:4]))
    resource.setrlimit(resource.RLIMIT_AS, (20 * 1024**3, 20 * 1024**3))
    sys.dont_write_bytecode = True
    os.environ.update(MPLCONFIGDIR=str(OUT / 'mpl_cache'), MPLBACKEND='Agg', WANDB_MODE='disabled',
                      OPENBLAS_NUM_THREADS='4', OMP_NUM_THREADS='4', NUMBA_NUM_THREADS='4')
    import nltk
    nltk.download = lambda *a, **k: False
    nltk.data.path.insert(0, str(OLD / 'cache/nltk_data'))
    sys.path.insert(0, str(OLD / 'source' / 'src'))
    import torch
    import yaml
    from yacs.config import CfgNode
    torch.set_num_threads(4)
    torch.manual_seed(4)
    random.seed(4)
    import numpy as np
    np.random.seed(4)
    cfg = CfgNode(yaml.safe_load((OLD / 'ACTUAL_CONFIG.yml').read_text()))
    cfg._from_weights = False
    cfg._use_cpu = True
    cfg.dataset.train_files = SPLITS['train']
    cfg.dataset.val_files = SPLITS['val']
    cfg.dataset.test_files = SPLITS['test']
    cfg.detection.evaluation.node_evaluation.use_kmeans = False
    cfg.edge_featurization.embed_nodes.feature_word2vec.num_workers = 1
    return torch, cfg


def verify_sources() -> None:
    manifest = json.loads((OUT / 'INPUT_FREEZE.json').read_text())
    for path, expected in manifest['source_sha256'].items():
        if sha(Path(path)) != expected:
            raise ValueError('Historical source identity changed: ' + path)
    if sha(OLD / 'ACTUAL_CONFIG.yml') != manifest['old_config_sha256']:
        raise ValueError('Old configuration changed')


def prepare(torch, cfg) -> None:
    if (OUT / 'PREPARED.json').exists():
        raise FileExistsError('Preparation already sealed; use the train command')
    source_hashes = {str(p): sha(p) for p in (OLD / 'source' / 'src').rglob('*.py')}
    sealed = json.loads((OLD / 'SERVER_ARTIFACT_SHA256.json').read_text())
    graph_root = Path(cfg.graph_construction.build_graphs._graphs_dir)
    selected, input_graphs, counts = {}, {}, collections.Counter()
    stage('VERIFY_AND_INDEX_FIXED_GRAPHS')
    for split, days in SPLITS.items():
        for day in days:
            for path in sorted((graph_root / day).iterdir()):
                expected = sealed.get(str(path.relative_to(OLD)))
                actual = sha(path)
                if expected != actual:
                    raise ValueError('Unsealed graph input: ' + str(path))
                graph = torch.load(path, map_location='cpu')
                input_graphs[str(path)] = {'sha256': actual, 'split': split}
                for src, dst, edge in graph.edges(data=True):
                    eid = event_key(edge['event_uuid'], edge['time'], edge['label'])
                    value = (split, path.name, int(src), int(dst), int(edge['time']), edge['label'],
                             graph.nodes[src]['node_type'], graph.nodes[dst]['node_type'])
                    if eid in selected and selected[eid] != value:
                        raise ValueError('Event UUID has conflicting occurrences')
                    selected[eid] = value
                    counts[split] += 1
    save('INPUT_FREEZE.json', {'source_sha256': source_hashes, 'graphs': input_graphs,
         'old_config_sha256': sha(OLD / 'ACTUAL_CONFIG.yml'), 'retained_events': dict(counts),
         'protocol_sha256': sha(OUT / 'experiment_protocol.json'),
         'raw_receipt_sha256': sha(OLD / 'RAW_COVERAGE.json')})
    (OUT / 'ACTUAL_CONFIG.yml').write_text(cfg.dump())
    db = sqlite3.connect(OUT / 'private_events.sqlite')
    db.execute('PRAGMA journal_mode=DELETE')
    db.execute('CREATE TABLE events(eid TEXT PRIMARY KEY, split TEXT, window TEXT, src INTEGER, dst INTEGER, '
               't INTEGER, op TEXT, stype TEXT, dtype TEXT, stok TEXT, dtok TEXT, raw_file TEXT, '
               'line_number INTEGER, byte_offset INTEGER, raw_line_sha256 TEXT, src_uuid TEXT, dst_uuid TEXT, properties TEXT)')
    db.execute('CREATE INDEX event_window ON events(split,window,t,eid)')
    net_meta, uuid_map = {}, {}
    raw_receipt = json.loads((OLD / 'RAW_COVERAGE.json').read_text())
    from config import edge_reversed
    from provnet_utils import tokenize_subject, tokenize_file, tokenize_netflow
    tokenizers = {'subject': tokenize_subject, 'file': tokenize_file, 'netflow': tokenize_netflow}
    tokenize_cache = {}

    def tokens(kind, text):
        key = (kind, text)
        if key not in tokenize_cache:
            tokenize_cache[key] = tokenizers[kind](text) if text else []
        return tokenize_cache[key]

    matched = collections.Counter()
    corpus, batch, raw_checks = set(), [], []
    event_re = re.compile(rb'cdm18\.Event"\s*:\s*\{\s*"uuid"\s*:\s*"([^"]+)"')
    time_re = re.compile(rb'"timestampNanos"\s*:\s*(\d+)')
    op_re = re.compile(rb'"type"\s*:\s*"(EVENT_[^"]+)"')
    selected_uuids = {key.split('|',1)[0] for key in selected}
    for entry in raw_receipt['files']:
        path = OLD / 'raw' / entry['name']
        initial = path.stat()
        h = hashlib.sha256()
        nbytes = nlines = 0
        stage('EXTRACT_AS_OBSERVED_EVENT_METADATA', file=path.name, matched=dict(matched))
        with path.open('rb') as stream:
            for line in stream:
                offset = nbytes
                nbytes += len(line)
                nlines += 1
                h.update(line)
                if b'cdm18.NetFlowObject"' in line:
                    obj = next(iter(json.loads(line)['datum'].values()))
                    uid = obj['uuid']
                    text = current_text(obj.get('remoteAddress'))
                    if uid in net_meta and net_meta[uid] != text:
                        raise ValueError('Netflow descriptor conflict')
                    net_meta[uid] = text
                else:
                    m = event_re.search(line)
                    if not m or m.group(1).decode() not in selected_uuids:
                        continue
                    tm,om=time_re.search(line),op_re.search(line)
                    if not tm or not om:
                        raise ValueError('Candidate raw event lacks typed time/operation')
                    eid = event_key(m.group(1).decode(),int(tm.group(1)),om.group(1).decode())
                    if eid not in selected:
                        continue
                    row = selected.pop(eid)
                    split, window, src, dst, t, op, stype, dtype = row
                    event = next(iter(json.loads(line)['datum'].values()))
                    if event['type'] != op or int(event['timestampNanos']) != t:
                        raise ValueError('Graph/raw event mismatch')
                    subject = unwrap(event['subject'])
                    obj = unwrap(event['predicateObject'])
                    props = event.get('properties') or {}
                    props = props.get('map', props)
                    texts = {subject: current_text(props.get('exec')),
                             obj: current_text(event.get('predicateObjectPath'))}
                    suid, duid = (obj, subject) if op in edge_reversed else (subject, obj)
                    for index, uid, typ in [(src, suid, stype), (dst, duid, dtype)]:
                        if index in uuid_map and uuid_map[index] != (uid, typ):
                            raise ValueError('Ambiguous node identity')
                        uuid_map[index] = (uid, typ)
                    st = tokens(stype, net_meta.get(suid, '') if stype == 'netflow' else texts.get(suid, ''))
                    dtok = tokens(dtype, net_meta.get(duid, '') if dtype == 'netflow' else texts.get(duid, ''))
                    if split == 'train':
                        for tok in (st, dtok):
                            if tok:
                                corpus.add(tuple(tok))
                    batch.append((eid, split, window, src, dst, t, op, stype, dtype, json.dumps(st),
                                  json.dumps(dtok), path.name, nlines, offset, hashlib.sha256(line).hexdigest(),
                                  suid, duid, json.dumps(props)))
                    matched[split] += 1
                    if len(batch) >= 5000:
                        db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', batch)
                        db.commit()
                        batch.clear()
                if nlines % 250000 == 0:
                    save('METADATA_PROGRESS.json', {'file': path.name, 'lines': nlines, 'bytes': nbytes,
                         'matched': dict(matched), 'remaining': len(selected), 'wall_seconds': time.monotonic()-START})
        if batch:
            db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', batch)
            db.commit()
            batch.clear()
        final = path.stat()
        if h.hexdigest() != entry['sha256'] or nbytes != entry['bytes_read']:
            raise ValueError('Raw bytes differ from original frozen receipt')
        if (initial.st_ino, initial.st_size, initial.st_mtime_ns) != (final.st_ino, final.st_size, final.st_mtime_ns):
            raise ValueError('Raw file changed while reading')
        raw_checks.append({'name': path.name, 'sha256': h.hexdigest(), 'bytes_read': nbytes,
                           'lines': nlines, 'eof': True})
        save('RAW_METADATA_READ_RECEIPT.json', raw_checks)
    if selected or dict(matched) != dict(counts):
        raise ValueError('Not all retained graph events found in raw input: ' + str(len(selected)))
    save('private_node_uuid_map.json', {str(k): list(v) for k, v in uuid_map.items()})
    save('METADATA_IDENTITY_RECEIPT.json', {'matched_events': dict(matched), 'unique_nodes': len(uuid_map),
         'metadata_policy': 'subject exec and object path on the same raw event; network descriptor already encountered in stream; empty when unavailable',
         'word2vec_fit': 'deduplicated nonempty token sequences from TRAIN EVENTS ONLY',
         'no_final_database_metadata': True, 'no_test_tokens_in_word2vec': True,
         'event_time_order': 'sort within author window by integer nanoseconds and event UUID; ties remain observationally tied'})
    stage('FIT_TRAIN_ONLY_WORD2VEC', sequences=len(corpus))
    from gensim.models import Word2Vec
    corpus = [list(t) for t in sorted(corpus)]
    w2v = Word2Vec(corpus, vector_size=128, window=5, min_count=1, sg=1, workers=1,
                  epochs=50, negative=5, seed=4)
    w2v.save(str(OUT / 'word2vec.model'))
    del corpus, net_meta, tokenize_cache
    gc.collect()
    stage('BUILD_PAIRED_EVENT_FEATURES')
    import numpy as np
    from torch_geometric.data import TemporalData
    from config import rel2id, ntype2id
    vector_cache, oov = {}, collections.Counter()

    def vector(token_json, split):
        key = token_json
        toks = json.loads(token_json)
        oov[split + '_tokens'] += len(toks)
        oov[split + '_unknown_tokens'] += sum(t not in w2v.wv for t in toks)
        if key not in vector_cache:
            known = [w2v.wv[t] for t in toks if t in w2v.wv]
            vec = np.mean(known, axis=0) if known else np.zeros(128, dtype=np.float32)
            norm = np.linalg.norm(vec)
            vector_cache[key] = vec / norm if norm > 0 else vec
        if not any(t in w2v.wv for t in toks):
            oov[split + '_zero_semantic_endpoints'] += 1
        return vector_cache[key]

    feature_manifest = {}
    for path_str, info in input_graphs.items():
        split, window = info['split'], Path(path_str).name
        rows = db.execute('SELECT eid,src,dst,t,op,stype,dtype,stok,dtok FROM events WHERE split=? AND window=? ORDER BY t,eid', (split, window)).fetchall()
        src, dst, ts, msgs, eids = [], [], [], [], []
        for eid, u, v, t, op, stype, dtype, stok, dtok in rows:
            src.append(u); dst.append(v); ts.append(t); eids.append(eid)
            msgs.append(np.concatenate([np.eye(3, dtype=np.float32)[ntype2id[stype]-1], vector(stok, split),
                         np.eye(10, dtype=np.float32)[rel2id[op]-1],
                         np.eye(3, dtype=np.float32)[ntype2id[dtype]-1], vector(dtok, split)]))
        g = TemporalData(src=torch.tensor(src), dst=torch.tensor(dst), t=torch.tensor(ts),
                         msg=torch.from_numpy(np.stack(msgs)))
        if not torch.isfinite(g.msg).all() or not torch.all(g.t[1:] >= g.t[:-1]):
            raise ValueError('Invalid paired features')
        target = OUT / 'features' / split / (window + '.pt')
        target.parent.mkdir(parents=True, exist_ok=True)
        torch.save(g, target)
        identity = target.with_suffix('.ids.json')
        identity.write_text(json.dumps(eids))
        feature_manifest[str(target.relative_to(OUT))] = {'sha256': sha(target), 'events': len(eids),
                    'identity_sha256': sha(identity), 'source_graph_sha256': info['sha256']}
    db.close()
    save('FEATURE_MANIFEST.json', feature_manifest)
    save('OOV_REPORT.json', dict(oov))
    verify_sources()
    save('PREPARED.json', {'status': 'PAIRED_FEATURES_READY', 'word2vec_sha256': sha(OUT/'word2vec.model'),
                         'feature_manifest_sha256': sha(OUT/'FEATURE_MANIFEST.json'), 'counts': dict(counts)})
    stage('PAIRED_FEATURES_READY', counts=dict(counts))


def load_split(torch, cfg, split):
    from data_utils import extract_msg_from_data
    manifests = json.loads((OUT / 'FEATURE_MANIFEST.json').read_text())
    result = []
    for file in sorted((OUT / 'features' / split).glob('*.pt')):
        if sha(file) != manifests[str(file.relative_to(OUT))]['sha256']:
            raise ValueError('Feature identity mismatch')
        result.append(torch.load(file, map_location='cpu'))
    return extract_msg_from_data(result, cfg)


def train(torch, cfg) -> None:
    if (OUT/'TRAINING_RESULT.json').exists() or (OUT/'EPOCHS.jsonl').exists():
        raise FileExistsError('Training must not overwrite an earlier attempt')
    verify_sources()
    stage('LOAD_TRAIN_AND_VALIDATION_ONLY')
    from factory import build_model, optimizer_factory, batch_loader_factory
    from torch_geometric.data import Data
    training, validation = load_split(torch,cfg,'train'), load_split(torch,cfg,'val')
    all_data = training + validation
    full = Data(t=torch.cat([g.t for g in all_data]), edge_type=torch.cat([g.edge_type for g in all_data]))
    # Upstream config uses only historical edge types; no concatenated test tensors.
    full.msg = torch.empty((len(full.t), 0))
    maxnode = 1 + max(int(torch.cat([g.src,g.dst]).max()) for g in all_data)
    model = build_model(training[0],torch.device('cpu'),cfg,maxnode)
    optimizer = optimizer_factory(cfg, set(model.parameters()))
    best = math.inf
    selected_epoch = None
    total_train_events = sum(g.t.numel() for g in training)
    for epoch in range(1,21):
        epoch_start = time.monotonic()
        stage('TRAINING', epoch=epoch, total_epochs=20)
        model.encoder.reset_state()
        model.graph_reindexer.x_src_cache = None
        model.graph_reindexer.x_dst_cache = None
        model.train()
        weighted = 0.0
        processed = 0
        for wi,g in enumerate(training):
            for batch in batch_loader_factory(cfg,g,model.graph_reindexer):
                optimizer.zero_grad()
                loss = model(batch,full)
                if not torch.isfinite(loss).all():
                    raise ValueError('Nonfinite training loss')
                loss.backward()
                optimizer.step()
                count = len(batch.t)
                weighted += float(loss.detach()) * count
                processed += count
            if wi % 10 == 0:
                save('TRAIN_PROGRESS.json', {'epoch':epoch,'window':wi+1,'windows':len(training),
                     'events':processed,'event_total':total_train_events,
                     'epoch_seconds':time.monotonic()-epoch_start,'weighted_training_loss':weighted/processed})
        model.eval()
        val_sum, val_n, val_max = 0.0, 0, -math.inf
        with torch.no_grad():
            for g in validation:
                for batch in batch_loader_factory(cfg,g,model.graph_reindexer):
                    losses = model(batch,full,inference=True)
                    if not torch.isfinite(losses).all():
                        raise ValueError('Nonfinite validation loss')
                    val_sum += float(losses.double().sum())
                    val_n += losses.numel()
                    val_max = max(val_max,float(losses.max()))
        value = val_sum / val_n
        row = {'epoch':epoch,'train_event_weighted_loss':weighted/processed,'train_events':processed,
               'validation_event_weighted_loss':value,'validation_events':val_n,'validation_max_event_loss':val_max,
               'seconds':time.monotonic()-epoch_start}
        checkpoint = OUT/'checkpoints'/('epoch_%02d.pt'%epoch)
        checkpoint.parent.mkdir(exist_ok=True)
        # Always save weights, selected model also saves post-validation historical state.
        torch.save(model.state_dict(),checkpoint)
        row['checkpoint_sha256'] = sha(checkpoint)
        if value < best:
            best,selected_epoch = value,epoch
            torch.save({'state_dict':model.state_dict(),'neighbor_loader':model.encoder.neighbor_loader,
                        'x_src_cache':model.graph_reindexer.x_src_cache,'x_dst_cache':model.graph_reindexer.x_dst_cache,
                        'max_nodes':maxnode,'epoch':epoch,'threshold':val_max,
                        'history_events':int(full.t.numel())},OUT/'selected_checkpoint.pt')
            save('SELECTION.json',{'epoch':epoch,'validation_loss':value,'threshold':val_max,
                 'tie_rule':'earliest epoch','history':'train then validation, without intervening unobserved events',
                 'selection_uses_test':False,'checkpoint_sha256':sha(OUT/'selected_checkpoint.pt')})
        with (OUT/'EPOCHS.jsonl').open('a') as f:
            f.write(json.dumps(row)+'\n')
        print(json.dumps(row),flush=True)
    verify_sources()
    save('TRAINING_RESULT.json',{'status':'TWENTY_EPOCH_TRAINING_COMPLETE','selected_epoch':selected_epoch,
         'selected_validation_event_weighted_loss':best,'selection':json.loads((OUT/'SELECTION.json').read_text()),
         'test_graphs_loaded_during_training':False,'labels_read':False,'gpu_used':False,
         'wall_seconds':time.monotonic()-START,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
    stage('TRAINING_COMPLETE',selected_epoch=selected_epoch)


def test(torch,cfg) -> None:
    if (OUT/'TEST_RESULT.json').exists():
        raise FileExistsError('Test has already been frozen')
    if not (OUT/'TRAINING_RESULT.json').is_file():
        raise ValueError('Training and selection must finish before test')
    verify_sources()
    from factory import build_model,batch_loader_factory
    from torch_geometric.data import Data
    selected = torch.load(OUT/'selected_checkpoint.pt',map_location='cpu')
    all_data = [*load_split(torch,cfg,'train'),*load_split(torch,cfg,'val'),*load_split(torch,cfg,'test')]
    full = Data(t=torch.cat([g.t for g in all_data]),edge_type=torch.cat([g.edge_type for g in all_data]))
    full.msg = torch.empty((len(full.t),0))
    test_files = sorted((OUT/'features'/'test').glob('*.pt'))
    testing = all_data[-len(test_files):]
    maxnode = 1+max(int(torch.cat([g.src,g.dst]).max()) for g in all_data)
    model = build_model(testing[0],torch.device('cpu'),cfg,maxnode)
    model.load_state_dict(selected['state_dict'])
    old_loader = selected['neighbor_loader']
    loader = model.encoder.neighbor_loader
    for name in ['neighbors','e_id']:
        getattr(loader,name)[:selected['max_nodes']] = getattr(old_loader,name)
    loader.cur_e_id = old_loader.cur_e_id
    for name in ['x_src_cache','x_dst_cache']:
        previous = selected[name]
        current = torch.zeros((maxnode,previous.shape[1]))
        current[:previous.shape[0]] = previous
        setattr(model.graph_reindexer,name,current)
    if loader.cur_e_id != selected['history_events']:
        raise ValueError('Neighbor/history indexing mismatch')
    model.eval()
    scores,alert_windows={},collections.defaultdict(set)
    threshold=selected['threshold']
    score_dir=OUT/'test_scores'
    score_dir.mkdir()
    with torch.no_grad():
        for wi,(path,g) in enumerate(zip(test_files,testing)):
            identities=json.loads(path.with_suffix('.ids.json').read_text())
            pos=0
            with (score_dir/(path.stem+'.jsonl')).open('x') as f:
                for batch in batch_loader_factory(cfg,g,model.graph_reindexer):
                    values=model(batch,full,inference=True)
                    if not torch.isfinite(values).all():
                        raise ValueError('Nonfinite test score')
                    for i,value in enumerate(values.tolist()):
                        src,dst=int(batch.src[i]),int(batch.dst[i])
                        row={'event_key':identities[pos],'event_uuid':identities[pos].split('|',1)[0],'src_index':src,'dst_index':dst,
                             'time_ns':int(batch.t[i]),'loss':value,'window':path.stem}
                        f.write(json.dumps(row)+'\n');pos+=1
                        for node in (src,dst):
                            scores[node]=max(scores.get(node,-math.inf),value)
                            if value>threshold:
                                alert_windows[node].add(path.stem)
            if pos!=len(identities):
                raise ValueError('Score/event identity count differs')
            stage('DEVELOPMENT_TEST',window=wi+1,windows=len(test_files),alert_nodes=len(alert_windows))
    mapping=json.loads((OUT/'private_node_uuid_map.json').read_text())
    q=[{'node_uuid':mapping[str(n)][0],'node_type':mapping[str(n)][1],'index':n,'score':scores[n],
        'alert_windows':sorted(windows)} for n,windows in sorted(alert_windows.items())]
    save('Q.json',q)
    save('NODE_SCORES.json',[{'node_uuid':mapping[str(n)][0],'index':n,'score':v,'is_alert':n in alert_windows}
                             for n,v in sorted(scores.items())])
    files=[OUT/'Q.json',OUT/'NODE_SCORES.json',OUT/'selected_checkpoint.pt',*score_dir.glob('*.jsonl')]
    save('PREDICTION_FREEZE.json',{str(p.relative_to(OUT)):sha(p) for p in files})
    verify_sources()
    save('TEST_RESULT.json',{'status':'NO_ALERTS' if not q else 'DEVELOPMENT_Q_FROZEN','Q_count':len(q),
         'threshold':threshold,'selected_epoch':selected['epoch'],'test_events':sum(len(g.t) for g in testing),
         'labels_read':False,'selection_uses_test':False,'gpu_used':False,
         'history_gap':'No graph_6..11 replay; post-graph_5 history restored directly for graph_12',
         'claim_scope':'Controlled adaptation, development case, not exact author replication or blind validation',
         'wall_seconds':time.monotonic()-START,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})
    stage('DEVELOPMENT_PREDICTIONS_FROZEN',Q_count=len(q))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['prepare','train','test','all'])
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    OUT=args.out.resolve()
    if OLD in OUT.parents or OUT==OLD:
        raise ValueError('Output must be outside frozen historical run')
    OUT.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.umask(0o077)
    try:
        torch,cfg=main_imports()
        if args.phase in ('prepare','all'):prepare(torch,cfg)
        if args.phase in ('train','all'):train(torch,cfg)
        if args.phase in ('test','all'):test(torch,cfg)
    except Exception as exc:
        save('FAILURE_'+args.phase+'.json',{'type':type(exc).__name__,'message':str(exc),
             'traceback':traceback.format_exc(),'wall_seconds':time.monotonic()-START})
        raise
