"""Read a private physical COPY of the stopped author DB; verify A=compress(B).

The historical database is never started. The temporary server accepts only a
private Unix socket, defaults to read-only transactions, and is stopped in finally.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,required=True)
    p=parser.parse_args().out.resolve()
    os.umask(0o077)
    os.sched_setaffinity(0,set(sorted(os.sched_getaffinity(0))[:4]))
    old=Path(os.environ['ORTHRUS_FROZEN_RUN']).resolve()
    bins=Path(os.environ['POSTGRES_BIN']).resolve()
    source=old/'pgdata'
    snapshot=p/'pg_snapshot'
    started=time.monotonic()
    if (p/'COMPRESSION_FACTOR_READY.json').exists():
        raise FileExistsError('Do not repeat an existing extraction attempt')
    if (source/'postmaster.pid').exists():
        raise ValueError('Historical database is running; no physical copy attempted')
    state=subprocess.check_output([str(bins/'pg_controldata'),str(source)],text=True)
    if 'Database cluster state:               shut down' not in state:
        raise ValueError('Historical database is not cleanly stopped')
    if list((source/'pg_tblspc').iterdir()) or any(x.is_symlink() for x in source.rglob('*')):
        raise ValueError('External tablespace or symlink would violate copy isolation')
    before={str(x.relative_to(source)):(x.stat().st_size,x.stat().st_mtime_ns) for x in source.rglob('*') if x.is_file()}
    if snapshot.exists():
        prior=json.loads((p/'DATABASE_COPY_ISOLATION_RECEIPT.json').read_text())
        if not prior['historical_file_stats_unchanged'] or not prior['snapshot_postmaster_stopped']:
            raise ValueError('Prior copy isolation check failed')
        copy_state=subprocess.check_output([str(bins/'pg_controldata'),str(snapshot)],text=True)
        if 'Database cluster state:               shut down' not in copy_state:
            raise ValueError('Snapshot not cleanly stopped')
    else:
        shutil.copytree(source,snapshot)
    sock=Path('/private/tmp') if Path('/private/tmp').exists() else Path('/tmp')
    sock=sock/('apt4pg_'+str(os.getpid()))
    sock.mkdir(mode=0o700)
    log=p/'private_postgres.log'
    args=['-k',str(sock),'-p','55442','-c',"listen_addresses=''",'-c','default_transaction_read_only=on',
          '-c','autovacuum=off','-c','max_connections=5','-c','shared_buffers=128MB']
    try:
        subprocess.run([str(bins/'pg_ctl'),'-D',str(snapshot),'-l',str(log),'-o',' '.join(args),'-w','start'],check=True)
        import psycopg2
        import torch
        import yaml
        import nltk
        nltk.download=lambda *a,**k:False
        sys.path.insert(0,str(old/'source'/'src'))
        from config import rel2id
        from provnet_utils import datetime_to_ns_time_US,ns_time_to_datetime_US
        cfg=yaml.safe_load((old/'ACTUAL_CONFIG.yml').read_text())
        graphs=Path(cfg['graph_construction']['build_graphs']['_graphs_dir'])
        db=sqlite3.connect(p/'uncompressed_events.sqlite')
        db.execute('CREATE TABLE events(rid INTEGER PRIMARY KEY,eid TEXT,window TEXT,split TEXT,src INTEGER,dst INTEGER,t INTEGER,op TEXT)')
        db.execute('CREATE INDEX uncompressed_window ON events(split,window,t,rid)')
        conn=psycopg2.connect(dbname='cadets_e3',user=os.environ['ORTHRUS_DB_USER'],host=str(sock),port=55442)
        conn.set_session(readonly=True)
        checks=[]
        for day,split in [(3,'train'),(4,'train'),(12,'test')]:
            low=datetime_to_ns_time_US('2018-04-%02d 00:00:00'%day)
            high=datetime_to_ns_time_US('2018-04-%02d 00:00:00'%(day+1))
            cur=conn.cursor(name='source_events_%d'%day)
            cur.itersize=50000
            cur.execute('SELECT * FROM event_table WHERE timestamp_rec>%s AND timestamp_rec<%s ORDER BY timestamp_rec,event_uuid',(low,high))
            start=None
            batch=[]
            window=[]

            def finish_window(rows):
                nonlocal start
                end=rows[-1][-2]
                name=ns_time_to_datetime_US(start)+'~'+ns_time_to_datetime_US(end)
                source_graph=graphs/('graph_%d'%day)/name
                if not source_graph.is_file():
                    raise ValueError('Replayed author window absent: '+name)
                g=torch.load(source_graph,map_location='cpu')
                pairs=collections.defaultdict(list)
                for row in rows:pairs[(row[1],row[4])].append(row)
                fused=[]
                for pair,events in pairs.items():
                    prev=None
                    for row in sorted(events,key=lambda r:r[-2]):
                        if row[2]!=prev:
                            fused.append((int(row[1]),int(row[4]),int(row[-2]),row[2],row[5]))
                            prev=row[2]
                expected=[(int(u),int(v),int(e['time']),e['label'],e['event_uuid']) for u,v,e in g.edges(data=True)]
                if collections.Counter(fused)!=collections.Counter(expected):
                    raise ValueError('Compression replay differs from frozen author graph: '+name)
                db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)',
                     [(int(r[-1]),r[5],name,split,int(r[1]),int(r[4]),int(r[-2]),r[2]) for r in rows])
                db.commit()
                checks.append({'day':day,'window':name,'before':len(rows),'after':len(fused),'exact_replay':True})
                (p/'COMPRESSION_REPLAY_PROGRESS.json').write_text(json.dumps({'verified_windows':len(checks),
                    'before_total':sum(x['before'] for x in checks if 'before' in x),'after_total':sum(x['after'] for x in checks if 'after' in x),
                    'wall_seconds':time.monotonic()-started},indent=2))
                start=end

            for row in cur:
                if row[2] not in rel2id:continue
                if start is None:start=int(row[-2])
                batch.append(row)
                if len(batch)==1024:
                    window.extend(batch)
                    if int(batch[-1][-2])>start+900_000_000_000:
                        finish_window(window)
                        window=[]
                    batch=[]
            # Match upstream: incomplete final chunk/window is NOT flushed.
            if batch:
                window.extend(batch)
                if int(batch[-1][-2])>start+900_000_000_000:
                    finish_window(window)
                    window=[]
            checks.append({'day':day,'discarded_author_tail_events':len(window)})
            cur.close()
        conn.close();db.close()
        valid=[x for x in checks if 'window' in x]
        if len(valid)!=276:
            raise ValueError('Expected 184 train and 92 test windows')
        (p/'COMPRESSION_FACTOR_READY.json').write_text(json.dumps({'status':'A_EQUALS_COMPRESSION_OF_B_VERIFIED',
            'verified_windows':len(valid),'before_total':sum(x['before'] for x in valid),
            'after_total':sum(x['after'] for x in valid),'checks':checks,
            'operation_vocabulary':'same original 10 operations; no FORK/ACCEPT addition',
            'historical_database_started':False,'database_used':'private physical copy; default read-only',
            'wall_seconds':time.monotonic()-started},indent=2))
    finally:
        if (snapshot/'postmaster.pid').exists():
            subprocess.run([str(bins/'pg_ctl'),'-D',str(snapshot),'-m','fast','-w','stop'],check=True)
        after={str(x.relative_to(source)):(x.stat().st_size,x.stat().st_mtime_ns) for x in source.rglob('*') if x.is_file()}
        receipt={'historical_file_stats_unchanged':before==after,'old_database_started':False,
                 'snapshot_postmaster_stopped':not (snapshot/'postmaster.pid').exists()}
        (p/'DATABASE_COPY_ISOLATION_RECEIPT_v2.json').write_text(json.dumps(receipt,indent=2))
        if before!=after:raise ValueError('Historical database files changed externally')


if __name__=='__main__':main()
