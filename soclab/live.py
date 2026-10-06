"""Single-host operations pilot: durable evidence, outbox and scheduled alerts.

No attack commands are executed. Private collection stays local by default.
"""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from .detections import detect, load_rules
from .events import normalize_event
from .loki import Loki, flatten
from .operations import canonical, text
from .store import SCHEMA

ROOT = Path(__file__).resolve().parents[1]
LIMIT_EVENTS = 100000
LIMIT_QUEUE = 10000
LIMIT_STORAGE = 512*1024*1024
SLA = {"critical":900, "high":3600, "medium":14400, "low":86400}


def private_path(path):
    roots=[ROOT/'data/local']
    if os.name=='nt' and os.environ.get('LOCALAPPDATA'):
        roots.append(Path(os.environ['LOCALAPPDATA'])/'SOCInvestigationLab/live')
    return any(Path(path).resolve().is_relative_to(root.resolve()) for root in roots)


def default_workspace():
    if os.name=='nt' and os.environ.get('LOCALAPPDATA'):
        return Path(os.environ['LOCALAPPDATA'])/'SOCInvestigationLab/live/default'
    return ROOT/'data/local/live'
STATES = {"new":{"triaged"}, "triaged":{"investigating"},
          "investigating":{"escalated","closed"}, "escalated":{"investigating","closed"}, "closed":set()}
LIVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (fingerprint TEXT PRIMARY KEY, event_uid TEXT UNIQUE NOT NULL,
 scope TEXT NOT NULL, kind TEXT NOT NULL, received REAL NOT NULL);
CREATE INDEX IF NOT EXISTS observation_scope ON observations(scope,event_uid);
CREATE TABLE IF NOT EXISTS batches (sha256 TEXT PRIMARY KEY, scope TEXT NOT NULL, kind TEXT NOT NULL,
 accepted INTEGER NOT NULL, duplicates INTEGER NOT NULL, received REAL NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (event_uid TEXT PRIMARY KEY, scope TEXT NOT NULL, kind TEXT NOT NULL,
 stamp TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt REAL NOT NULL, lease_token TEXT, lease_until REAL, error TEXT);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,next_attempt);
CREATE TABLE IF NOT EXISTS collectors (scope TEXT PRIMARY KEY, cursor TEXT NOT NULL, updated REAL NOT NULL,
 gap_count INTEGER NOT NULL DEFAULT 0, last_error TEXT);
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, scope TEXT NOT NULL, kind TEXT NOT NULL,
 rule_id TEXT NOT NULL, severity TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL,
 owner TEXT, verdict TEXT, created REAL NOT NULL, due REAL NOT NULL, finding TEXT NOT NULL,
 rule_sha256 TEXT NOT NULL, case_id TEXT);
CREATE INDEX IF NOT EXISTS alert_state ON alerts(state,created);
CREATE TABLE IF NOT EXISTS alert_audit (alert_id TEXT NOT NULL, sequence INTEGER NOT NULL,
 payload TEXT NOT NULL, previous TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(alert_id,sequence));
CREATE TABLE IF NOT EXISTS detection_runs (id TEXT PRIMARY KEY, scope TEXT NOT NULL, at REAL NOT NULL,
 inspected INTEGER NOT NULL, inserted INTEGER NOT NULL, rule_sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS maintenance (at REAL NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL,
 affected INTEGER NOT NULL);
"""


def connect(workspace):
    workspace = Path(workspace).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(workspace/'live.sqlite', timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=FULL')
    conn.executescript(SCHEMA + LIVE_SCHEMA)
    return conn


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value):
        raise ValueError('scope must be a short alphanumeric identifier')
    return value


def ingest_batch(workspace, source, *, scope, kind='synthetic', cursor=None, gap=False, now=None):
    """One transaction commits evidence, duplicate identities, queue and cursor.

    The archived bytes precede the commit; a crash can leave an unreferenced
    archive but never a committed cursor without its evidence and queue.
    """
    scope = identifier(scope)
    if kind not in ('synthetic','private_host'):
        raise ValueError('kind must be synthetic or private_host')
    workspace, source = Path(workspace).resolve(), Path(source).resolve()
    if kind == 'private_host' and not private_path(workspace):
        raise ValueError('private host workspace must stay under data/local or the private LOCALAPPDATA live cache')
    if source.stat().st_size > 16000000:
        raise ValueError('batch exceeds 16 MB')
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    # The same exact file is never reinterpreted under another scope/kind.
    records=[]
    for line, value in enumerate(raw.decode('utf-8-sig').splitlines(),1):
        if not value.strip(): continue
        if len(records) >= 500: raise ValueError('batch exceeds 500 records')
        obj=json.loads(value); event=normalize_event(obj,digest,line)
        identity={k:event[k] for k in ('host','channel','provider','timestamp','event_id','record_id','event_data')}
        if 'original_xml' in obj: identity['original_xml']=obj['original_xml']
        fingerprint=hashlib.sha256(canonical([scope,kind,identity])).hexdigest()
        records.append((event,fingerprint))
    if not records: raise ValueError('batch contains no records')
    now=time.time() if now is None else now
    with closing(connect(workspace)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        existing_kind=conn.execute('SELECT kind FROM batches WHERE scope=? LIMIT 1',(scope,)).fetchone()
        if existing_kind and existing_kind[0]!=kind:
            raise ValueError('a collection cannot mix private host and synthetic evidence')
        previous=conn.execute('SELECT * FROM batches WHERE sha256=?',(digest,)).fetchone()
        if previous:
            if previous['scope']!=scope or previous['kind']!=kind:
                raise ValueError('source batch already belongs to another collection')
            return {'accepted':0,'duplicates':len(records),'already_imported':True,'source_sha256':digest}
        accepted=[(e,f) for e,f in records if not conn.execute('SELECT 1 FROM observations WHERE fingerprint=?',(f,)).fetchone()]
        # Duplicate observations inside this same batch must also be excluded.
        unique={f:e for e,f in reversed(accepted)}
        accepted=[(e,f) for f,e in unique.items()]
        queued=conn.execute("SELECT count(*) FROM outbox WHERE state!='delivered'").fetchone()[0]
        count=conn.execute('SELECT count(*) FROM events').fetchone()[0]
        stored_bytes=sum(p.stat().st_size for p in workspace.rglob('*') if p.is_file())
        if queued+len(accepted)>LIMIT_QUEUE or count+len(accepted)>LIMIT_EVENTS or stored_bytes+len(raw)*4>LIMIT_STORAGE:
            raise ValueError('capacity reached; cursor unchanged, retain and investigate backlog')
        archive=workspace/'archive'/f'{digest}.jsonl'; archive.parent.mkdir(parents=True,exist_ok=True)
        if not archive.exists():
            with archive.open('xb') as stream:
                stream.write(raw); stream.flush()
                import os
                os.fsync(stream.fileno())
        elif hashlib.sha256(archive.read_bytes()).hexdigest()!=digest:
            raise ValueError('archived batch hash mismatch')
        conn.execute('INSERT INTO sources VALUES (?,?,?)',(digest,str(archive),len(accepted)))
        for offset,(event,fingerprint) in enumerate(accepted):
            stored={**event,'event_data':canonical(event['event_data']).decode()}
            conn.execute(f"INSERT INTO events ({','.join(stored)}) VALUES ({','.join('?' for _ in stored)})",tuple(stored.values()))
            conn.execute('INSERT INTO observations VALUES (?,?,?,?,?)',(fingerprint,event['event_uid'],scope,kind,now))
            payload=flatten(event); payload['collection_kind']=kind; payload['scope']=scope
            payload['received_at']=datetime.fromtimestamp(now,timezone.utc).isoformat()
            # Arrival timestamp is persisted before delivery and remains stable on retry.
            stamp=str(int(now*1_000_000_000)+offset*1000)
            conn.execute('INSERT INTO outbox(event_uid,scope,kind,stamp,payload,state,next_attempt) VALUES (?,?,?,?,?,?,?)',
                         (event['event_uid'],scope,kind,stamp,canonical(payload).decode(),'held_private' if kind=='private_host' else 'pending',now))
        duplicates=len(records)-len(accepted)
        conn.execute('INSERT INTO batches VALUES (?,?,?,?,?,?)',(digest,scope,kind,len(accepted),duplicates,now))
        if cursor is not None:
            conn.execute('INSERT INTO collectors(scope,cursor,updated,gap_count) VALUES (?,?,?,?) ON CONFLICT(scope) DO UPDATE SET cursor=excluded.cursor,updated=excluded.updated,gap_count=collectors.gap_count+excluded.gap_count,last_error=NULL',
                         (scope,canonical(cursor).decode(),now,int(bool(gap))))
    return {'accepted':len(accepted),'duplicates':duplicates,'already_imported':False,'source_sha256':digest}


def collector_state(workspace, scope):
    with closing(connect(workspace)) as conn:
        row=conn.execute('SELECT * FROM collectors WHERE scope=?',(scope,)).fetchone()
        return {**dict(row),'cursor':json.loads(row['cursor'])} if row else None


def collector_heartbeat(workspace, scope, cursor, *, error=None, gap=False):
    with closing(connect(workspace)) as conn, conn:
        conn.execute('INSERT INTO collectors VALUES (?,?,?,?,?) ON CONFLICT(scope) DO UPDATE SET cursor=excluded.cursor,updated=excluded.updated,gap_count=collectors.gap_count+excluded.gap_count,last_error=excluded.last_error',
                     (scope,canonical(cursor).decode(),time.time(),int(gap),error))


def drain(workspace, *, client=None, now=None, batch_size=100):
    if not 1<=batch_size<=250: raise ValueError('delivery batch must be 1..250')
    client=client or Loki(timeout=10)
    now=time.time() if now is None else now
    token=uuid.uuid4().hex
    with closing(connect(workspace)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute("UPDATE outbox SET state='pending',lease_token=NULL,lease_until=NULL WHERE state='sending' AND lease_until<=?",(now,))
        first=conn.execute("SELECT scope,kind FROM outbox WHERE state='pending' AND next_attempt<=? ORDER BY next_attempt,event_uid LIMIT 1",(now,)).fetchone()
        if not first: return {'sent':0,'failed':0}
        rows=conn.execute("SELECT * FROM outbox WHERE state='pending' AND next_attempt<=? AND scope=? AND kind=? ORDER BY stamp,event_uid LIMIT ?",(now,first['scope'],first['kind'],batch_size)).fetchall()
        for row in rows:
            conn.execute("UPDATE outbox SET state='sending',lease_token=?,lease_until=? WHERE event_uid=?",(token,now+180,row['event_uid']))
    try:
        client.request('/loki/api/v1/push',{'streams':[{'stream':{'job':'soclab_live','scope':first['scope'],'kind':first['kind']},'values':[[r['stamp'],r['payload']] for r in rows]}]})
    except (ValueError,OSError) as exc:
        # Error responses may echo sensitive event content: retain only the class.
        with closing(connect(workspace)) as conn, conn:
            for row in rows:
                delay=min(300,2**min(row['attempts']+1,8))
                code=re.match(r'Loki HTTP (\d{3}):',str(exc))
                diagnostic='HTTP_'+code[1] if code else type(exc).__name__
                state='dead_letter' if row['attempts']+1>=8 else 'pending'
                conn.execute("UPDATE outbox SET state=?,attempts=attempts+1,next_attempt=?,lease_token=NULL,lease_until=NULL,error=? WHERE event_uid=? AND lease_token=?",(state,now+delay,diagnostic,row['event_uid'],token))
        return {'sent':0,'failed':len(rows),'error':type(exc).__name__}
    with closing(connect(workspace)) as conn, conn:
        changed=conn.execute("UPDATE outbox SET state='delivered',lease_token=NULL,lease_until=NULL,error=NULL WHERE lease_token=?",(token,)).rowcount
    return {'sent':changed,'failed':0,'delivery':'at-least-once; uncertain remote acceptance may repeat a record'}


def retry_now(workspace, *, actor, reason):
    actor,reason=text(actor,'actor',80),text(reason,'reason')
    with closing(connect(workspace)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        count=conn.execute("UPDATE outbox SET state='pending',attempts=0,next_attempt=? WHERE state IN ('pending','dead_letter')",(time.time(),)).rowcount
        conn.execute('INSERT INTO maintenance VALUES (?,?,?,?)',(time.time(),actor,reason,count))
    return {'rescheduled':count}


def _snapshot(row):
    result=dict(row); result['finding']=json.loads(result['finding']); return result


def _append(conn, snapshot, *, actor, reason, action):
    previous=conn.execute('SELECT sha256 FROM alert_audit WHERE alert_id=? ORDER BY sequence DESC LIMIT 1',(snapshot['id'],)).fetchone()
    previous=previous[0] if previous else '0'*64
    payload={'snapshot':snapshot,'actor':actor,'reason':reason,'action':action,'at':time.time()}
    digest=hashlib.sha256(previous.encode()+canonical(payload)).hexdigest()
    conn.execute('INSERT INTO alert_audit VALUES (?,?,?,?,?)',(snapshot['id'],snapshot['revision'],canonical(payload).decode(),previous,digest))


def _verified(conn, alert_id):
    row=conn.execute('SELECT * FROM alerts WHERE id=?',(alert_id,)).fetchone()
    if not row: raise ValueError('unknown alert')
    current=_snapshot(row); previous='0'*64; audit=[]
    for sequence,entry in enumerate(conn.execute('SELECT * FROM alert_audit WHERE alert_id=? ORDER BY sequence',(alert_id,)),1):
        payload=json.loads(entry['payload']); digest=hashlib.sha256(previous.encode()+canonical(payload)).hexdigest()
        if entry['sequence']!=sequence or entry['previous']!=previous or entry['sha256']!=digest: raise ValueError('alert audit integrity failed')
        previous=digest; audit.append({**dict(entry),'payload':payload})
    if not audit or len(audit)!=current['revision'] or audit[-1]['payload']['snapshot']!=current:
        raise ValueError('alert state differs from audit')
    return {'alert':current,'audit':audit,'anchor_sha256':previous}


def run_detection(workspace, *, scope, rules_path=None, now=None, window=600):
    scope=identifier(scope); rules_path=rules_path or ROOT/'rules/windows.json'
    if not 60<=window<=3600: raise ValueError('window must be 60..3600 seconds')
    rules=load_rules(rules_path); rule_hash=hashlib.sha256(canonical({'rules':rules,'auth_threshold':5,'window_seconds':window,'engine_version':'4.0.0'})).hexdigest()
    now=time.time() if now is None else now
    cutoff=datetime.fromtimestamp(now-window,timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    ceiling=datetime.fromtimestamp(now+120,timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    with closing(connect(workspace)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        rows=conn.execute('SELECT e.*,o.kind FROM events e JOIN observations o USING(event_uid) WHERE o.scope=? AND e.timestamp>=? AND e.timestamp<=? ORDER BY e.timestamp,e.event_uid LIMIT 10001',(scope,cutoff,ceiling)).fetchall()
        if len(rows)>10000: raise ValueError('detection window saturated; no partial evaluation claimed')
        events=[]
        for row in rows:
            event=dict(row); event['event_data']=json.loads(event['event_data']); events.append(event)
        inserted=0
        for finding in detect(events,rules,cross_source=True,window_seconds=window):
            alert_id=hashlib.sha256(canonical([scope,finding['finding_id'],rule_hash])).hexdigest()
            if conn.execute('SELECT 1 FROM alerts WHERE id=?',(alert_id,)).fetchone(): continue
            severity=finding['suggested_severity']; uid=finding['evidence'][0]['event_uid']
            kind=next(e['kind'] for e in events if e['event_uid']==uid)
            conn.execute('INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(alert_id,scope,kind,finding['rule_id'],severity,'new',1,None,None,now,now+SLA[severity],canonical(finding).decode(),rule_hash,None))
            current=_snapshot(conn.execute('SELECT * FROM alerts WHERE id=?',(alert_id,)).fetchone())
            _append(conn,current,actor='detection-worker',reason='Detection lead created; analyst verdict required.',action='detect')
            inserted+=1
        run_id=uuid.uuid4().hex
        conn.execute('INSERT INTO detection_runs VALUES (?,?,?,?,?,?)',(run_id,scope,now,len(events),inserted,rule_hash))
    return {'run_id':run_id,'inspected':len(events),'new_alerts':inserted,'rule_sha256':rule_hash,'window_seconds':window}


def alert_detail(workspace, alert_id):
    with closing(connect(workspace)) as conn:
        conn.execute('BEGIN'); return _verified(conn,alert_id)


def update_alert(workspace, alert_id, *, revision, actor, reason, target=None, owner=None, verdict=None):
    actor,reason=text(actor,'actor',80),text(reason,'reason')
    if type(revision) is not int: raise ValueError('revision must be an integer')
    if owner is not None: owner=text(owner,'owner',80)
    with closing(connect(workspace)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE'); current=_verified(conn,alert_id)['alert']
        if revision!=current['revision']: raise ValueError('revision conflict; reload alert')
        if current['state']=='closed': raise ValueError('closed alerts are immutable')
        if target is not None:
            if target not in STATES[current['state']]: raise ValueError('invalid alert transition')
            if target=='closed' and verdict not in ('expected_activity','insufficient_evidence','suspicious_activity'):
                raise ValueError('closure requires an explicit verdict')
            current['state']=target; current['verdict']=verdict if target=='closed' else None
        if owner is not None: current['owner']=owner
        current['revision']+=1
        conn.execute('UPDATE alerts SET state=?,revision=?,owner=?,verdict=? WHERE id=?',(current['state'],current['revision'],current['owner'],current['verdict'],alert_id))
        _append(conn,current,actor=actor,reason=reason,action='review')
    return current


def promote_case(workspace, alert_id, *, actor, reason):
    """Deterministic case identity permits recovery after cross-database commit."""
    from .operations import get_case, create_case
    workspace=Path(workspace).resolve(); actor=text(actor,'actor',80); reason=text(reason,'reason')
    with closing(connect(workspace)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE'); current=_verified(conn,alert_id)['alert']
        if current['case_id']: return {'case_id':current['case_id'],'already_linked':True}
        case_id=uuid.uuid5(uuid.NAMESPACE_URL,'soclab-live:'+alert_id).hex
        case_db=workspace/'cases.sqlite'
        try: existing=get_case(case_db,case_id)['case']
        except ValueError as exc:
            if str(exc)!='unknown operations case': raise
            existing=None
        uids=[e['event_uid'] for e in current['finding']['evidence']]
        if existing:
            if existing['source_case']!=current['scope'] or {e['event_uid'] for e in existing['evidence']}!=set(uids):
                raise ValueError('deterministic case identity conflicts with retained evidence')
        else:
            create_case(case_db,source_case=current['scope'],evidence_db=workspace/'live.sqlite',uids=uids,
                title=current['finding']['title'],severity=current['severity'],actor=actor,rationale=reason,case_id=case_id)
        current['case_id']=case_id; current['revision']+=1
        conn.execute('UPDATE alerts SET case_id=?,revision=? WHERE id=?',(case_id,current['revision'],alert_id))
        _append(conn,current,actor=actor,reason=reason,action='promote_case')
    return {'case_id':case_id,'already_linked':False}


def status(workspace, *, now=None):
    now=time.time() if now is None else now
    with closing(connect(workspace)) as conn:
        conn.execute('BEGIN')
        queues={r[0]:r[1] for r in conn.execute('SELECT state,count(*) FROM outbox GROUP BY state')}
        alerts={r[0]:r[1] for r in conn.execute('SELECT state,count(*) FROM alerts GROUP BY state')}
        oldest=conn.execute("SELECT min(o.received) FROM observations o JOIN outbox b USING(event_uid) WHERE b.state IN ('pending','sending','dead_letter')").fetchone()[0]
        collectors=[{**dict(r),'cursor':json.loads(r['cursor'])} for r in conn.execute('SELECT * FROM collectors')]
        for collector in collectors:
            collector['seconds_since_attempt']=max(0,now-collector['updated'])
            collector['health']='error' if collector['last_error'] else 'stale' if collector['seconds_since_attempt']>60 else 'healthy'
        runs=[dict(r) for r in conn.execute('SELECT * FROM detection_runs ORDER BY at DESC LIMIT 10')]
        return {'events':conn.execute('SELECT count(*) FROM events').fetchone()[0],
            'duplicates':conn.execute('SELECT coalesce(sum(duplicates),0) FROM batches').fetchone()[0],
            'queue':queues,'alerts':alerts,'oldest_pending_seconds':max(0,now-oldest) if oldest else 0,
            'overdue_alerts':conn.execute("SELECT count(*) FROM alerts WHERE state!='closed' AND due<?",(now,)).fetchone()[0],
            'collectors':collectors,'detection_runs':runs,'limits':{'events':LIMIT_EVENTS,'queue':LIMIT_QUEUE,'storage_admission_bytes':LIMIT_STORAGE},
            'privacy':'private_host records are held locally; this version does not enable their backend delivery',
            'database_bytes':sum(p.stat().st_size for p in Path(workspace).glob('live.sqlite*'))}


def list_alerts(workspace, *, state=None, limit=100):
    if not 1<=limit<=200 or state is not None and state not in STATES: raise ValueError('invalid alert filter')
    with closing(connect(workspace)) as conn:
        conn.execute('BEGIN')
        query='SELECT id FROM alerts'+(' WHERE state=?' if state else '')+' ORDER BY created DESC,id LIMIT ?'
        args=(state,limit) if state else (limit,)
        results=[]
        for row in conn.execute(query,args):
            alert=_verified(conn,row[0])['alert']
            # A queue listing needs metadata, not every retained script/XML field.
            # Full evidence is fetched only for an explicitly selected alert.
            alert['evidence_count']=len(alert['finding']['evidence'])
            alert['finding']={'title':alert['finding']['title']}
            results.append(alert)
        return results


def export_review(workspace,alert_id):
    """Retain both independent audited snapshots, including alert decisions."""
    import os
    from tempfile import TemporaryDirectory
    import zipfile
    from .operations import get_case, _export_files
    workspace=Path(workspace).resolve(); detail=alert_detail(workspace,alert_id); alert=detail['alert']
    if not alert['case_id']: raise ValueError('open an anchored case first')
    case=get_case(workspace/'cases.sqlite',alert['case_id'])
    files,_=_export_files(case); files['case-manifest.json']=files.pop('manifest.json')
    files['alert.json']=canonical(alert)+b'\n'; files['alert-audit.json']=canonical(detail['audit'])+b'\n'
    manifest={'format':'soclab-live-review-v1','alert_anchor':detail['anchor_sha256'],'case_anchor':case['anchor_sha256'],
              'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
              'scope':'Independent alert and case snapshots; relative integrity, self-declared actors, no digital signature'}
    files['manifest.json']=canonical(manifest)+b'\n'
    output_dir=workspace/'exports'; output_dir.mkdir(parents=True,exist_ok=True)
    output=output_dir/f"alert-{alert_id}-r{alert['revision']}-case-{alert['case_id']}-r{case['case']['revision']}.zip"
    if output.exists():
        try:
            with zipfile.ZipFile(output) as archive:
                if sorted(archive.namelist())!=sorted(files) or any(archive.read(k)!=v for k,v in files.items()):
                    raise ValueError('existing reviewed packet differs from audited snapshots')
        except zipfile.BadZipFile: raise ValueError('existing packet is incomplete') from None
    else:
        with TemporaryDirectory(prefix='.live-export-',dir=output_dir) as td:
            staged=Path(td)/'packet.zip'
            with zipfile.ZipFile(staged,'w') as archive:
                for name,raw in files.items():
                    info=zipfile.ZipInfo(name,(2026,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED
                    archive.writestr(info,raw)
            os.link(staged,output)
    return {'file':output.name,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'manifest':manifest}


def snapshot(workspace,output):
    """SQLite online backup plus immutable archives in an exclusive ZIP."""
    import os
    from tempfile import TemporaryDirectory
    import zipfile
    workspace,output=Path(workspace).resolve(),Path(output).resolve()
    if output.exists(): raise ValueError('snapshot destination already exists')
    if output.suffix!='.zip': raise ValueError('snapshot destination must be a ZIP')
    output.parent.mkdir(parents=True,exist_ok=True)
    with closing(connect(workspace)) as lock,lock:
        lock.execute('BEGIN IMMEDIATE')
        private=lock.execute("SELECT 1 FROM observations WHERE kind='private_host' LIMIT 1").fetchone()
        if private and not private_path(output):
            raise ValueError('private snapshot must stay under data/local or the private live cache')
        with TemporaryDirectory(prefix='.live-snapshot-',dir=output.parent) as td:
            td=Path(td); files={}
            for name in ('live.sqlite','cases.sqlite'):
                path=workspace/name
                if not path.exists(): continue
                with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as source,closing(sqlite3.connect(td/name)) as dest:
                    source.backup(dest)
                    if dest.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('snapshot database integrity failed')
                with (td/name).open('rb') as stream: files[name]=hashlib.file_digest(stream,'sha256').hexdigest()
            archives=[r[0] for r in lock.execute('SELECT sha256 FROM sources')]
            staged=td/'snapshot.zip'
            with zipfile.ZipFile(staged,'w',compression=zipfile.ZIP_DEFLATED) as archive:
                for name in tuple(files): archive.write(td/name,name)
                for digest in archives:
                    name=f'archive/{digest}.jsonl'; raw=(workspace/name).read_bytes()
                    if hashlib.sha256(raw).hexdigest()!=digest: raise ValueError('source archive diverged')
                    archive.writestr(name,raw); files[name]=digest
                archive.writestr('snapshot-manifest.json',canonical({'format':'soclab-live-snapshot-v1','files':files,'privacy':'private' if private else 'synthetic','at':time.time()}))
            os.link(staged,output)
    with output.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'file':output.name,'files':len(files),'sha256':digest}


def restore_snapshot(archive_path,workspace):
    import zipfile
    workspace=Path(workspace).resolve()
    if workspace.exists(): raise ValueError('restore requires a new workspace')
    with zipfile.ZipFile(archive_path) as archive:
        if sum(i.file_size for i in archive.infolist())>1024*1024*1024: raise ValueError('snapshot expands beyond 1 GiB')
        manifest=json.loads(archive.read('snapshot-manifest.json'))
        if manifest.get('format')!='soclab-live-snapshot-v1': raise ValueError('unsupported snapshot')
        if manifest['privacy']=='private' and not private_path(workspace):
            raise ValueError('private restore must stay under data/local or the private live cache')
        files=manifest['files']
        if sorted(archive.namelist())!=sorted([*files,'snapshot-manifest.json']) or 'live.sqlite' not in files: raise ValueError('snapshot inventory mismatch')
        for name,digest in files.items():
            if not re.fullmatch(r'(live|cases)\.sqlite|archive/[a-f0-9]{64}\.jsonl',name): raise ValueError('invalid snapshot path')
            with archive.open(name) as stream:
                if hashlib.file_digest(stream,'sha256').hexdigest()!=digest: raise ValueError('snapshot file hash mismatch')
        # All paths and bytes have passed validation before creating the target.
        workspace.mkdir(parents=True,exist_ok=False)
        for name in files:
            target=workspace/name;target.parent.mkdir(parents=True,exist_ok=True)
            with archive.open(name) as source,target.open('xb') as dest:
                import shutil
                shutil.copyfileobj(source,dest,65536)
    with closing(connect(workspace)) as conn,conn:
        if conn.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise ValueError('restored database integrity failed')
        for row in conn.execute('SELECT sha256 FROM sources').fetchall():
            conn.execute('UPDATE sources SET path=? WHERE sha256=?',(str(workspace/'archive'/f'{row[0]}.jsonl'),row[0]))
    return {'restored_files':len(files),'events':status(workspace)['events'],'note':'In-flight delivery leases expire normally; uncertain acceptance remains at-least-once.'}
