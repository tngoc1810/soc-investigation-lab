"""Exercise ingestion, a real HTTP outage, restart, case export and recovery.

Only constructed data is used. --backend additionally checks actual local Loki.
"""
import argparse
from contextlib import closing
from datetime import datetime,timezone
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from soclab import live
from soclab.loki import Loki


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-id',default='live-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    parser.add_argument('--backend',action='store_true')
    parser.add_argument('--out',type=Path,default=Path('output/live-validation.json'))
    args=parser.parse_args();live.identifier(args.run_id)
    workspace=ROOT/'output/live'/args.run_id
    if workspace.exists() or args.out.exists():raise ValueError('choose a fresh run ID and output artifact')
    inputs=workspace.parent/(args.run_id+'-inputs');inputs.mkdir(parents=True,exist_ok=False)
    records=[json.loads(x) for x in (ROOT/'data/fixtures/demo.jsonl').read_text(encoding='utf-8').splitlines()]
    end=max(datetime.fromisoformat(r['timestamp'].replace('Z','+00:00')).timestamp() for r in records)
    now=time.time();scope='demo-'+args.run_id
    for r in records:
        stamp=datetime.fromisoformat(r['timestamp'].replace('Z','+00:00')).timestamp()
        r['provenance']['original_fixture_timestamp']=r['timestamp']
        r['provenance']['note']='Constructed operational exercise; timestamp shifted for the live window. No attack command executed.'
        r['timestamp']=datetime.fromtimestamp(now-5+stamp-end,timezone.utc).isoformat()
    batches=[]
    for number,subset in enumerate((records[:5],records[5:])):
        path=inputs/f'batch-{number}.jsonl';path.write_text(''.join(json.dumps(r)+'\n' for r in subset),encoding='utf-8',newline='\n')
        batches.append(live.ingest_batch(workspace,path,scope=scope,now=now+number*.001))
        result=live.run_detection(workspace,scope=scope,now=now)
        if number==0:assert result['new_alerts']==0
        else:assert result['new_alerts']==8
    repeat=inputs/'overlap.jsonl';overlap={**records[0],'poll_note':'later overlapping read'}
    repeat.write_text(json.dumps(overlap)+'\n',encoding='utf-8',newline='\n')
    assert live.ingest_batch(workspace,repeat,scope=scope)['duplicates']==1
    assert live.run_detection(workspace,scope=scope,now=now)['new_alerts']==0
    class Offline(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(503);self.end_headers()
    server=ThreadingHTTPServer(('127.0.0.1',0),Offline);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:failed=live.drain(workspace,client=Loki(f'http://127.0.0.1:{server.server_port}',timeout=1))
    finally:server.shutdown();server.server_close();thread.join()
    assert failed['failed']==19
    restart=subprocess.run([sys.executable,'-m','soclab','live','status','--workspace',str(workspace)],cwd=ROOT,capture_output=True,check=True)
    resumed=json.loads(restart.stdout);assert resumed['queue']=={'pending':19}
    with closing(live.connect(workspace)) as conn:
        persisted={r['event_uid']:[r['stamp'],r['payload']] for r in conn.execute('SELECT * FROM outbox')}
    auth=next(a for a in live.list_alerts(workspace) if a['rule_id']=='AUTH-001')
    reasons=(('triaged','Same host/domain/account/source and logon type; failures plus success require context review.'),
             ('investigating','Six original records support the authentication sequence. Password mistakes and stale service credentials remain alternatives.'),
             ('escalated','Escalation exercise: request endpoint/process context and account-owner verification. No compromise or containment is established.'))
    revision=1
    for target,reason in reasons:
        current=live.update_alert(workspace,auth['id'],revision=revision,actor='exercise-analyst',owner='exercise-analyst',reason=reason,target=target);revision=current['revision']
    linked=live.promote_case(workspace,auth['id'],actor='exercise-analyst',reason='Retain the six constructed authentication records and the review history.')
    exported=live.export_review(workspace,auth['id'])
    with zipfile.ZipFile(workspace/'exports'/exported['file']) as z:
        manifest=json.loads(z.read('manifest.json'))
        for name,digest in manifest['files'].items():assert hashlib.sha256(z.read(name)).hexdigest()==digest
        assert len(json.loads(z.read('alert-audit.json')))==5
    snapshot=workspace.parent/(args.run_id+'-snapshot.zip');backed_up=live.snapshot(workspace,snapshot)
    restored=workspace.parent/(args.run_id+'-restored');restored_result=live.restore_snapshot(snapshot,restored)
    assert live.status(restored)['queue']=={'pending':19}
    assert live.alert_detail(restored,auth['id'])==live.alert_detail(workspace,auth['id'])
    captured=[]
    class Accepted:
        def request(self,path,payload):captured.append(payload);return {'status':'accepted-test-double'}
    live.retry_now(workspace,actor='exercise-operator',reason='HTTP outage exercise ended; destination ready for redrive.')
    recovered=live.drain(workspace,client=Loki(timeout=10) if args.backend else Accepted())
    assert recovered['sent']==19
    with closing(live.connect(workspace)) as conn:
        after={r['event_uid']:[r['stamp'],r['payload']] for r in conn.execute('SELECT * FROM outbox')}
    assert persisted==after
    backend=None
    if args.backend:
        client=Loki();client.request('/flush',{})
        begin=min(int(v[0]) for v in persisted.values())-1_000_000_000
        finish=max(int(v[0]) for v in persisted.values())+1_000_000_000
        expression='{job="soclab_live",scope='+json.dumps(scope)+',kind="synthetic"}'
        for attempt in range(40):
            response=client.logs(expression,begin,finish,limit=100)
            values=[v for stream in response['data']['result'] for v in stream['values']]
            if len(values)==19:break
            time.sleep(.5)
        assert len(values)==19
        found={json.loads(v[1])['event_uid'] for v in values};assert found==set(persisted)
        backend={'version':client.request('/loki/api/v1/status/buildinfo'),'query':expression,'start_ns':begin,'end_ns':finish,'observed':len(values),'all_19_uids_match':True,'response':response}
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'soclab').glob('*.py')}
    from soclab import __version__
    record={'version':__version__,'validated_at':datetime.now(timezone.utc).isoformat(),'run_id':args.run_id,'workspace':workspace.relative_to(ROOT).as_posix(),
            'batches':batches,'events':19,'overlap_duplicates':1,'new_alerts':8,'authentication_anchors':6,
            'outage':{'method':'Actual localhost HTTP 503 server','pending_after_failure':19,'fresh_process_confirmed_pending':19},
            'recovery':{'sent':19,'exact_persisted_payload_and_timestamp_preserved':True,'destination':'actual local Loki' if args.backend else 'in-process acceptance test double'},
            'snapshot':backed_up,'restore':restored_result,'case':linked,'packet':exported,'alert_anchor':live.alert_detail(workspace,auth['id'])['anchor_sha256'],
            'backend':backend,'source_hashes':hashes,'scope':'Constructed data and a simulated HTTP outage. Actual backend results only when --backend is present. No attack commands, private telemetry or containment actions.'}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(record,indent=2,ensure_ascii=False)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'workspace':record['workspace'],'events':19,'alerts':8,'pending_after_restart':19,'delivered':19,'actual_backend':bool(backend),'packet':exported['file'],'artifact':str(args.out)},indent=2))


if __name__=='__main__':main()
