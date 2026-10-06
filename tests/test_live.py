"""Recovery and analyst invariants for the operational pilot."""
from contextlib import closing
from copy import deepcopy
from datetime import datetime,timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import subprocess
import time
import unittest
from unittest.mock import patch
from urllib.request import urlopen,Request
from urllib.error import HTTPError
import zipfile

from soclab import live,operations,collector
from soclab.liveweb import build_handler

class LiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.workspace=self.root/'workspace';self.now=time.time()
        self.records=[json.loads(x) for x in (live.ROOT/'data/fixtures/demo.jsonl').read_text(encoding='utf-8').splitlines()]
        end=max(datetime.fromisoformat(r['timestamp'].replace('Z','+00:00')).timestamp() for r in self.records)
        for r in self.records:
            old=datetime.fromisoformat(r['timestamp'].replace('Z','+00:00')).timestamp()
            r['timestamp']=datetime.fromtimestamp(self.now-10+old-end,timezone.utc).isoformat()
    def batch(self,records=None,scope='demo',name=None,**kwargs):
        records=self.records if records is None else records
        p=self.root/(name or ('batch-'+str(len(list(self.root.glob('*.jsonl'))))+'.jsonl'))
        p.write_text(''.join(json.dumps(r)+'\n' for r in records),encoding='utf-8')
        return live.ingest_batch(self.workspace,p,scope=scope,now=self.now,**kwargs)
    def alerts(self):
        self.batch();live.run_detection(self.workspace,scope='demo',now=self.now)
        return live.list_alerts(self.workspace)
    def test_cross_batch_auth_and_rerun_are_idempotent(self):
        self.batch(self.records[:5]);self.batch(self.records[5:])
        first=live.run_detection(self.workspace,scope='demo',now=self.now)
        self.assertEqual(first['new_alerts'],8)
        self.assertIn('AUTH-001',[a['rule_id'] for a in live.list_alerts(self.workspace)])
        self.assertEqual(live.run_detection(self.workspace,scope='demo',now=self.now)['new_alerts'],0)
    def test_overlap_dedup_and_changed_record_id_reuse(self):
        self.batch(self.records[:2]);r=deepcopy(self.records[1]);r['provenance']={'collected_at':'later'}
        result=self.batch([r]);self.assertEqual(result['duplicates'],1)
        r['timestamp']=datetime.fromtimestamp(self.now,timezone.utc).isoformat()
        self.assertEqual(self.batch([r])['accepted'],1)
        self.assertEqual(live.status(self.workspace)['events'],3)
    def test_scope_boundaries_never_join_independent_batches(self):
        self.batch(self.records[:5],scope='first');self.batch(self.records[5:],scope='second')
        for scope in ('first','second'):live.run_detection(self.workspace,scope=scope,now=self.now)
        self.assertNotIn('AUTH-001',[a['rule_id'] for a in live.list_alerts(self.workspace)])
    def test_capacity_failure_rolls_back_cursor_events_and_queue(self):
        self.batch(self.records[:1],cursor={'record_id':1})
        with patch.object(live,'LIMIT_QUEUE',1):
            with self.assertRaisesRegex(ValueError,'capacity'):self.batch(self.records[1:2],cursor={'record_id':2})
        self.assertEqual(live.collector_state(self.workspace,'demo')['cursor'],{'record_id':1})
        self.assertEqual(live.status(self.workspace)['events'],1)
    def test_invalid_later_event_cannot_commit_earlier_record(self):
        broken=deepcopy(self.records[1]);broken['timestamp']='no timezone'
        with self.assertRaises(ValueError):self.batch([self.records[0],broken])
        self.assertEqual(live.status(self.workspace)['events'],0)
    def test_durable_failed_delivery_and_restart_preserve_exact_payload(self):
        self.batch(self.records[:2])
        class Offline:
            def request(self,*args):raise ValueError('unavailable with private response body')
        self.assertEqual(live.drain(self.workspace,client=Offline(),now=self.now)['failed'],2)
        captured=[]
        class Online:
            def request(self,path,payload):captured.append(payload)
        self.assertEqual(live.drain(self.workspace,client=Online(),now=self.now+1)['sent'],0)
        with closing(live.connect(self.workspace)) as conn:before=[(r['stamp'],r['payload']) for r in conn.execute('SELECT * FROM outbox ORDER BY stamp')]
        self.assertEqual(live.drain(self.workspace,client=Online(),now=self.now+3)['sent'],2)
        self.assertEqual(captured[0]['streams'][0]['values'],[list(x) for x in before])
        self.assertEqual(live.status(self.workspace)['queue'],{'delivered':2})
    def test_abandoned_lease_recovers_only_after_expiration(self):
        self.batch(self.records[:1])
        with closing(live.connect(self.workspace)) as conn,conn:
            conn.execute("UPDATE outbox SET state='sending',lease_until=?,lease_token='crashed'",(self.now+10,))
        class Online:
            def request(self,*args):pass
        self.assertEqual(live.drain(self.workspace,client=Online(),now=self.now+9)['sent'],0)
        self.assertEqual(live.drain(self.workspace,client=Online(),now=self.now+11)['sent'],1)
    def test_dead_letter_retains_payload_and_audited_redrive(self):
        self.batch(self.records[:1])
        class Offline:
            def request(self,*args):raise ValueError('Loki HTTP 400: sensitive body must not be retained')
        for attempt in range(8):live.drain(self.workspace,client=Offline(),now=self.now+attempt*301)
        self.assertEqual(live.status(self.workspace)['queue'],{'dead_letter':1})
        with closing(live.connect(self.workspace)) as conn:
            row=conn.execute('SELECT payload,error FROM outbox').fetchone()
            self.assertEqual(row['error'],'HTTP_400');self.assertTrue(row['payload'])
        self.assertEqual(live.retry_now(self.workspace,actor='operator',reason='Destination repaired')['rescheduled'],1)
        with closing(live.connect(self.workspace)) as conn:self.assertEqual(conn.execute('SELECT count(*) FROM maintenance').fetchone()[0],1)
    def test_private_delivery_is_held_and_public_workspace_rejected(self):
        with self.assertRaisesRegex(ValueError,'data/local'):self.batch(self.records[:1],kind='private_host')
        # Simulate the private root without putting test fixtures on the real host.
        with patch.object(live,'ROOT',self.root):
            self.workspace=self.root/'data/local/test'
            self.batch(self.records[:1],kind='private_host')
            class Never:
                def request(self,*args):raise AssertionError('private records left their hold')
            self.assertEqual(live.drain(self.workspace,client=Never(),now=self.now+100)['sent'],0)
            self.assertEqual(live.status(self.workspace)['queue'],{'held_private':1})
    def test_review_revision_closure_owner_and_audit_tamper(self):
        a=self.alerts()[0]
        updated=live.update_alert(self.workspace,a['id'],revision=1,actor='analyst',reason='Verify original event first',target='triaged',owner='analyst')
        self.assertEqual(updated['owner'],'analyst')
        with self.assertRaisesRegex(ValueError,'revision conflict'):live.update_alert(self.workspace,a['id'],revision=1,actor='other',reason='stale')
        updated=live.update_alert(self.workspace,a['id'],revision=2,actor='analyst',reason='Investigate context',target='investigating')
        with self.assertRaisesRegex(ValueError,'verdict'):live.update_alert(self.workspace,a['id'],revision=3,actor='analyst',reason='close',target='closed')
        live.update_alert(self.workspace,a['id'],revision=3,actor='analyst',reason='Evidence incomplete',target='closed',verdict='insufficient_evidence')
        with self.assertRaisesRegex(ValueError,'immutable'):live.update_alert(self.workspace,a['id'],revision=4,actor='analyst',reason='rewrite')
        with closing(live.connect(self.workspace)) as conn,conn:conn.execute('UPDATE alerts SET owner=? WHERE id=?',('tampered',a['id']))
        with self.assertRaisesRegex(ValueError,'audit'):live.alert_detail(self.workspace,a['id'])
    def test_case_bridge_recovers_after_case_commit_before_link(self):
        a=self.alerts()[0];original=live._append
        def crash(conn,snapshot,**kwargs):
            if kwargs['action']=='promote_case':raise OSError('Crash after case committed')
            return original(conn,snapshot,**kwargs)
        with patch.object(live,'_append',side_effect=crash):
            with self.assertRaises(OSError):live.promote_case(self.workspace,a['id'],actor='analyst',reason='Retain evidence')
        self.assertIsNone(live.alert_detail(self.workspace,a['id'])['alert']['case_id'])
        self.assertEqual(len(operations.list_cases(self.workspace/'cases.sqlite')),1)
        result=live.promote_case(self.workspace,a['id'],actor='analyst',reason='Recover retained case link')
        self.assertEqual(len(operations.list_cases(self.workspace/'cases.sqlite')),1)
        self.assertEqual(live.promote_case(self.workspace,a['id'],actor='analyst',reason='Retry')['case_id'],result['case_id'])
    def test_export_contains_alert_decisions_and_rejects_modified_packet(self):
        a=self.alerts()[0];live.promote_case(self.workspace,a['id'],actor='analyst',reason='Record evidence')
        result=live.export_review(self.workspace,a['id']);self.assertEqual(live.export_review(self.workspace,a['id']),result)
        p=self.workspace/'exports'/result['file']
        with zipfile.ZipFile(p) as z:
            content={n:z.read(n) for n in z.namelist()};self.assertIn('alert-audit.json',content)
        content['alert.json']=b'changed'
        with zipfile.ZipFile(p,'w') as z:
            for name,raw in content.items():z.writestr(name,raw)
        with self.assertRaisesRegex(ValueError,'differs'):live.export_review(self.workspace,a['id'])
    def test_live_http_csrf_revision_conflict_and_metrics(self):
        a=self.alerts()[0];server=ThreadingHTTPServer(('127.0.0.1',0),build_handler(self.workspace))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(thread.join);self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        origin=f'http://127.0.0.1:{server.server_port}'
        with urlopen(origin+'/api/status') as r:csrf=json.load(r)['csrf']
        with urlopen(origin+'/api/alerts') as r:
            listing=json.load(r)
            self.assertTrue(all('evidence' not in item['finding'] for item in listing))
        with urlopen(origin+'/api/alert?id='+a['id']) as r:
            self.assertTrue(json.load(r)['alert']['finding']['evidence'])
        body=json.dumps({'id':a['id'],'revision':1,'actor':'http-analyst','reason':'Verified original record','target':'triaged'}).encode()
        with self.assertRaises(HTTPError) as err:urlopen(Request(origin+'/api/review',data=body,headers={'Content-Type':'application/json','Origin':origin}))
        self.assertEqual(err.exception.code,403)
        req=Request(origin+'/api/review',data=body,headers={'Content-Type':'application/json','Origin':origin,'X-SOC-CSRF':csrf})
        with urlopen(req) as r:self.assertEqual(r.status,200)
        with self.assertRaises(HTTPError) as err:urlopen(req)
        self.assertEqual(err.exception.code,409)
        with urlopen(origin+'/metrics') as r:metrics=r.read().decode()
        self.assertIn('soclab_events 19',metrics);self.assertNotIn('WS-LAB',metrics)
    def test_snapshot_restore_preserves_queue_audit_case_and_dedup(self):
        a=self.alerts()[0];live.promote_case(self.workspace,a['id'],actor='analyst',reason='Retain case')
        snapshot=self.root/'snapshot.zip';live.snapshot(self.workspace,snapshot)
        restored=self.root/'restored';live.restore_snapshot(snapshot,restored)
        self.assertEqual(live.status(restored)['queue'],{'pending':19})
        self.assertEqual(live.alert_detail(restored,a['id']),live.alert_detail(self.workspace,a['id']))
        self.assertEqual(len(operations.list_cases(restored/'cases.sqlite')),1)
        source=self.root/'duplicate.jsonl';source.write_text(''.join(json.dumps(r)+'\n' for r in self.records),encoding='utf-8')
        self.assertEqual(live.ingest_batch(restored,source,scope='demo')['accepted'],0)
        with self.assertRaisesRegex(ValueError,'already exists'):live.snapshot(self.workspace,snapshot)
    def test_restore_rejects_path_escape_before_creating_target(self):
        bad=self.root/'bad.zip'
        import hashlib
        with zipfile.ZipFile(bad,'w') as z:
            files={'live.sqlite':hashlib.sha256(b'fake').hexdigest(),'../escape.txt':hashlib.sha256(b'bad').hexdigest()}
            z.writestr('snapshot-manifest.json',json.dumps({'format':'soclab-live-snapshot-v1','privacy':'synthetic','files':files}))
            z.writestr('live.sqlite',b'fake');z.writestr('../escape.txt',b'bad')
        target=self.root/'restore'
        with self.assertRaisesRegex(ValueError,'path'):live.restore_snapshot(bad,target)
        self.assertFalse(target.exists());self.assertFalse((self.root/'escape.txt').exists())
    def test_native_timeout_preserves_cursor_and_reports_stale_or_error_health(self):
        import hashlib
        scope='windows-'+hashlib.sha256(b'System').hexdigest()[:12]
        workspace=self.root/'data/local/native'
        cursor={'record_id':77,'xml_sha256':'a'*64}
        live.collector_heartbeat(workspace,scope,cursor)
        self.assertEqual(live.status(workspace,now=time.time()+70)['collectors'][0]['health'],'stale')
        with patch.object(live,'ROOT',self.root),patch.object(collector,'native_available',return_value=True),patch.object(collector.subprocess,'run',side_effect=subprocess.TimeoutExpired('powershell',60)):
            with self.assertRaisesRegex(ValueError,'timed out'):collector.poll(workspace)
        state=live.collector_state(workspace,scope)
        self.assertEqual(state['cursor'],cursor)
        self.assertEqual(live.status(workspace)['collectors'][0]['health'],'error')
