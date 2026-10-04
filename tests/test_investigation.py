"""Regression tests for incorrect evidence joins and measurable evaluation errors."""

from copy import deepcopy
import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from soclab.corpus import evaluate, metrics, normalize_scenario, sample_events, scenarios
from soclab.events import normalize_event
from soclab.investigation import guid, investigate, risk_reason, write_investigation
from soclab.store import ingest, iter_events, sources
from soclab.webapp import build_handler

ROOT=Path(__file__).resolve().parents[1]


class InvestigationTests(unittest.TestCase):
    def run_records(self,records):
        events,scope=normalize_scenario(records)
        return investigate(events,scope)

    def test_complete_chain_keeps_five_stages_and_exact_guid_edges(self):
        result=self.run_records(sample_events())
        self.assertEqual(len(result['chains']),1)
        self.assertEqual(len(result['chains'][0]['stages']),5)
        self.assertEqual(len(result['nodes']),3)
        self.assertEqual(len(result['edges']),2)
        self.assertEqual(result['verdict'],'unassessed; correlation creates review leads')

    def test_isolation_and_missing_telemetry_variants_do_not_create_full_chain(self):
        for case in scenarios():
            if case['variant'] in ('complete','powershell','reordered','duplicate','authorized-admin'):continue
            with self.subTest(case=case['id']):self.assertEqual(self.run_records(case['events'])['chains'],[])

    def test_unknown_or_omitted_approved_source_rejects_analysis(self):
        events,scope=normalize_scenario(sample_events())
        scope['source_sha256']=scope['source_sha256'][:-1]
        with self.assertRaises(ValueError):investigate(events,scope)
        scope['source_sha256'].append('f'*64)
        with self.assertRaises(ValueError):investigate(events,scope)

    def test_requires_explicit_reason_and_valid_unique_source_hashes(self):
        events,scope=normalize_scenario(sample_events())
        for broken in ([],{**scope,'collection_reason':42},{**scope,'collection_reason':''},{**scope,'source_sha256':[{}]},{**scope,'source_sha256':['bad']},{**scope,'source_sha256':scope['source_sha256']*2}):
            with self.assertRaises(ValueError):investigate(events,broken)

    def test_overlapping_exports_keep_aliases_without_inflating_failure_count(self):
        records=sample_events();events,scope=normalize_scenario(records)
        copied=[normalize_event(e,'a'*64,i+1) for i,e in enumerate(records)]
        result=investigate(events+copied,{**scope,'source_sha256':scope['source_sha256']+['a'*64]})
        self.assertEqual(result['duplicate_observations'],len(records))
        self.assertEqual(len(result['chains']),1)
        self.assertEqual(result['candidates'][0]['failure_count'],5)
        self.assertTrue(all(len(n['evidence'])==2 for n in result['nodes']))

    def test_changed_content_with_same_record_id_is_not_deduplicated(self):
        records=sample_events();altered=deepcopy(records[7]);altered['event_data']['CommandLine']='mshta.exe other'
        result=self.run_records(records+[altered])
        self.assertEqual(result['duplicate_observations'],0)
        self.assertEqual(result['chains'],[])
        self.assertTrue(any(d['code']=='conflicting_process_creation' for d in result['diagnostics']))

    def test_pid_reuse_without_guid_never_joins_activity(self):
        records=sample_events();records[8]['event_data'].pop('ProcessGuid');records[8]['event_data']['ProcessId']='4001'
        self.assertEqual(self.run_records(records)['chains'],[])

    def test_parent_in_future_cannot_establish_task_ancestry(self):
        records=sample_events();records[7]['timestamp']='2026-09-03T10:00:20Z'
        result=self.run_records(records)
        self.assertEqual(result['chains'],[])
        self.assertTrue(any(d['code']=='invalid_parent_order_or_cycle' for d in result['diagnostics']))

    def test_self_parent_is_rejected(self):
        records=sample_events();records[9]['event_data']['ParentProcessGuid']=records[9]['event_data']['ProcessGuid']
        self.assertEqual(self.run_records(records)['chains'],[])

    def test_cycle_at_equal_timestamps_is_rejected(self):
        records=sample_events()
        for e in (records[6],records[7]):e['timestamp']='2026-09-03T10:00:07Z'
        records[6]['event_data']['ParentProcessGuid']=records[7]['event_data']['ProcessGuid']
        result=self.run_records(records)
        self.assertTrue(any(d['code']=='invalid_parent_order_or_cycle' for d in result['diagnostics']))

    def test_initiated_false_does_not_establish_outbound_stage(self):
        records=sample_events();records[8]['event_data']['Initiated']='false'
        self.assertEqual(self.run_records(records)['chains'],[])

    def test_unavailable_guid_values_do_not_link_sessions(self):
        for value in ('','-','not-a-guid','{00000000-0000-0000-0000-000000000000}'):
            with self.subTest(value=value):self.assertIsNone(guid(value))

    def test_script_arguments_and_quoted_switches_do_not_become_host_switches(self):
        records=sample_events();e=records[7]
        e['event_data']['Image']='powershell.exe'
        for text in ('powershell.exe -File backup.ps1 -EncodedCommand inert','powershell.exe -Command "Write-Output -EncodedCommand"','powershell.exe "-EncodedCommand"'):
            e['event_data']['CommandLine']=text
            with self.subTest(text=text):self.assertIsNone(risk_reason(e))
        e['event_data']['CommandLine']='powershell.exe -NoProfile -enc inert'
        self.assertIsNotNone(risk_reason(e))

    def test_failure_threshold_counts_unique_observations(self):
        records=sample_events();records=[e for e in records if e['record_id']!=100];records.append(deepcopy(records[0]))
        self.assertEqual(self.run_records(records)['chains'],[])

    def test_partial_chain_lists_missing_collection_requirements(self):
        case=next(c for c in scenarios() if c['variant']=='no-network')
        result=self.run_records(case['events'])
        self.assertFalse(result['candidates'][0]['complete'])
        self.assertIn('initiated network activity for the risky process',result['candidates'][0]['missing'])

    def test_metrics_include_real_misses_and_undefined_denominators(self):
        r=evaluate()
        self.assertEqual(r['metrics']['holdout']['identity_graph'],{'tp':2,'fp':1,'tn':3,'fn':2,'precision':2/3,'recall':.5,'f1':4/7})
        self.assertEqual(metrics([],'predicted_review')['precision'],None)
        self.assertEqual(len({row['id'] for row in r['rows']}),20)

    def test_corpus_modified_label_requires_resealed_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for p in (ROOT/'data/corpus').glob('*.json'):(root/p.name).write_bytes(p.read_bytes())
            p=root/'H01.json';case=json.loads(p.read_text());case['expected_review']=False;p.write_text(json.dumps(case))
            with self.assertRaises(ValueError):evaluate(root)

    def test_existing_investigation_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'result.json';target.write_text('preserve')
            with self.assertRaises(ValueError):write_investigation(Path('absent'),Path('absent'),target)
            self.assertEqual(target.read_text(),'preserve')

    def test_original_event_endpoint_is_scoped_and_returns_complete_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);db=root/'test.sqlite';ingest(ROOT/'data/fixtures/demo.jsonl',db)
            event=next(iter_events(db));index=root/'index.json'
            index.write_text(json.dumps({'run_id':'test','note':'test','cases':[{'id':'test','db':str(db)}]}))
            server=ThreadingHTTPServer(('127.0.0.1',0),build_handler(index));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                base=f'http://127.0.0.1:{server.server_port}'
                with urlopen(base+'/api/event?case=test&uid='+event['event_uid']) as response:r=json.load(response)
                self.assertEqual(r['original'],json.loads(event['original_json']))
                self.assertEqual(r['source_line'],event['source_line'])
                for query in ('case=other&uid='+event['event_uid'],'case=test&uid='+'a'*64,'case=test&uid=invalid'):
                    with self.assertRaises(HTTPError):urlopen(base+'/api/event?'+query)
            finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
