"""Adversarial review: coherent snapshots, failed writes and telemetry boundaries."""
from contextlib import closing
from copy import deepcopy
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from soclab import operations
from soclab.corpus import normalize_scenario, sample_events
from soclab.hunting import run_hunts
from soclab.investigation import scoped_events
from soclab.loki import Loki
from soclab.store import ingest, iter_events
from soclab.webapp import build_handler

ROOT = Path(__file__).resolve().parents[1]


class QualityReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db, self.workspace = self.root/'events.sqlite', self.root/'cases.sqlite'
        ingest(ROOT/'data/fixtures/demo.jsonl', self.db)
        self.uid = next(iter_events(self.db))['event_uid']

    def create(self):
        return operations.create_case(self.workspace, source_case='fixture', evidence_db=self.db,
            uids=[self.uid], title='Quality review fixture', actor='test', rationale='Inert review exercise.')

    def server(self, handler):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.handle_error = lambda *args: None
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, f'http://127.0.0.1:{server.server_port}'

    def test_case_and_audit_remain_one_snapshot_across_a_committed_update(self):
        case = self.create()
        with closing(sqlite3.connect(self.workspace)) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
        original = operations._audit
        interleaved = False
        def read_audit(conn, case_id):
            nonlocal interleaved
            if not interleaved:
                interleaved = True
                # Another connection commits exactly between the two reads.
                operations.update_case(self.workspace, case_id, revision=1, action='note',
                    actor='other-reader', rationale='A real interleaved committed decision.')
            return original(conn, case_id)
        with patch.object(operations, '_audit', side_effect=read_audit):
            result = operations.get_case(self.workspace, case['id'])
        self.assertEqual(result['case'], result['audit'][-1]['payload']['snapshot'])
        self.assertEqual(result['case']['revision'], len(result['audit']))
        self.assertEqual(operations.get_case(self.workspace, case['id'])['case']['revision'], 2)

    def test_failed_export_does_not_reserve_revision_or_leave_a_partial_zip(self):
        case = self.create()
        with patch.object(zipfile.ZipFile, 'writestr', side_effect=OSError('Injected write failure')):
            with self.assertRaises(OSError):
                operations.export_case(self.workspace, case['id'], self.root/'exports')
        self.assertEqual(list((self.root/'exports').iterdir()), [])
        result = operations.export_case(self.workspace, case['id'], self.root/'exports')
        with zipfile.ZipFile(self.root/'exports'/result['file']) as archive:
            self.assertEqual(archive.testzip(), None)

    def test_case_board_refuses_tampered_state(self):
        self.create()
        with closing(sqlite3.connect(self.workspace)) as conn, conn:
            conn.execute("UPDATE cases SET title='Altered outside the audit'")
        with self.assertRaisesRegex(ValueError, 'state'):
            operations.list_cases(self.workspace)

    def test_reviewed_download_can_be_restored_but_modified_content_is_rejected(self):
        case = self.create()
        exported = operations.export_case(self.workspace, case['id'], self.root/'exports')
        snapshot = operations.get_case(self.workspace, case['id'])
        self.assertEqual(operations.reviewed_export(snapshot, self.root/'exports'), exported)
        output = self.root/'exports'/exported['file']
        with zipfile.ZipFile(output) as archive:
            contents = {name:archive.read(name) for name in archive.namelist()}
        contents['report.md'] = b'Changed review rationale'
        with zipfile.ZipFile(output, 'w') as archive:
            for name, data in contents.items(): archive.writestr(name, data)
        with self.assertRaisesRegex(ValueError, 'audited revision'):
            operations.reviewed_export(snapshot, self.root/'exports')

    def test_checksum_inventory_rejects_new_unlisted_evidence(self):
        from scripts.verify_checksums import verify
        folder = self.root/'evidence'; folder.mkdir()
        (folder/'record.txt').write_bytes(b'Checked artifact\n')
        (folder/'checksums.json').write_text(json.dumps({'files':{
            'evidence/record.txt':hashlib.sha256(b'Checked artifact\n').hexdigest()}}))
        self.assertEqual(verify(self.root), 1)
        (folder/'unchecked.txt').write_text('An unreviewed artifact')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            verify(self.root)

    def test_wrong_channels_cannot_supply_windows_hunt_evidence(self):
        events, _ = normalize_scenario(sample_events())
        records = []
        for event in events:
            record = json.loads(event['original_json'])
            record['channel'] = 'Unrelated/Operational'
            records.append(record)
        # Event 1102 belongs to the Microsoft-Windows-Eventlog provider.
        records.append({'timestamp':'2026-09-03T11:00:00Z','host':'LAB', 'provider':'Unrelated',
            'channel':'Security','event_id':1102,'record_id':999,'event_data':{}})
        source = self.root/'wrong-channel.jsonl'
        source.write_text(''.join(json.dumps(r)+'\n' for r in records), encoding='utf-8')
        db = self.root/'wrong-channel.sqlite'
        ingest(source, db)
        self.assertTrue(all(not h['rows'] for h in run_hunts(db)['hunts']))

    def test_graph_limit_stops_reading_an_oversized_iterable(self):
        events, scope = normalize_scenario(sample_events())
        def oversized():
            for number in range(100002):
                if number == 100001:
                    self.fail('Input was consumed past the bounded overflow record')
                yield events[0]
        with self.assertRaisesRegex(ValueError, '100000'):
            scoped_events(oversized(), scope)

    def test_http_rejects_non_ascii_csrf_and_duplicate_host_without_disconnect(self):
        index = self.root/'index.json'
        index.write_text(json.dumps({'cases':[{'id':'fixture','db':str(self.db)}]}))
        server, origin = self.server(build_handler(index, self.workspace))
        request = Request(origin+'/api/operations/create', data=b'{}', headers={
            'Origin':origin,'Content-Type':'application/json','X-SOC-CSRF':'bad\u00e9'})
        with self.assertRaises(HTTPError) as error:
            urlopen(request)
        self.assertEqual(error.exception.code, 403)
        conn = HTTPConnection('127.0.0.1', server.server_port)
        self.addCleanup(conn.close)
        conn.putrequest('GET','/api/operations',skip_host=True)
        conn.putheader('Host', f'127.0.0.1:{server.server_port}')
        conn.putheader('Host', 'unrelated.invalid')
        conn.endheaders()
        response = conn.getresponse()
        self.assertEqual(response.status, 403)
        response.read()

    def test_loki_does_not_follow_backend_redirects(self):
        received = []
        class Destination(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                received.append(self.path)
                self.send_response(200); self.end_headers(); self.wfile.write(b'{}')
        _, destination = self.server(Destination)
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                self.send_response(302); self.send_header('Location', destination+'/unexpected')
                self.end_headers()
        _, origin = self.server(Redirect)
        with self.assertRaisesRegex(ValueError, '302'):
            Loki(origin).query('{job="soclab"}', 0)
        self.assertEqual(received, [])
