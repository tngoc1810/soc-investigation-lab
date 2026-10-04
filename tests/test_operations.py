import hashlib
from contextlib import closing
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import zipfile

from soclab.operations import create_case, update_case, get_case, export_case
from soclab.store import ingest, iter_events
from soclab.webapp import build_handler

ROOT = Path(__file__).resolve().parents[1]


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db, self.workspace = self.root/"events.sqlite", self.root/"operations.sqlite"
        ingest(ROOT/"data/fixtures/demo.jsonl", self.db)
        self.uid = next(iter_events(self.db))["event_uid"]

    def tearDown(self):
        self.temp.cleanup()

    def create(self):
        return create_case(self.workspace, source_case="fixture", evidence_db=self.db, uids=[self.uid], title="Test analyst decision", rationale="Constructed exercise; no endpoint action.")

    def move(self, case, target, **kwargs):
        return update_case(self.workspace, case["id"], revision=case["revision"], action="transition", target=target, actor="test-analyst", rationale="Evidence reviewed within this fixture.", **kwargs)

    def test_illegal_transition_and_closure_need_verdict(self):
        case = self.create()
        with self.assertRaisesRegex(ValueError, "transition"): self.move(case, "closed")
        case = self.move(self.move(case, "triaged"), "investigating")
        with self.assertRaisesRegex(ValueError, "verdict"): self.move(case, "closed")
        case = self.move(case, "closed", verdict="insufficient_evidence")
        self.assertEqual(case["revision"], 4)
        with self.assertRaisesRegex(ValueError, "transition"): self.move(case, "investigating")

    def test_stale_revision_does_not_overwrite(self):
        case = self.create()
        self.move(case, "triaged")
        with self.assertRaisesRegex(ValueError, "conflict"): self.move(case, "triaged")
        self.assertEqual(get_case(self.workspace, case["id"])["case"]["revision"], 2)

    def test_unknown_evidence_cannot_be_attached(self):
        with self.assertRaisesRegex(ValueError, "belong"):
            create_case(self.workspace, source_case="fixture", evidence_db=self.db, uids=["f"*64], title="Wrong scope", rationale="Must fail.")

    def test_audit_edit_and_state_edit_detected(self):
        case = self.create()
        with closing(sqlite3.connect(self.workspace)) as conn, conn:
            conn.execute("UPDATE audit SET payload=replace(payload,'Constructed','Fabricated')")
        with self.assertRaisesRegex(ValueError, "integrity"): get_case(self.workspace, case["id"])
        with self.assertRaisesRegex(ValueError, "integrity"): self.move(case, "triaged")

    def test_tail_truncation_and_case_edit_detected(self):
        case = self.move(self.create(), "triaged")
        with closing(sqlite3.connect(self.workspace)) as conn, conn: conn.execute("DELETE FROM audit WHERE sequence=2")
        with self.assertRaisesRegex(ValueError, "state"): get_case(self.workspace, case["id"])

    def test_export_is_verifiable_and_immutable(self):
        case = self.move(self.create(), "triaged")
        result = export_case(self.workspace, case["id"], self.root/"exports")
        path = self.root/"exports"/result["file"]
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), result["sha256"])
        with zipfile.ZipFile(path) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            for name, digest in manifest["files"].items(): self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)
            self.assertEqual(json.loads(archive.read("evidence.jsonl"))["event_uid"], self.uid)
        with self.assertRaises(FileExistsError): export_case(self.workspace, case["id"], self.root/"exports")

    def test_additional_evidence_is_audited_and_cannot_remove_original(self):
        case = self.create()
        other = list(iter_events(self.db))[1]["event_uid"]
        case = update_case(self.workspace,case["id"],revision=1,action="attach",actor="test",rationale="Additional record reviewed.",evidence_db=self.db,uids=[other])
        self.assertEqual([e["event_uid"] for e in case["evidence"]],[self.uid,other])
        self.assertEqual(get_case(self.workspace,case["id"])["audit"][-1]["payload"]["action"],"attach")
        with self.assertRaisesRegex(ValueError,"already attached"):
            update_case(self.workspace,case["id"],revision=2,action="attach",actor="test",rationale="Duplicate.",evidence_db=self.db,uids=[other])

    def test_post_rejects_cross_origin_missing_token_and_large_body(self):
        index = self.root/"index.json"
        index.write_text(json.dumps({"cases":[{"id":"fixture", "db":str(self.db)}]}), encoding="utf-8")
        server = ThreadingHTTPServer(("127.0.0.1",0), build_handler(index, self.workspace))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(origin+"/api/operations") as response: token=json.load(response)["csrf"]
            for bad_origin, bad_token in (("http://attacker.invalid",token),(origin,"wrong"),("",token)):
                request=Request(origin+"/api/operations/create",data=b"{}",headers={"Origin":bad_origin,"Content-Type":"application/json","X-SOC-CSRF":bad_token})
                with self.assertRaises(HTTPError) as error: urlopen(request)
                self.assertEqual(error.exception.code,403)
            request=Request(origin+"/api/operations/create",data=b" "*65537,headers={"Origin":origin,"Content-Type":"application/json","X-SOC-CSRF":token})
            with self.assertRaises(HTTPError) as error: urlopen(request)
            self.assertEqual(error.exception.code,400)
            payload={"source_case":"fixture","uids":[self.uid],"title":"HTTP exercise","actor":"test","rationale":"Allowed local request."}
            request=Request(origin+"/api/operations/create",data=json.dumps(payload).encode(),headers={"Origin":origin,"Content-Type":"application/json","X-SOC-CSRF":token})
            with urlopen(request) as response: self.assertEqual(json.load(response)["status"],"new")
        finally:
            server.shutdown();server.server_close();thread.join()
