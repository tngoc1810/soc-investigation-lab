from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from soclab.hunting import run_hunts
from soclab.store import ingest
from soclab.store import iter_events, sources

ROOT=Path(__file__).resolve().parents[1]


class HuntingTests(unittest.TestCase):
    def test_evidence_reads_do_not_recreate_indexes_or_modify_database(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/"events.sqlite";ingest(ROOT/"data/fixtures/demo.jsonl",db)
            with closing(sqlite3.connect(db)) as conn, conn: conn.execute("DROP INDEX event_time")
            before=hashlib.sha256(db.read_bytes()).hexdigest()
            self.assertEqual(len(list(iter_events(db))),19)
            self.assertEqual(len(sources(db)),1)
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(),before)

    def test_hunts_are_read_only_and_preserve_collection_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/"events.sqlite"
            source=ingest(ROOT/"data/fixtures/demo.jsonl",db)
            before=hashlib.sha256(db.read_bytes()).hexdigest()
            result=run_hunts(db)
            self.assertEqual(len(result["hunts"]),8)
            self.assertEqual(result["source_sha256"],[source["source_sha256"]])
            self.assertEqual(result["event_count"],19)
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(),before)

    def test_zero_telemetry_is_reported_as_collection_gap(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/"events.sqlite";ingest(ROOT/"data/fixtures/script-fragments.jsonl",db)
            result=run_hunts(db)
            self.assertEqual(result["hunts"][4]["returned_rows"],5)
            self.assertEqual(result["hunts"][3]["returned_rows"],0)
            self.assertIn("coverage",result["hunts"][3]["assessment"])
