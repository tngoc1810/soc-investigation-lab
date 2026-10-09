"""Ràng buộc nguồn, clock, dữ liệu thiếu, quyền riêng tư và output của readiness."""

from contextlib import closing
import hashlib
import json
from pathlib import Path
import tempfile
import sqlite3
import unittest
from unittest.mock import patch

from scripts.service_fixtures import AS_OF, build
from scripts.validate_service_readiness import hashes
from soclab import live
from soclab.service_readiness import assess, write_bundle, moment
from soclab.service_report import render_html, render_markdown


class ServiceReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace, self.profile = build(self.root / 'source')

    def context(self, change=None):
        value = json.loads(self.profile.read_text(encoding='utf-8'))
        if change: change(value)
        self.profile.write_text(json.dumps(value, ensure_ascii=False) + '\n', encoding='utf-8')
        return value

    def evaluate(self, **settings):
        return assess(self.workspace, self.profile, as_of=settings.pop('as_of', AS_OF), **settings)

    def edit(self, sql, args=()):
        with closing(live.connect(self.workspace)) as conn, conn: conn.execute(sql, args)

    def finance(self, report): return next(r for r in report['assets'] if r['asset']['id'] == 'finance')

    def test_exact_summary_and_read_only_repeatable_snapshot(self):
        before = hashes(self.workspace); first = self.evaluate(); second = self.evaluate()
        self.assertEqual(first['summary'], {'assets': 2, 'selected_events': 12, 'unmapped_hosts': 1, 'telemetry_checks': 5, 'checks_needing_review': 4, 'active_alerts': 2})
        self.assertEqual(first, second); self.assertEqual(before, hashes(self.workspace))
        self.assertEqual(first['verdict'], 'chưa_kết_luận')

    def test_missing_fields_late_future_and_wrong_channel_are_distinct(self):
        finance = self.finance(self.evaluate()); checks = {r['id']: r for r in finance['telemetry']}
        self.assertEqual(checks['AUTH-COVERAGE']['issues'], [])
        process = checks['PROCESS-QUALITY']
        self.assertEqual((process['observed_total'], process['in_window'], process['future_records'], process['negative_received_lag']), (2, 1, 1, 1))
        self.assertEqual(process['missing_fields']['event_data.ParentImage'], 1)
        self.assertEqual(checks['NETWORK-QUALITY']['missing_fields']['event_data.DestinationPort'], 1)
        self.assertEqual((checks['SCRIPT-COVERAGE']['in_window'], checks['SCRIPT-COVERAGE']['late_records']), (0, 1))
        self.assertEqual(finance['unmatched_policy_events'], 1)

    def test_no_events_is_not_disabled_sensor_or_safe_asset(self):
        backup = next(r for r in self.evaluate()['assets'] if r['asset']['id'] == 'backup')
        check = backup['telemetry'][0]
        self.assertEqual(check['observed_total'], 0)
        self.assertEqual(check['collector_checks'][0]['state'], 'chưa_có_heartbeat')
        self.assertIn('không suy ra cấu hình audit bị tắt', ' '.join(check['issues']))
        self.assertEqual(backup['handoff']['verdict'], 'chưa_kết_luận')

    def test_heartbeat_is_scope_state_not_host_sensor_proof(self):
        report = self.evaluate(); finance = self.finance(report)
        process = next(c for c in finance['telemetry'] if c['id'] == 'PROCESS-QUALITY')
        heartbeat = process['collector_checks'][0]
        self.assertEqual((heartbeat['state'], heartbeat['gap_count']), ('cần_review', 1))
        self.edit('UPDATE collectors SET updated=?,gap_count=0,last_error=NULL', (moment(AS_OF) - 1,))
        process = next(c for c in self.finance(self.evaluate())['telemetry'] if c['id'] == 'PROCESS-QUALITY')
        self.assertEqual(process['collector_checks'][0]['state'], 'có_heartbeat_trong_ngưỡng')
        self.assertIn('không chứng minh sensor', process['collector_checks'][0]['boundary'])

    def test_source_hash_set_change_requires_new_approval(self):
        with closing(live.connect(self.workspace)) as conn:
            source = json.loads(conn.execute("SELECT original_json FROM events WHERE event_id=4625 LIMIT 1").fetchone()[0])
        source['record_id'] = 99
        source['timestamp'] = '2026-10-09T02:59:59Z'
        p = self.root / 'new.jsonl'; p.write_text(json.dumps(source) + '\n')
        live.ingest_batch(self.workspace, p, scope='security', now=moment(AS_OF))
        with self.assertRaisesRegex(ValueError, 'Tập source'): self.evaluate()

    def test_archive_hash_change_fails_before_publication(self):
        file = next((self.workspace / 'archive').glob('*.jsonl')); file.write_bytes(file.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'Hash/archive'): write_bundle(self.workspace, self.profile, self.root / 'report', as_of=AS_OF)
        self.assertFalse((self.root / 'report').exists())

    def test_database_event_mutation_disagrees_with_original_bytes(self):
        self.edit("UPDATE events SET host='IMPOSTOR' WHERE record_id=10")
        with self.assertRaisesRegex(ValueError, 'khác acquisition'): self.evaluate()

    def test_original_json_mutation_is_detected(self):
        self.edit("UPDATE events SET original_json='{}' WHERE record_id=10")
        with self.assertRaisesRegex(ValueError, 'khác acquisition'): self.evaluate()

    def test_observation_source_outside_approved_batches_is_rejected(self):
        # Deliberately bypass FK enforcement to model an externally corrupted DB.
        with closing(sqlite3.connect(self.workspace / 'live.sqlite')) as conn, conn:
            conn.execute("UPDATE events SET source_sha256=? WHERE record_id=10", ('0' * 64,))
        with self.assertRaisesRegex(ValueError, 'acquisition source'): self.evaluate()

    def test_alert_audit_tamper_is_rejected(self):
        self.edit("UPDATE alerts SET owner='changed-outside-audit'")
        with self.assertRaisesRegex(ValueError, 'audit'): self.evaluate()

    def test_missing_outbox_record_is_not_presented_as_empty_healthy_queue(self):
        self.edit('DELETE FROM outbox WHERE event_uid=(SELECT event_uid FROM events WHERE record_id=10)')
        with self.assertRaisesRegex(ValueError, 'Outbox không khớp'): self.evaluate()

    def test_closed_alert_verdict_and_assignee_are_preserved(self):
        with closing(live.connect(self.workspace)) as conn: identifier = conn.execute("SELECT id FROM alerts WHERE rule_id='WIN-001'").fetchone()[0]
        for revision, state in ((1, 'triaged'), (2, 'investigating'), (3, 'closed')):
            live.update_alert(self.workspace, identifier, revision=revision, actor='declared-operator', reason='Controlled review', owner='assigned-analyst', target=state,
                              verdict='insufficient_evidence' if state == 'closed' else None)
        before = hashes(self.workspace); report = self.evaluate()
        alert = next(a for a in self.finance(report)['alerts'] if a['id'] == identifier)
        self.assertEqual((alert['state'], alert['owner'], alert['verdict'], alert['revision']), ('closed', 'assigned-analyst', 'insufficient_evidence', 4))
        self.assertEqual(report['summary']['active_alerts'], 1)
        self.assertEqual(before, hashes(self.workspace))
        self.assertFalse((self.workspace / 'cases.sqlite').exists())

    def test_priority_change_never_changes_alert_severity_or_verdict(self):
        before = self.finance(self.evaluate())
        self.context(lambda p: p['assets'][0].update(criticality='low'))
        after = self.finance(self.evaluate())
        self.assertNotEqual(before['priority'], after['priority'])
        self.assertEqual(before['alerts'], after['alerts'])
        self.assertEqual(after['handoff']['verdict'], 'chưa_kết_luận')

    def test_expired_not_yet_valid_naive_and_invalid_window_fail(self):
        for date in ('2026-11-09T03:00:00Z', '2026-10-08T03:00:00Z', '2026-10-09T03:00:00'):
            with self.subTest(date=date), self.assertRaises(ValueError): self.evaluate(as_of=date)
        for value in (True, 1, 999999999):
            with self.subTest(value=value), self.assertRaises(ValueError): self.evaluate(window_seconds=value)

    def test_duplicate_keys_and_size_limits_fail(self):
        raw = self.profile.read_bytes()
        self.profile.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, 'trùng'): self.evaluate()
        self.profile.write_bytes(raw)
        with patch('soclab.service_readiness.MAX_PROFILE_BYTES', 10), self.assertRaises(ValueError): self.evaluate()
        with patch('soclab.service_readiness.MAX_ARCHIVE_BYTES', 10), self.assertRaises(ValueError): self.evaluate()

    def test_asset_alias_ambiguity_and_asset_without_policy_fail(self):
        original = self.context()
        for mutate in (lambda p: p['assets'][1].update(hosts=['fin-ws-01']),
                       lambda p: p.update(telemetry=[r for r in p['telemetry'] if r['asset_id'] == 'finance']),
                       lambda p: p['assets'][0].update(criticality=[]),
                       lambda p: p['telemetry'][0].update(scopes=[{}]),
                       lambda p: p['telemetry'][0].update(asset_id=[])):
            self.profile.write_text(json.dumps(original, ensure_ascii=False), encoding='utf-8')
            self.context(mutate)
            with self.assertRaises(ValueError): self.evaluate()

    def test_early_event_limit_and_changed_kind_fail(self):
        with patch('soclab.service_readiness.MAX_EVENTS', 3), self.assertRaises(ValueError): self.evaluate()
        self.context(lambda p: p.update(kind='private_host'))
        with patch('soclab.service_readiness.private_path', return_value=True), self.assertRaisesRegex(ValueError, 'khác loại'): self.evaluate()

    def test_private_workspace_and_public_output_guard(self):
        self.context(lambda p: p.update(kind='private_host'))
        for table in ('batches', 'observations', 'outbox'): self.edit(f"UPDATE {table} SET kind='private_host'")
        with self.assertRaisesRegex(ValueError, 'Workspace private'): self.evaluate()
        # Windows runner temp paths may use 8.3 aliases; compare resolved paths,
        # just as the production workspace guard does.
        with patch('soclab.service_readiness.private_path', side_effect=lambda p: Path(p).resolve() == self.workspace.resolve()):
            with self.assertRaisesRegex(ValueError, 'Báo cáo private'): write_bundle(self.workspace, self.profile, self.root / 'public-output', as_of=AS_OF)
        self.assertFalse((self.root / 'public-output').exists())

    def test_unrelated_private_scope_is_not_exported_with_synthetic_context(self):
        record = {'timestamp': '2026-10-09T03:00:00Z', 'host': 'PRIVATE-SECRET-HOST', 'channel': 'System', 'provider': 'EventLog', 'event_id': 1, 'record_id': 900, 'event_data': {'Message': 'PRIVATE-SECRET-TEXT'}}
        p = self.root / 'private.jsonl'; p.write_text(json.dumps(record) + '\n')
        with patch('soclab.live.private_path', return_value=True): live.ingest_batch(self.workspace, p, scope='unrelated-private', kind='private_host', now=moment(AS_OF))
        result = self.evaluate()
        self.assertNotIn('PRIVATE-SECRET', json.dumps(result))
        self.assertEqual(result['summary']['selected_events'], 12)

    def test_unmapped_host_alert_remains_visible_without_invented_owner(self):
        with closing(live.connect(self.workspace)) as conn:
            record = json.loads(conn.execute('SELECT original_json FROM events WHERE record_id=20').fetchone()[0])
        record.update(host='WS-UNMAPPED', record_id=100)
        p = self.root / 'unmapped-process.jsonl'; p.write_text(json.dumps(record) + '\n')
        live.ingest_batch(self.workspace, p, scope='unmapped', now=moment(AS_OF) - 5)
        live.run_detection(self.workspace, scope='unmapped', now=moment(AS_OF))
        with closing(live.connect(self.workspace)) as conn: approved = [r[0] for r in conn.execute("SELECT sha256 FROM batches WHERE scope='unmapped'")]
        self.context(lambda p: next(s for s in p['scopes'] if s['id'] == 'unmapped').update(source_sha256=approved))
        result = self.evaluate(); unknown = result['unmapped_hosts'][0]
        self.assertEqual(len(unknown['alert_ids']), 1)
        self.assertEqual(result['summary']['active_alerts'], 3)
        self.assertNotIn('owner', unknown)

    def test_inert_html_and_markdown_context_cannot_inject_actions(self):
        injection = '</script><script>alert(1)</script><img src=x onerror=alert(1)>'
        self.context(lambda p: p['assets'][0].update(owner=injection, name='[mở link](https://evil.invalid)'))
        result = self.evaluate(); html = render_html(result); md = render_markdown(result)
        self.assertNotIn(injection, html); self.assertIn('\\u003c/script', html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn('&lt;/script&gt;', md)
        self.assertIn('\\[mở link\\]', md)

    def test_existing_or_source_destination_is_rejected(self):
        output = self.root / 'occupied'; output.mkdir()
        with self.assertRaises(ValueError): write_bundle(self.workspace, self.profile, output, as_of=AS_OF)
        with self.assertRaisesRegex(ValueError, 'ngoài workspace'): write_bundle(self.workspace, self.profile, self.workspace / 'report', as_of=AS_OF)

    def test_failed_render_or_publication_never_leaves_final_report(self):
        output = self.root / 'failed'
        with patch('soclab.service_report.render_html', side_effect=ValueError('render failed')):
            with self.assertRaises(ValueError): write_bundle(self.workspace, self.profile, output, as_of=AS_OF)
        self.assertFalse(output.exists())
        with patch('soclab.service_readiness.os.rename', side_effect=PermissionError('locked')), patch('soclab.service_readiness.time.sleep'):
            with self.assertRaises(PermissionError): write_bundle(self.workspace, self.profile, output, as_of=AS_OF)
        self.assertFalse(output.exists())

    def test_bundle_manifest_and_vietnamese_handoff_verified(self):
        output = self.root / 'report'; result = write_bundle(self.workspace, self.profile, output, as_of=AS_OF)
        self.assertEqual({p.name for p in output.iterdir()}, {'index.html', 'readiness.json', 'ban-giao.md', 'manifest.json'})
        manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
        for file, expected in manifest['files'].items(): self.assertEqual(hashlib.sha256((output / file).read_bytes()).hexdigest(), expected)
        self.assertIn('Không gửi email/ticket', (output / 'ban-giao.md').read_text(encoding='utf-8'))
        self.assertIn('chưa_kết_luận', json.dumps(result, ensure_ascii=False))
