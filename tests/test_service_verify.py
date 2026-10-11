"""Nhận gói bàn giao: trust anchor độc lập, file inventory và nhất quán biểu diễn."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.service_fixtures import AS_OF, build
from soclab.cli import main
from soclab.service_readiness import write_bundle
from soclab.service_report import render_html, render_markdown
from soclab.service_verify import verify_bundle


class ServiceVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace, profile = build(root / 'source')
            write_bundle(workspace, profile, root / 'report', as_of=AS_OF)
            cls.original = {p.name: p.read_bytes() for p in (root / 'report').iterdir()}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'bundle'
        self.root.mkdir()
        for name, raw in self.original.items():
            (self.root / name).write_bytes(raw)
        self.anchor = self.digest('manifest.json')

    def digest(self, name):
        return hashlib.sha256((self.root / name).read_bytes()).hexdigest()

    def verify(self, anchor=None):
        return verify_bundle(self.root, manifest_sha256=anchor or self.anchor)

    def reseal(self, *, render=False):
        report = json.loads((self.root / 'readiness.json').read_bytes())
        if render:
            (self.root / 'index.html').write_bytes(render_html(report).encode())
            (self.root / 'ban-giao.md').write_bytes(render_markdown(report).encode())
        manifest = json.loads((self.root / 'manifest.json').read_bytes())
        manifest['files'] = {name: self.digest(name) for name in manifest['files']}
        (self.root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        return self.digest('manifest.json')

    def change_report(self, change):
        report = json.loads((self.root / 'readiness.json').read_bytes())
        change(report)
        (self.root / 'readiness.json').write_text(json.dumps(report, ensure_ascii=False), encoding='utf-8')

    def test_valid_bundle_no_writes_no_source_recheck_claim(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = self.verify()
        self.assertEqual(result['files_verified'], 3)
        self.assertTrue(result['rendered_documents_match'])
        self.assertFalse(result['source_acquisition_rechecked'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_changed_html_rejected_before_rendering(self):
        with (self.root / 'index.html').open('ab') as stream:
            stream.write(b'<script>fetch("https://example.invalid")</script>')
        with self.assertRaisesRegex(ValueError, 'Byte'):
            self.verify()

    def test_whole_bundle_reseal_does_not_defeat_retained_anchor(self):
        self.change_report(lambda r: r['assets'][0]['asset'].update(owner='another owner'))
        self.reseal(render=True)
        with self.assertRaisesRegex(ValueError, 'giữ độc lập'):
            self.verify()

    def test_html_reseal_without_matching_json_rejected(self):
        (self.root / 'index.html').write_text('<html>All healthy</html>', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Giao diện'):
            self.verify(self.reseal())

    def test_handoff_reseal_without_matching_json_rejected(self):
        (self.root / 'ban-giao.md').write_text('# All healthy', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'Biên bản'):
            self.verify(self.reseal())

    def test_mismatched_context_and_snapshot_rejected(self):
        for field in ('context', 'snapshot'):
            with self.subTest(field=field):
                for name, raw in self.original.items():
                    (self.root / name).write_bytes(raw)
                self.change_report(lambda r: r['context'].update(sha256='0' * 64) if field == 'context' else r.update(selected_snapshot_sha256='0' * 64))
                with self.assertRaisesRegex(ValueError, 'khác manifest'):
                    self.verify(self.reseal(render=True))

    def test_mismatched_summary_rejected_after_consistent_rerender(self):
        self.change_report(lambda r: r['summary'].update(checks_needing_review=0))
        with self.assertRaisesRegex(ValueError, 'Tổng quan khác'):
            self.verify(self.reseal(render=True))

    def test_boolean_count_rejected(self):
        self.change_report(lambda r: r['summary'].update(assets=True))
        with self.assertRaisesRegex(ValueError, 'số đếm'):
            self.verify(self.reseal(render=True))

    def test_unmapped_alert_cannot_hide_mapped_active_count(self):
        self.change_report(lambda r: r['summary'].update(active_alerts=0))
        with self.assertRaisesRegex(ValueError, 'Số alert'):
            self.verify(self.reseal(render=True))

    def test_missing_and_extra_entries_rejected(self):
        (self.root / 'extra.txt').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'file thừa'):
            self.verify()
        (self.root / 'extra.txt').unlink()
        (self.root / 'ban-giao.md').unlink()
        with self.assertRaisesRegex(ValueError, 'file thiếu'):
            self.verify()

    def test_manifest_path_traversal_rejected(self):
        manifest = json.loads((self.root / 'manifest.json').read_bytes())
        manifest['files']['../outside.txt'] = '0' * 64
        (self.root / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'đường dẫn'):
            self.verify(self.digest('manifest.json'))

    def test_duplicate_json_key_rejected_even_when_hash_approved(self):
        raw = (self.root / 'manifest.json').read_text(encoding='utf-8')
        (self.root / 'manifest.json').write_text(raw.replace('{', '{"format":"shadow",', 1), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'trùng lặp'):
            self.verify(self.digest('manifest.json'))

    def test_nonfinite_report_json_rejected(self):
        for number in ('NaN', '1e999'):
            with self.subTest(number=number):
                for name, raw in self.original.items():
                    (self.root / name).write_bytes(raw)
                raw = (self.root / 'readiness.json').read_text(encoding='utf-8')
                (self.root / 'readiness.json').write_text(raw.replace('"schema_version": 1', '"schema_version": ' + number), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'không hữu hạn'):
                    self.verify(self.reseal())

    def test_size_bounds_checked_before_unbounded_load(self):
        with patch('soclab.service_verify.MAX_FILE_BYTES', 10), self.assertRaisesRegex(ValueError, 'dung lượng'):
            self.verify()
        with patch('soclab.service_verify.MAX_MANIFEST_BYTES', 10), self.assertRaisesRegex(ValueError, 'dung lượng'):
            self.verify()

    def test_directory_in_place_of_file_rejected(self):
        (self.root / 'index.html').unlink()
        (self.root / 'index.html').mkdir()
        with self.assertRaisesRegex(ValueError, 'không thường'):
            self.verify()

    def test_report_symlink_rejected_when_supported(self):
        target = self.root.parent / 'outside.html'
        target.write_bytes((self.root / 'index.html').read_bytes())
        (self.root / 'index.html').unlink()
        try:
            (self.root / 'index.html').symlink_to(target)
        except OSError:
            self.skipTest('Host không cấp quyền tạo symlink; không mô phỏng bằng file thường')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.verify()

    def test_malformed_report_produces_value_error(self):
        self.change_report(lambda r: r.pop('assets'))
        with self.assertRaisesRegex(ValueError, 'cấu trúc'):
            self.verify(self.reseal())

    def test_invalid_digest_and_unsupported_format_rejected(self):
        with self.assertRaisesRegex(ValueError, '64'):
            self.verify('invalid')
        manifest = json.loads((self.root / 'manifest.json').read_bytes())
        manifest['format'] = 'unknown'
        (self.root / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'định dạng'):
            self.verify(self.digest('manifest.json'))

    def test_cli_success_and_failure_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(['verify-readiness', '--bundle', str(self.root), '--manifest-sha256', self.anchor])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(output.getvalue())['source_acquisition_rechecked'])
        with contextlib.redirect_stderr(io.StringIO()) as error:
            code = main(['verify-readiness', '--bundle', str(self.root), '--manifest-sha256', '0' * 64])
        self.assertEqual(code, 2)
        self.assertIn('giữ độc lập', error.getvalue())
