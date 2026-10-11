"""Kiểm gói readiness đã nhận, đối chiếu manifest giữ qua kênh độc lập."""

import hashlib
import json
import math
from pathlib import Path
import re
import stat

from .service_report import render_html, render_markdown

REPORT_FILES = frozenset(('readiness.json', 'index.html', 'ban-giao.md'))
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('SHA-256 phải gồm 64 ký tự hex thường')
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('JSON có key trùng lặp')
        result[key] = value
    return result


def _json(raw):
    def invalid(value):
        raise ValueError('JSON có số không hữu hạn')
    def finite_number(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError('JSON có số không hữu hạn')
        return number
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=invalid, parse_float=finite_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('JSON không hợp lệ') from error


def _plain(path):
    info = path.lstat()
    if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError('Không nhận symlink hoặc reparse point trong gói báo cáo')
    return info


def _read(path, limit):
    info = _plain(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError('File không thường hoặc vượt giới hạn dung lượng')
    # Read only bounded bytes, including when another process changes the size.
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('File vượt giới hạn dung lượng')
    return raw


def verify_bundle(directory, *, manifest_sha256):
    """No browser, network or writes. Caller supplies an independently retained hash.

    This checks transferred bytes and this renderer's output, not the source
    acquisition or the authority of whoever supplied the retained hash.
    The local filesystem must remain stable during the check.
    """
    expected = _digest(manifest_sha256)
    root = Path(directory).absolute()
    if not stat.S_ISDIR(_plain(root).st_mode):
        raise ValueError('Cần thư mục gói readiness')
    if {p.name for p in root.iterdir()} != REPORT_FILES | {'manifest.json'}:
        raise ValueError('Gói có file thiếu, file thừa hoặc tên không hợp lệ')
    raw_manifest = _read(root / 'manifest.json', MAX_MANIFEST_BYTES)
    actual_manifest = hashlib.sha256(raw_manifest).hexdigest()
    if actual_manifest != expected:
        raise ValueError('Manifest khác SHA-256 đã giữ độc lập')
    manifest = _json(raw_manifest)
    if not isinstance(manifest, dict) or set(manifest) != {'format', 'context_sha256', 'snapshot_sha256', 'files', 'scope'}:
        raise ValueError('Cấu trúc manifest không hợp lệ')
    if manifest['format'] != 'soclab-service-readiness-v1':
        raise ValueError('Không hỗ trợ định dạng manifest này')
    if not isinstance(manifest['files'], dict) or set(manifest['files']) != REPORT_FILES:
        raise ValueError('Manifest cần đúng ba file báo cáo, không nhận đường dẫn tùy ý')
    _digest(manifest['context_sha256'])
    _digest(manifest['snapshot_sha256'])
    files = {}
    for name in sorted(REPORT_FILES):
        files[name] = _read(root / name, MAX_FILE_BYTES)
        if hashlib.sha256(files[name]).hexdigest() != _digest(manifest['files'][name]):
            raise ValueError('Byte báo cáo không khớp manifest: ' + name)
    report = _json(files['readiness.json'])
    try:
        if not isinstance(report, dict) or type(report.get('schema_version')) is not int or report['schema_version'] != 1:
            raise ValueError('Không hỗ trợ schema readiness này')
        if report['context']['kind'] not in ('synthetic', 'private_host'):
            raise ValueError('Loại dữ liệu không hợp lệ')
        if report['context']['sha256'] != manifest['context_sha256'] or report['selected_snapshot_sha256'] != manifest['snapshot_sha256'] or report['scope'] != manifest['scope']:
            raise ValueError('Context, snapshot hoặc phạm vi khác manifest')
        if report['verdict'] != 'chưa_kết_luận' or report['archive_and_database_anchors_verified'] is not True:
            raise ValueError('Readiness có verdict hoặc cờ nguồn không hợp lệ')
        if not isinstance(report['assets'], list) or not 1 <= len(report['assets']) <= 100:
            raise ValueError('Số tài sản không hợp lệ')
        checks = [check for row in report['assets'] for check in row['telemetry']]
        if not 1 <= len(checks) <= 200:
            raise ValueError('Số telemetry requirement không hợp lệ')
        alerts = {}
        for row in report['assets']:
            for alert in row['alerts']:
                if alert['id'] in alerts and alerts[alert['id']] != alert:
                    raise ValueError('Một alert có nội dung khác nhau giữa các tài sản')
                alerts[alert['id']] = alert
        mapped_active = {key for key, alert in alerts.items() if alert['state'] != 'closed'}
        summary = report['summary']
        counts = {'assets': len(report['assets']), 'unmapped_hosts': len(report['unmapped_hosts']),
                  'telemetry_checks': len(checks), 'checks_needing_review': sum(bool(c['issues']) for c in checks)}
        if set(summary) != set(counts) | {'selected_events', 'active_alerts'} or any(type(n) is not int or n < 0 for n in summary.values()):
            raise ValueError('Tổng quan cần số đếm nguyên không âm')
        if any(summary[key] != value for key, value in counts.items()) or summary['selected_events'] > 50000:
            raise ValueError('Tổng quan khác chi tiết báo cáo')
        # Unmapped alert IDs do not carry state, so they bound rather than determine the active count.
        unmapped_ids = {key for row in report['unmapped_hosts'] for key in row['alert_ids']}
        if not len(mapped_active) <= summary['active_alerts'] <= len(mapped_active | (unmapped_ids - set(alerts))):
            raise ValueError('Số alert mở khác phạm vi chi tiết')
        if files['index.html'] != render_html(report).encode('utf-8'):
            raise ValueError('Giao diện không khớp JSON hoặc renderer đang dùng')
        if files['ban-giao.md'] != render_markdown(report).encode('utf-8'):
            raise ValueError('Biên bản không khớp JSON hoặc renderer đang dùng')
    except (KeyError, TypeError, AttributeError, IndexError, RecursionError) as error:
        raise ValueError('Chi tiết readiness thiếu hoặc sai cấu trúc') from error
    return {'format': manifest['format'], 'manifest_sha256': actual_manifest,
            'files_verified': len(files), 'rendered_documents_match': True,
            'summary': summary, 'source_acquisition_rechecked': False,
            'scope': 'Đối chiếu byte và biểu diễn với manifest giữ độc lập; không xác thực người gửi, không đọc lại acquisition hoặc mở HTML. Filesystem phải ổn định trong lúc kiểm.'}
