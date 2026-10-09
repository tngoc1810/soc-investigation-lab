"""Ảnh chụp chỉ đọc: tài sản, chất lượng telemetry và hồ sơ bàn giao điều tra."""

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time
from tempfile import TemporaryDirectory

from .events import normalize_event, utc_timestamp, field_value
from .live import _verified, private_path
from .operations import canonical

MAX_EVENTS = 50000
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_PROFILE_BYTES = 256 * 1024
CRITICALITY = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def moment(value):
    return datetime.fromisoformat(utc_timestamp(value).replace('Z', '+00:00')).timestamp()


def text(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 500 or any(ord(c) < 32 for c in value):
        raise ValueError(f'{label}: cần chuỗi rõ ràng, tối đa 500 ký tự, không có ký tự điều khiển')
    return value.strip()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('JSON có khóa trùng lặp')
        result[key] = value
    return result


def read_profile(path, as_of):
    path = Path(path)
    if path.stat().st_size > MAX_PROFILE_BYTES: raise ValueError('Hồ sơ context vượt 256 KiB')
    raw = path.read_bytes()
    if len(raw) > MAX_PROFILE_BYTES: raise ValueError('Hồ sơ context đổi kích thước khi đọc')
    profile = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object)
    validate_profile(profile, as_of)
    return profile, hashlib.sha256(raw).hexdigest()


def validate_profile(profile, as_of):
    if not isinstance(profile, dict) or type(profile.get('schema_version')) is not int or profile['schema_version'] != 1:
        raise ValueError('Hồ sơ context cần schema_version = 1')
    for key in ('id', 'reviewed_by', 'collection_reason'): text(profile.get(key), key)
    if profile.get('kind') not in ('synthetic', 'private_host'): raise ValueError('Context cần phân loại synthetic hoặc private_host')
    reviewed, expires = moment(profile.get('reviewed_at')), moment(profile.get('valid_until'))
    if not reviewed <= as_of <= expires or expires - reviewed > 366 * 86400:
        raise ValueError('Context chưa có hiệu lực, hết hạn hoặc thời hạn vượt một năm')
    scopes = profile.get('scopes')
    if not isinstance(scopes, list) or not 1 <= len(scopes) <= 50: raise ValueError('Cần 1–50 collection scope')
    scope_ids = set()
    for scope in scopes:
        if not isinstance(scope, dict): raise ValueError('Collection scope không hợp lệ')
        identifier = text(scope.get('id'), 'scope.id')
        if identifier != scope['id'] or identifier in scope_ids: raise ValueError('Scope trùng hoặc có khoảng trắng biên')
        scope_ids.add(identifier)
        hashes = scope.get('source_sha256')
        if (not isinstance(hashes, list) or len(hashes) > 1000 or any(not isinstance(h, str) or not re.fullmatch('[a-f0-9]{64}', h) for h in hashes)
                or len(set(hashes)) != len(hashes)): raise ValueError('Scope cần tập source hash chính xác, không trùng')
    assets = profile.get('assets')
    if not isinstance(assets, list) or not 1 <= len(assets) <= 100: raise ValueError('Cần 1–100 tài sản')
    asset_ids, hosts = set(), set()
    for asset in assets:
        if not isinstance(asset, dict): raise ValueError('Tài sản không hợp lệ')
        identifier = text(asset.get('id'), 'asset.id')
        if identifier != asset['id'] or identifier in asset_ids: raise ValueError('Asset ID trùng hoặc có khoảng trắng biên')
        asset_ids.add(identifier)
        for key in ('name', 'owner', 'business_service', 'data_classification', 'incident_lead'): text(asset.get(key), key)
        if not isinstance(asset.get('criticality'), str) or asset['criticality'] not in CRITICALITY: raise ValueError('Criticality tài sản không hợp lệ')
        aliases = asset.get('hosts')
        if not isinstance(aliases, list) or not 1 <= len(aliases) <= 10: raise ValueError('Tài sản cần 1–10 tên host được khai báo')
        for alias in aliases:
            key = text(alias, 'host').casefold()
            if key in hosts or alias != alias.strip(): raise ValueError('Tên host/alias ánh xạ nhiều lần hoặc có khoảng trắng biên')
            hosts.add(key)
    requirements = profile.get('telemetry')
    if not isinstance(requirements, list) or not 1 <= len(requirements) <= 200: raise ValueError('Cần 1–200 yêu cầu telemetry')
    identifiers = set()
    for requirement in requirements:
        if not isinstance(requirement, dict): raise ValueError('Yêu cầu telemetry không hợp lệ')
        identifier = text(requirement.get('id'), 'telemetry.id')
        if identifier in identifiers: raise ValueError('Telemetry ID trùng')
        identifiers.add(identifier)
        if not isinstance(requirement.get('asset_id'), str) or requirement['asset_id'] not in asset_ids: raise ValueError('Telemetry tham chiếu tài sản chưa khai báo')
        selected = requirement.get('scopes')
        if not isinstance(selected, list) or not selected or any(not isinstance(s, str) or s not in scope_ids for s in selected) or len(set(selected)) != len(selected):
            raise ValueError('Telemetry cần scope đã được phê duyệt, không trùng')
        for key in ('provider', 'channel'): text(requirement.get(key), key)
        ids = requirement.get('event_ids')
        if not isinstance(ids, list) or not 1 <= len(ids) <= 30 or any(type(i) is not int or i < 0 for i in ids) or len(set(ids)) != len(ids):
            raise ValueError('Event ID phải là danh sách số nguyên không âm, không trùng')
        fields = requirement.get('required_fields')
        if (not isinstance(fields, list) or len(fields) > 30 or any(not isinstance(f, str) or not re.fullmatch(r'event_data\.[A-Za-z][A-Za-z0-9_]{0,79}', f) for f in fields)
                or len(set(fields)) != len(fields)): raise ValueError('Required fields cần tên event_data rõ ràng, không trùng')
        for key in ('expected_activity_seconds', 'max_ingest_lag_seconds'):
            if type(requirement.get(key)) is not int or not 1 <= requirement[key] <= 86400 * 30: raise ValueError('Ngưỡng thời gian telemetry không hợp lệ')
        heartbeat = requirement.get('max_collector_age_seconds')
        if heartbeat is not None and (type(heartbeat) is not int or not 1 <= heartbeat <= 86400): raise ValueError('Ngưỡng heartbeat không hợp lệ')
    if {r['asset_id'] for r in requirements} != asset_ids: raise ValueError('Mỗi tài sản cần ít nhất một yêu cầu telemetry; không có policy không có nghĩa là đủ coverage')


def snapshot(workspace, profile, as_of):
    workspace = Path(workspace).resolve()
    scopes = [s['id'] for s in profile['scopes']]
    slots = ','.join('?' for _ in scopes)
    db = workspace / 'live.sqlite'
    if not db.is_file(): raise ValueError('Workspace chưa có live.sqlite')
    if profile['kind'] == 'private_host' and not private_path(workspace): raise ValueError('Workspace private phải nằm trong private cache hoặc data/local')
    with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA query_only=ON'); conn.execute('BEGIN')
        batches = [dict(r) for r in conn.execute(f'SELECT * FROM batches WHERE scope IN ({slots}) ORDER BY scope,sha256', scopes)]
        for declaration in profile['scopes']:
            actual = [b for b in batches if b['scope'] == declaration['id']]
            if any(b['kind'] != profile['kind'] for b in actual): raise ValueError('Context và collection khác loại dữ liệu')
            if {b['sha256'] for b in actual} != set(declaration['source_sha256']):
                raise ValueError('Tập source đã thay đổi hoặc chưa được phê duyệt; cần review lại context')
        rows = [dict(r) for r in conn.execute(f'SELECT e.*,o.scope,o.kind,o.received FROM events e JOIN observations o USING(event_uid) WHERE o.scope IN ({slots}) ORDER BY e.event_uid LIMIT ?', [*scopes, MAX_EVENTS + 1])]
        if len(rows) > MAX_EVENTS: raise ValueError('Ảnh chụp vượt giới hạn 50.000 event')
        if any(r['kind'] != profile['kind'] for r in rows): raise ValueError('Observation khác loại context')
        if len(rows) != sum(b['accepted'] for b in batches): raise ValueError('Số observation và accepted batch không khớp')
        by_source = {}
        approved_sources = {b['sha256'] for b in batches}
        for row in rows:
            if row['source_sha256'] not in approved_sources or type(row['source_line']) is not int or row['source_line'] < 1:
                raise ValueError('Observation không có acquisition source hợp lệ trong scope')
            by_source.setdefault(row['source_sha256'], {})[row['source_line']] = row
        archive_bytes = 0
        for batch in batches:
            path = workspace / 'archive' / (batch['sha256'] + '.jsonl')
            if path.resolve().parent != (workspace / 'archive').resolve(): raise ValueError('Archive trỏ ra ngoài thư mục acquisition')
            size = path.stat().st_size; archive_bytes += size
            if size > 16000000 or archive_bytes > MAX_ARCHIVE_BYTES: raise ValueError('Archive vượt giới hạn kiểm chứng byte')
            checked = set(); digest = hashlib.sha256(); seen_bytes = 0
            with path.open('rb') as stream:
                for line, raw in enumerate(stream, 1):
                    seen_bytes += len(raw)
                    if seen_bytes > size: raise ValueError('Archive thay đổi khi đang đọc')
                    digest.update(raw)
                    row = by_source.get(batch['sha256'], {}).get(line)
                    if row is None: continue  # A skipped overlapping observation stays anchored to its first accepted source.
                    original = json.loads(raw.decode('utf-8-sig' if line == 1 else 'utf-8'))
                    expected = normalize_event(original, batch['sha256'], line)
                    for key, value in expected.items():
                        actual = json.loads(row[key]) if key == 'event_data' else row[key]
                        if key == 'original_json': actual, value = json.loads(actual), json.loads(value)
                        if actual != value: raise ValueError('Event trong database khác acquisition archive')
                    checked.add(line)
            if seen_bytes != size or digest.hexdigest() != batch['sha256'] or checked != set(by_source.get(batch['sha256'], {})):
                raise ValueError('Hash/archive/evidence reference không khớp')
        collectors = [dict(r) for r in conn.execute(f'SELECT * FROM collectors WHERE scope IN ({slots}) ORDER BY scope', scopes)]
        if any(not isinstance(c['updated'], (int, float)) or not math.isfinite(c['updated']) or type(c['gap_count']) is not int or c['gap_count'] < 0 for c in collectors):
            raise ValueError('Collector metadata không hợp lệ')
        alerts = []
        event_ids = {r['event_uid'] for r in rows}
        event_rows = {r['event_uid']: r for r in rows}
        for row in conn.execute(f'SELECT id FROM alerts WHERE scope IN ({slots}) ORDER BY id', scopes):
            verified = _verified(conn, row['id']); alert = verified['alert']
            evidence = alert['finding']['evidence']
            if not evidence or any(e['event_uid'] not in event_ids for e in evidence): raise ValueError('Alert tham chiếu evidence ngoài snapshot được duyệt')
            for anchor in evidence:
                original = event_rows[anchor['event_uid']]
                if any(anchor.get(k) != original[k] for k in ('source_sha256', 'source_line', 'host', 'provider', 'channel', 'event_id')):
                    raise ValueError('Anchor của alert khác acquisition đã kiểm chứng')
            if any(not isinstance(alert[k], (int, float)) or not math.isfinite(alert[k]) for k in ('created', 'due')): raise ValueError('Thời gian alert không hợp lệ')
            alerts.append({**alert, 'audit_anchor_sha256': verified['anchor_sha256']})
        queues = [dict(r) for r in conn.execute(f'SELECT o.scope,b.state,COUNT(*) AS count,MIN(o.received) AS oldest_received FROM outbox b JOIN observations o USING(event_uid) WHERE o.scope IN ({slots}) GROUP BY o.scope,b.state ORDER BY o.scope,b.state', scopes)]
        if sum(q['count'] for q in queues) != len(rows) or any(q['state'] not in ('pending', 'sending', 'delivered', 'dead_letter', 'held_private') for q in queues):
            raise ValueError('Outbox không khớp tập observation hoặc có trạng thái không hợp lệ')
        if conn.execute(f'SELECT COUNT(*) FROM outbox b JOIN observations o USING(event_uid) WHERE o.scope IN ({slots}) AND (b.scope!=o.scope OR b.kind!=o.kind)', scopes).fetchone()[0]:
            raise ValueError('Outbox và observation khác scope/kind')
        identity = {'profile': profile, 'events': [{k: r[k] for k in ('event_uid', 'source_sha256', 'source_line', 'scope', 'kind', 'received', 'original_json')} for r in rows],
                    'collectors': collectors, 'queues': queues, 'alerts': alerts}
        fingerprint = hashlib.sha256(canonical(identity)).hexdigest()
    return rows, collectors, alerts, queues, fingerprint


def assess(workspace, profile_path, *, as_of, window_seconds=3600):
    now = moment(as_of)
    if type(window_seconds) is not int or not 60 <= window_seconds <= 86400 * 30: raise ValueError('Cửa sổ quan sát cần từ 60 giây đến 30 ngày')
    profile, profile_hash = read_profile(profile_path, now)
    rows, collectors, alerts, queues, fingerprint = snapshot(workspace, profile, now)
    host_assets = {h.casefold(): a['id'] for a in profile['assets'] for h in a['hosts']}
    by_pair, unknown, asset_events, uid_assets = {}, {}, {}, {}
    for row in rows:
        row['event_data'] = json.loads(row['event_data']); row['time'] = moment(row['timestamp'])
        if not isinstance(row['received'], (int, float)) or not math.isfinite(row['received']): raise ValueError('Received timestamp không hợp lệ')
        asset_id = host_assets.get(row['host'].casefold())
        uid_assets[row['event_uid']] = asset_id
        if asset_id is None:
            unknown[row['host']] = unknown.get(row['host'], 0) + 1
            continue
        asset_events.setdefault(asset_id, []).append(row)
        key = (asset_id, row['scope'], row['provider'].casefold(), row['channel'].casefold(), row['event_id'])
        by_pair.setdefault(key, []).append(row)
    collector_map = {c['scope']: c for c in collectors}
    results = []
    for asset in profile['assets']:
        checks, matched = [], set()
        for requirement in profile['telemetry']:
            if requirement['asset_id'] != asset['id']: continue
            observed = [r for scope in requirement['scopes'] for eid in requirement['event_ids']
                        for r in by_pair.get((asset['id'], scope, requirement['provider'].casefold(), requirement['channel'].casefold(), eid), [])]
            matched.update(r['event_uid'] for r in observed)
            in_window = [r for r in observed if now - window_seconds <= r['time'] <= now]
            not_future = [r for r in observed if r['time'] <= now]
            latest = max((r['time'] for r in not_future), default=None)
            missing = {f: sum(not isinstance(field_value(r, f), str) or not field_value(r, f).strip() for r in observed) for f in requirement['required_fields']}
            late = [r for r in observed if r['received'] - r['time'] > requirement['max_ingest_lag_seconds']]
            future = [r for r in observed if r['time'] > now + 120]
            clock = [r for r in observed if r['received'] < r['time']]
            absent_ids = sorted(set(requirement['event_ids']) - {r['event_id'] for r in in_window})
            issues = []
            if not observed: issues.append('Chưa có quan sát đúng provider/channel/Event ID trong nguồn được duyệt.')
            elif latest is None or now - latest > requirement['expected_activity_seconds']: issues.append('Hoạt động event cũ hơn ngưỡng đã khai báo; chưa đủ căn cứ nói sensor ngừng chạy.')
            if absent_ids: issues.append('Một số Event ID chưa xuất hiện trong cửa sổ; không suy ra cấu hình audit bị tắt.')
            if any(missing.values()): issues.append('Trường phục vụ điều tra bị thiếu hoặc rỗng.')
            if late: issues.append('Có event nhận trễ theo received time lưu trong workspace.')
            if future or clock: issues.append('Timestamp tương lai hoặc received time trước event time; cần kiểm tra đồng hồ.')
            heartbeats = []
            for scope in requirement['scopes']:
                c = collector_map.get(scope)
                state = 'không_yêu_cầu'
                if requirement.get('max_collector_age_seconds') is not None:
                    state = 'chưa_có_heartbeat' if c is None else 'cần_review' if c['last_error'] or c['gap_count'] or c['updated'] > now or now - c['updated'] > requirement['max_collector_age_seconds'] else 'có_heartbeat_trong_ngưỡng'
                    if state != 'có_heartbeat_trong_ngưỡng': issues.append('Collector scope có lỗi/gap, heartbeat cũ hoặc chưa có heartbeat.')
                heartbeats.append({'scope': scope, 'state': state, 'gap_count': c['gap_count'] if c else None, 'error': c['last_error'] if c else None,
                                   'age_seconds': round(now - c['updated'], 3) if c else None,
                                   'boundary': 'Heartbeat thuộc collector scope; không chứng minh sensor trên từng host hoạt động.'})
            checks.append({'id': requirement['id'], 'provider': requirement['provider'], 'channel': requirement['channel'],
                           'observed_total': len(observed), 'in_window': len(in_window), 'latest_event_age_seconds': round(now - latest, 3) if latest is not None else None,
                           'missing_event_ids_in_window': absent_ids, 'missing_fields': missing, 'late_records': len(late), 'future_records': len(future),
                           'negative_received_lag': len(clock), 'collector_checks': heartbeats, 'issues': sorted(set(issues)),
                           'anchor_samples': [{k: r[k] for k in ('event_uid', 'source_sha256', 'source_line', 'timestamp', 'scope')} for r in sorted(observed, key=lambda r: r['event_uid'])[:5]]})
        selected_alerts = []
        for alert in alerts:
            related = {uid_assets[e['event_uid']] for e in alert['finding']['evidence']}
            if asset['id'] not in related: continue
            selected_alerts.append({'id': alert['id'], 'rule_id': alert['rule_id'], 'suggested_severity': alert['severity'], 'state': alert['state'],
                                    'owner': alert['owner'], 'revision': alert['revision'], 'verdict': alert['verdict'], 'audit_anchor_sha256': alert['audit_anchor_sha256'],
                                    'due_at': datetime.fromtimestamp(alert['due'], timezone.utc).isoformat(), 'overdue': alert['state'] != 'closed' and alert['due'] < now,
                                    'evidence_uids': [e['event_uid'] for e in alert['finding']['evidence']], 'multiple_assets_or_unmapped': len(related) > 1 or None in related})
        gaps = [c['id'] for c in checks if c['issues']]
        active = [a for a in selected_alerts if a['state'] != 'closed']
        unclassified = len([r for r in asset_events.get(asset['id'], []) if r['event_uid'] not in matched])
        priority = 'ưu_tiên_review' if CRITICALITY[asset['criticality']] >= 3 and (active or gaps) else 'cần_bổ_sung_telemetry' if gaps else 'review_theo_hàng_đợi' if active else 'chưa_có_lead_đang_mở'
        results.append({'asset': asset, 'priority': priority, 'telemetry': checks, 'unmatched_policy_events': unclassified, 'alerts': selected_alerts,
                        'handoff': {'owner': asset['owner'], 'incident_lead': asset['incident_lead'], 'business_service': asset['business_service'],
                                    'collection_reason': profile['collection_reason'], 'open_alert_ids': [a['id'] for a in active], 'telemetry_gap_ids': gaps,
                                    'verdict': 'chưa_kết_luận', 'authority': 'Chủ sở hữu/context do người vận hành khai báo; chưa xác thực danh tính hoặc quyền ứng phó.',
                                    'proposals': [
                                        {'action': 'Giữ acquisition, đối chiếu thời gian và bổ sung nguồn/trường còn thiếu', 'owner': asset['incident_lead'], 'approval': 'Phê duyệt truy cập và lưu giữ dữ liệu', 'impact': 'Chi phí thu nhận/lưu trữ và dữ liệu nhạy cảm', 'rollback': 'Không xóa acquisition gốc; giữ snapshot trước thay đổi', 'verification': 'Hash/UID đúng, telemetry gap có giải trình'},
                                        {'action': 'Xác minh hoạt động với chủ dịch vụ trước khi đề xuất containment', 'owner': asset['owner'], 'approval': 'Change/ticket và người có thẩm quyền phải được xác minh', 'impact': 'Có thể gián đoạn dịch vụ nếu chặn nhầm', 'rollback': 'Phải có cấu hình trước thay đổi và cách phục hồi được phê duyệt', 'verification': 'Đối chiếu process/session, nội dung, destination và tình trạng dịch vụ'}]}})
    results.sort(key=lambda r: (-CRITICALITY[r['asset']['criticality']], r['asset']['id']))
    from . import __version__
    return {'schema_version': 1, 'version': __version__, 'as_of': utc_timestamp(as_of), 'window_seconds': window_seconds,
            'context': {'id': profile['id'], 'sha256': profile_hash, 'kind': profile['kind'], 'reviewed_by': profile['reviewed_by'], 'valid_until': profile['valid_until']},
            'source_scopes': profile['scopes'], 'selected_snapshot_sha256': fingerprint, 'archive_and_database_anchors_verified': True,
            'summary': {'assets': len(results), 'selected_events': len(rows), 'unmapped_hosts': len(unknown), 'telemetry_checks': sum(len(r['telemetry']) for r in results),
                        'checks_needing_review': sum(bool(c['issues']) for r in results for c in r['telemetry']), 'active_alerts': sum(a['state'] != 'closed' for a in alerts)},
            'assets': results, 'unmapped_hosts': [{'host': h, 'observations': count,
                'alert_ids': [a['id'] for a in alerts if any(e['host'] == h for e in a['finding']['evidence'])],
                'assessment': 'Chưa có mapping tài sản/chủ sở hữu; không tự gán priority hoặc verdict.'} for h, count in sorted(unknown.items())],
            'delivery_states': queues, 'verdict': 'chưa_kết_luận',
            'readonly_boundary': 'SQLite mode=ro/query_only; SQLite có thể tạo WAL/SHM coordination. Không sửa bảng dữ liệu. Snapshot là hiện trạng lúc đọc, không phục dựng lịch sử database ở as_of.',
            'limits': {'events': MAX_EVENTS, 'archive_bytes': MAX_ARCHIVE_BYTES, 'anchor_samples_per_check': 5},
            'scope': 'Ảnh chụp chỉ đọc của collection được phê duyệt. Không sửa owner/status/verdict, không đánh giá mọi audit policy, không gửi thông báo hoặc thực hiện containment.'}


def write_bundle(workspace, profile_path, output, *, as_of, window_seconds=3600):
    output = Path(output).resolve()
    if output.is_relative_to(Path(workspace).resolve()): raise ValueError('Báo cáo phải nằm ngoài workspace nguồn để giữ acquisition chỉ đọc')
    if output.exists(): raise ValueError('Báo cáo cần destination mới; không ghi đè hồ sơ đã giữ')
    result = assess(workspace, profile_path, as_of=as_of, window_seconds=window_seconds)
    if result['context']['kind'] == 'private_host' and not private_path(output): raise ValueError('Báo cáo private phải giữ trong private cache hoặc data/local')
    from .service_report import render_html, render_markdown
    files = {'readiness.json': json.dumps(result, ensure_ascii=False, indent=2).encode() + b'\n',
             'index.html': render_html(result).encode(), 'ban-giao.md': render_markdown(result).encode()}
    manifest = {'format': 'soclab-service-readiness-v1', 'context_sha256': result['context']['sha256'], 'snapshot_sha256': result['selected_snapshot_sha256'],
                'files': {n: hashlib.sha256(raw).hexdigest() for n, raw in files.items()}, 'scope': result['scope']}
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix='.readiness-', dir=output.parent) as tmp:
        staged = Path(tmp) / 'bundle'; staged.mkdir()
        for name, raw in files.items(): (staged / name).write_bytes(raw)
        (staged / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
        for attempt in range(6):
            if output.exists(): raise ValueError('Destination đã được tạo bởi process khác')
            try:
                os.rename(staged, output)
                break
            except PermissionError:
                if attempt == 5: raise
                time.sleep(0.1)  # A short bounded retry for transient Windows filesystem scanners.
    return result
