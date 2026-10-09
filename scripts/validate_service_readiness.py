"""Kiểm chứng pipeline readiness thực thi, tính chỉ đọc và chất lượng dữ liệu tự dựng."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.service_fixtures import AS_OF, build
from soclab.service_readiness import write_bundle
from soclab import __version__


def hashes(root):
    # SQLite mode=ro may create WAL/SHM coordination files. SHM and a zero-frame WAL are not evidence writes.
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*'))
            if p.is_file() and not p.name.endswith('.sqlite-shm') and not (p.name.endswith('.sqlite-wal') and p.stat().st_size <= 32)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', args.run_id): raise ValueError('Run ID không hợp lệ')
    if args.out.exists(): raise ValueError('Artifact kiểm chứng cần file mới')
    root = ROOT / 'output/service-readiness' / args.run_id
    workspace, context = build(root / 'source')
    before = hashes(workspace)
    result = write_bundle(workspace, context, root / 'report', as_of=AS_OF)
    assert hashes(workspace) == before, 'Readiness đã thay đổi source workspace'
    assert result['summary'] == {'assets': 2, 'selected_events': 12, 'unmapped_hosts': 1, 'telemetry_checks': 5, 'checks_needing_review': 4, 'active_alerts': 2}
    finance, backup = result['assets']
    assert finance['asset']['id'] == 'finance' and backup['asset']['id'] == 'backup'
    checks = {c['id']: c for c in finance['telemetry']}
    assert checks['AUTH-COVERAGE']['issues'] == []
    assert checks['PROCESS-QUALITY']['missing_fields']['event_data.ParentImage'] == 1
    assert checks['PROCESS-QUALITY']['future_records'] == 1
    assert checks['NETWORK-QUALITY']['missing_fields']['event_data.DestinationPort'] == 1
    assert checks['SCRIPT-COVERAGE']['late_records'] == 1 and checks['SCRIPT-COVERAGE']['in_window'] == 0
    assert finance['unmatched_policy_events'] == 1 and backup['telemetry'][0]['observed_total'] == 0
    assert all(a['handoff']['verdict'] == 'chưa_kết_luận' for a in result['assets'])
    assert all(a['priority'] == 'ưu_tiên_review' for a in result['assets'])
    manifest = json.loads((root / 'report/manifest.json').read_text(encoding='utf-8'))
    for name, digest in manifest['files'].items(): assert hashlib.sha256((root / 'report' / name).read_bytes()).hexdigest() == digest
    artifact = {'version': __version__, 'validated_at_utc': datetime.now(timezone.utc).isoformat(), 'run_id': args.run_id,
                'summary': result['summary'], 'as_of': AS_OF, 'context_sha256': result['context']['sha256'], 'snapshot_sha256': result['selected_snapshot_sha256'],
                'persistent_database_archives_and_nonempty_wal_unchanged': before == hashes(workspace), 'archive_and_database_anchors_verified': result['archive_and_database_anchors_verified'],
                'readonly_boundary': 'SQLite mode=ro/query_only và transaction đọc. WAL/SHM coordination có thể được tạo; không đồng nghĩa ghi event/alert. Phép so hash loại SHM và WAL không có frame.',
                'exact_report_manifest_verified': True, 'future_timestamp_and_wrong_channel_retained': True, 'missing_host_telemetry_not_called_disabled': True,
                'missing_fields': {k: v['missing_fields'] for k, v in checks.items()}, 'verdict': result['verdict'],
                'source_hashes': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / 'soclab').glob('*.py'))},
                'scope': 'Dữ liệu và collector diagnostic đều tự dựng. Chỉ đọc source workspace; không thu thập log host thật, không thông báo người nhận, không thực hiện containment.'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8', newline='\n') as stream: stream.write(json.dumps(artifact, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(artifact['summary'], ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
