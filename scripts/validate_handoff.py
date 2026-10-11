"""Chạy CLI thật với gói đã giữ và bản sao bị sửa; không thay evidence gốc."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from soclab import __version__
from soclab.service_report import render_html, render_markdown

RETAINED_DIGEST = '7cec40b06c4e378cda911ddf8f61a9ed36324437f9ad58b49e092b3df8134691'


def cli(directory, digest):
    completed = subprocess.run([sys.executable, '-m', 'soclab', 'verify-readiness', '--bundle', str(directory),
                                '--manifest-sha256', digest], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=30)
    return {'exit_code': completed.returncode, 'stdout': completed.stdout, 'stderr': completed.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('Kết quả cần file mới')
    original = ROOT / 'evidence/service/report'
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in original.iterdir()}
    accepted = cli(original, RETAINED_DIGEST)
    assert accepted['exit_code'] == 0, accepted['stderr']
    assert json.loads(accepted['stdout'])['source_acquisition_rechecked'] is False
    rejected = {}
    with tempfile.TemporaryDirectory(prefix='soc-handoff-') as temporary:
        for scenario in ('changed_html', 'whole_bundle_resealed', 'handoff_resealed', 'extra_file'):
            target = Path(temporary) / scenario
            shutil.copytree(original, target)
            supplied_digest = RETAINED_DIGEST
            if scenario == 'changed_html':
                with (target / 'index.html').open('ab') as stream:
                    stream.write(b'<script>fetch("https://example.invalid")</script>')
            elif scenario == 'extra_file':
                (target / 'extra.txt').write_text('extra')
            else:
                if scenario == 'whole_bundle_resealed':
                    report = json.loads((target / 'readiness.json').read_bytes())
                    report['assets'][0]['asset']['owner'] = 'Changed owner'
                    (target / 'readiness.json').write_text(json.dumps(report, ensure_ascii=False), encoding='utf-8')
                    (target / 'index.html').write_bytes(render_html(report).encode())
                    (target / 'ban-giao.md').write_bytes(render_markdown(report).encode())
                else:
                    (target / 'ban-giao.md').write_text('# Changed decision', encoding='utf-8')
                manifest = json.loads((target / 'manifest.json').read_bytes())
                manifest['files'] = {name: hashlib.sha256((target / name).read_bytes()).hexdigest() for name in manifest['files']}
                (target / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
                if scenario == 'handoff_resealed':
                    # Even an accepted new anchor cannot make an inconsistent presentation match JSON.
                    supplied_digest = hashlib.sha256((target / 'manifest.json').read_bytes()).hexdigest()
            rejected[scenario] = cli(target, supplied_digest)
            assert rejected[scenario]['exit_code'] == 2, rejected[scenario]
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in original.iterdir()}
    assert before == after
    artifact = {'version': __version__, 'validated_at_utc': datetime.now(timezone.utc).isoformat(),
                'retained_manifest_sha256': RETAINED_DIGEST, 'original_bundle_unchanged': True,
                'accepted': accepted, 'rejected': rejected,
                'source_hashes': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                                  [ROOT / 'soclab/service_verify.py', ROOT / 'soclab/service_report.py', ROOT / 'soclab/cli.py', Path(__file__)]},
                'scope': 'CLI chạy thật trên public constructed v6 bundle và bốn bản sao kiểm lỗi; không thu host thật, không mở HTML hoặc gọi mạng. Anchor là digest artifact đã giữ trong repo, chưa chứng minh kênh truyền có xác thực.'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(artifact, ensure_ascii=False, indent=2) + '\n')
    print('Verified retained bundle and rejected four modified copies through the actual CLI.')


if __name__ == '__main__':
    main()
