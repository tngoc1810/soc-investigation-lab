"""Kiểm hồ sơ chính: UTF-8, local links, CLI grammar và native PowerShell AST nếu có."""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from soclab import __version__, cli

DOCUMENTS = ['README.md', 'docs/PROJECT_REPORT_VI.md', 'docs/ARCHITECTURE.md', 'docs/OPERATIONS.md',
             'docs/ACCEPTANCE.md', 'docs/START_HERE_VI.md', 'docs/PORTFOLIO_NOTES.md', 'docs/ENGINEERING_V6.md',
             'docs/ENGINEERING_V61.md', 'docs/DESIGN_DECISIONS_VI.md', 'evidence/service/README.md', 'evidence/handoff/README.md']


class Parsed(Exception):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('Kết quả cần file mới')
    paths = [ROOT / name for name in DOCUMENTS] + sorted((ROOT / 'cases').glob('*/report.md'))
    links, blocks, commands = [], [], []
    real_parse = argparse.ArgumentParser.parse_args

    def parse_only(self, *values, **options):
        real_parse(self, *values, **options)
        raise Parsed()

    for path in paths:
        text = path.read_text(encoding='utf-8')
        if '\ufffd' in text:
            raise ValueError('Có replacement character trong ' + str(path))
        for target in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text):
            target = target.strip('<>')
            if urlparse(target).scheme or target.startswith('#'):
                continue
            resolved = (path.parent / unquote(target.split('#')[0])).resolve()
            if not resolved.is_relative_to(ROOT) or (not resolved.exists() and resolved != args.out.resolve()):
                raise ValueError('Local link không tồn tại hoặc ngoài repo: ' + target)
            links.append({'document': path.relative_to(ROOT).as_posix(), 'target': target})
        for block in re.findall(r'```powershell\s*\n(.*?)```', text, re.S):
            blocks.append({'document': path.relative_to(ROOT).as_posix(), 'text': block})
            for line in block.splitlines():
                if line.startswith('python -m soclab '):
                    # Validate argparse grammar only; native AST below checks the unchanged PowerShell source.
                    grammar = re.sub(r'\(Join-Path \$taskLiveRoot "([^"]+)"\)', r'"data/local/\1"', line)
                    with patch.object(argparse.ArgumentParser, 'parse_args', parse_only), contextlib.redirect_stdout(io.StringIO()):
                        try:
                            cli.main(shlex.split(grammar)[3:])
                        except Parsed:
                            commands.append(line)
                        except SystemExit as error:
                            if error.code:
                                raise
                            commands.append(line)
                elif line.startswith('python scripts/') or line.startswith('./scripts/'):
                    name = shlex.split(line)[1 if line.startswith('python ') else 0]
                    if not (ROOT / name).is_file():
                        raise ValueError('Script reference thiếu: ' + name)
    native = {'status': 'not_run', 'reason': 'Native PowerShell AST checker chỉ chạy khi Windows PowerShell có sẵn'}
    if os.name == 'nt' and shutil.which('powershell'):
        with tempfile.TemporaryDirectory(prefix='soc-doc-check-') as temporary:
            block_file = Path(temporary) / 'blocks.json'
            block_file.write_text(json.dumps(blocks, ensure_ascii=False), encoding='utf-8')
            process = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-File',
                                      str(ROOT / 'scripts/check_document_blocks.ps1'), '-InputPath', str(block_file)],
                                     capture_output=True, text=True, encoding='utf-8', timeout=30)
            if process.returncode:
                raise ValueError('PowerShell AST check thất bại: ' + process.stderr)
            results = json.loads(process.stdout)
            if len(results) != len(blocks) or not all(r['syntax_valid'] for r in results):
                raise ValueError('AST check không đủ block')
            native = {'status': 'passed', 'blocks_checked': len(results)}
    artifact = {'version': __version__, 'validated_at_utc': datetime.now(timezone.utc).isoformat(),
                'files': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                'local_links_verified': len(links), 'cli_commands_parsed_without_execution': len(commands),
                'powershell_ast': native,
                'scope': '20 hồ sơ chính và tám case hiện tại theo danh sách files; local file existence/UTF-8/CLI grammar. Không kiểm URL remote, fragment headings hoặc kết quả chạy operational; AST chỉ parse fenced PowerShell blocks, không execute.'}
    artifact['scope'] = artifact['scope'].replace('20 hồ sơ chính và tám case hiện tại', str(len(paths)) + ' hồ sơ chính/case hiện tại')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(artifact, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in artifact.items() if k != 'files'}, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
