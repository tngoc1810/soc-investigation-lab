"""Independent expectations for artifacts, public process edges and corpus results."""

import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.corpus import evaluate


def main():
    index=json.loads((ROOT/'output/portfolio/index.json').read_text(encoding='utf-8'))
    cases={c['id']:c for c in index['cases']}
    if set(cases)!={f'case-00{i}' for i in range(1,6)}:raise ValueError('reviewed five-case set differs')
    for case in cases.values():
        if not (ROOT/case['report']).is_file():raise ValueError('missing report')
    new=json.loads((ROOT/cases['case-005']['investigation']).read_text(encoding='utf-8'))
    if new['raw_events']!=2511 or len(new['nodes'])!=3 or len(new['edges'])!=2 or len(new['chains'])!=1:raise ValueError('multi-source replay mismatch')
    if len(new['scenario']['source_sha256'])!=3:raise ValueError('approved source scope mismatch')
    public=json.loads((ROOT/cases['case-001']['investigation']).read_text(encoding='utf-8'))
    if len(public['nodes'])!=4 or len(public['edges'])!=3 or public['chains']:raise ValueError('public process topology mismatch')
    result=evaluate();metric=result['metrics']['holdout']['identity_graph']
    if {k:metric[k] for k in ('tp','fp','tn','fn')}!={'tp':2,'fp':1,'tn':3,'fn':2}:raise ValueError('reviewed held-out errors changed; review corpus/policy before accepting')
    print('Verified five reports, three-source chain, public GUID graph and all eight held-out outcomes.')


if __name__=='__main__':main()
