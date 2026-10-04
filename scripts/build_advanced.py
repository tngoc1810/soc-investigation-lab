"""Build v2 investigation artifacts after the four-case Windows replay."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from soclab.corpus import sample_events, scenarios, write_evaluation
from soclab.investigation import investigate
from soclab.report import analyze
from soclab.store import ingest, iter_events, sources


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-id',default='v2-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S'))
    args=parser.parse_args()
    if not args.run_id or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in args.run_id):
        parser.error('run-id needs simple letters/numbers/hyphens/underscores')
    index_path=ROOT/'output/portfolio/index.json'
    index=json.loads(index_path.read_text(encoding='utf-8-sig'))
    bundle=ROOT/'output/portfolio'/args.run_id
    if bundle.exists():raise ValueError('advanced run already exists; choose a new run ID')
    groups={'security':[],'sysmon':[],'background':[]}
    for e in sample_events():groups['security' if e['channel']=='Security' else 'sysmon'].append(e)
    for i in range(2500):
        groups['background'].append({'timestamp':'2026-09-03T09:00:00Z','host':'QUIET-WS-LAB','channel':'Security','provider':'Microsoft-Windows-Security-Auditing',
                                     'event_id':4634,'record_id':10000+i,'event_data':{'TargetUserName':'inventory.lab','TargetDomainName':'LAB','LogonType':'3','TargetLogonId':hex(i+4096)},
                                     'provenance':{'kind':'synthetic','note':'Inert background logoff fixture; not a scale benchmark'}})
    db=bundle/'case-005/evidence.sqlite';approved=[]
    for name,events in groups.items():
        path=ROOT/f'data/fixtures/chain-{name}.jsonl'
        path.write_text(''.join(json.dumps(e,ensure_ascii=False,sort_keys=True)+'\n' for e in events),encoding='utf-8',newline='\n')
        approved.append(ingest(path,db)['source_sha256'])
    scope={'id':'CASE-005-synthetic-collection','collection_reason':'Security, Sysmon and background fixtures generated together; explicit scope is limited to these three exact sources.',
           'kind':'synthetic','source_sha256':approved}
    scope_path=ROOT/'data/scenarios/chain-collection.json';write(scope_path,scope)
    analysis=bundle/'case-005/analysis'
    manifest=analyze(db,ROOT/'rules/windows.json',analysis)
    result=investigate(list(iter_events(db)),scope)
    write(bundle/'case-005/investigation.json',result)
    if len(result['chains'])!=1 or len(result['nodes'])!=3 or len(result['edges'])!=2:raise ValueError('advanced collection differs from reviewed topology')
    legacy=[c for c in index['cases'] if c['id']!='case-005']
    for case in legacy:
        case_scope={'id':case['id'],'collection_reason':'Single case database from pinned replay; independent from all other cases.','source_sha256':[s['sha256'] for s in sources(ROOT/case['db'])]}
        target=bundle/case['id']/'investigation.json'
        write(target,investigate(list(iter_events(ROOT/case['db'])),case_scope))
        case['investigation']=str(target.relative_to(ROOT)).replace('\\','/')
    legacy.append({'id':'case-005','title':'Authentication to execution: reconstruct a scoped investigation','kind':'Synthetic multi-source experiment',
                   'verdict':'Escalate constructed chain; task execution unproven','report':'cases/005-multisource-chain/report.md',
                   'db':str(db.relative_to(ROOT)).replace('\\','/'),'analysis':str(analysis.relative_to(ROOT)).replace('\\','/'),
                   'investigation':str((bundle/'case-005/investigation.json').relative_to(ROOT)).replace('\\','/')})
    corpus=[]
    for case in scenarios():
        path=ROOT/f"data/corpus/{case['id']}.json"
        write(path,case)
        corpus.append({'id':case['id'],'split':case['split'],'path':str(path.relative_to(ROOT)).replace('\\','/'),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    write(ROOT/'data/corpus/manifest.json',{'unit':'isolated synthetic scenario','labels':'constructed review intent; never passed to the engine','cases':corpus})
    evaluation_path=bundle/'evaluation.json';evaluation=write_evaluation(evaluation_path)
    index.update(cases=legacy,advanced_run_id=args.run_id,evaluation=str(evaluation_path.relative_to(ROOT)).replace('\\','/'))
    write(index_path,index)
    summary={'version':'2.0.0','run_id':args.run_id,'new_case_events':manifest['event_count'],'new_case_base_findings':manifest['findings_by_rule'],
             'process_nodes':len(result['nodes']),'observed_parent_edges':len(result['edges']),'complete_chain_leads':len(result['chains']),
             'evaluation':evaluation['metrics'],'scope':'Constructed experiment and public graphs; offline only'}
    write(ROOT/'evidence/advanced/replay-validation.json',summary)
    write(ROOT/'evidence/advanced/evaluation.json',evaluation)
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
