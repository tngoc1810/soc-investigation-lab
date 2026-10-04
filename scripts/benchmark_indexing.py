"""Compare released v2 code with indexed v3 on a constructed auth workload."""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.events import normalize_event
from soclab.investigation import investigate

BASELINE="c213b0734507c4c391baa32c8cc0827f26a6ebfd"


def workload(accounts=200):
    # Five failures and one success per domain-qualified identity; no execution
    # telemetry. All candidates must remain incomplete under either engine.
    source="a"*64
    events=[]
    for account in range(accounts):
        for sequence in range(6):
            raw={"timestamp":"2026-09-03T10:00:0"+str(sequence)+"Z","host":"AUTH-SCALE-LAB","channel":"Security","provider":"Microsoft-Windows-Security-Auditing","event_id":4625 if sequence<5 else 4624,"record_id":len(events)+1,"event_data":{"TargetUserName":f"account{account}.lab","TargetDomainName":"LAB","IpAddress":"192.0.2.20","LogonType":"3","LogonGuid":"00000000-0000-0000-0000-000000000000"}}
            events.append(normalize_event(raw,source,len(events)+1))
    return events,{"id":"indexing-synthetic","collection_reason":"One constructed source, same workload for both code versions.","source_sha256":[source]}


def child(args):
    engine=investigate
    if args.engine=="v2":
        spec=importlib.util.spec_from_file_location("soclab._v2_benchmark",args.baseline_path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);engine=module.investigate
    events,scope=workload(args.accounts)
    started=time.perf_counter();result=engine(events,scope);elapsed=time.perf_counter()-started
    comparable={key:result[key] for key in ("raw_events","unique_observations","nodes","edges","chains","candidates","diagnostics")}
    digest=hashlib.sha256(json.dumps(comparable,sort_keys=True,separators=(",", ":")).encode()).hexdigest()
    peak=None
    if sys.platform=="win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_=[("cb",wintypes.DWORD),("PageFaultCount",wintypes.DWORD)]+[(name,ctypes.c_size_t) for name in ("PeakWorkingSetSize","WorkingSetSize","QuotaPeakPagedPoolUsage","QuotaPagedPoolUsage","QuotaPeakNonPagedPoolUsage","QuotaNonPagedPoolUsage","PagefileUsage","PeakPagefileUsage")]
        counters=Counters();counters.cb=ctypes.sizeof(counters)
        handle=ctypes.windll.kernel32.GetCurrentProcess()
        ctypes.windll.psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle,ctypes.byref(counters),counters.cb): peak=counters.PeakWorkingSetSize/1048576
    print(json.dumps({"engine":args.engine,"seconds":elapsed,"peak_process_working_set_mib":peak,"result_sha256":digest,"events":len(events),"incomplete_candidates":len(result["candidates"]),"complete_chains":len(result["chains"])}))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--accounts",type=int,default=200)
    parser.add_argument("--engine",choices=("v2","v3"))
    parser.add_argument("--baseline-path",type=Path)
    parser.add_argument("--out",type=Path,default=Path("evidence/operations/indexing-benchmark.json"))
    args=parser.parse_args()
    if not 1<=args.accounts<=1000: raise ValueError("accounts must be 1..1000")
    if args.engine: child(args);return
    if args.out.exists(): raise ValueError("benchmark output already exists")
    baseline=ROOT/"output/indexing-benchmark/v2.py"
    baseline.parent.mkdir(parents=True,exist_ok=True)
    raw=subprocess.run(["git","show",BASELINE+":soclab/investigation.py"],cwd=ROOT,check=True,capture_output=True).stdout
    baseline.write_bytes(raw)
    rows=[]
    for engine in ("v2","v3"):
        for _ in range(3):
            result=subprocess.run([sys.executable,__file__,"--engine",engine,"--accounts",str(args.accounts),"--baseline-path",str(baseline)],cwd=ROOT,check=True,capture_output=True,text=True)
            rows.append(json.loads(result.stdout))
    if len({r["result_sha256"] for r in rows})!=1: raise AssertionError("engine output semantics changed on benchmark workload")
    medians={engine:statistics.median(r["seconds"] for r in rows if r["engine"]==engine) for engine in ("v2","v3")}
    artifact={"baseline_commit":BASELINE,"baseline_file_sha256":hashlib.sha256(raw).hexdigest(),"indexed_file_sha256":hashlib.sha256((ROOT/"soclab/investigation.py").read_bytes()).hexdigest(),"accounts":args.accounts,"trials":rows,"median_seconds":medians,"speedup_on_this_workload":medians["v2"]/medians["v3"],"scope":"Six fresh Python processes. Synthetic auth-heavy workload; identical output digest. Timing covers investigate(), memory covers the whole child process. Not backend, browser, live throughput, or a general speed guarantee."}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(artifact,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps(artifact,indent=2))


if __name__=="__main__":main()
