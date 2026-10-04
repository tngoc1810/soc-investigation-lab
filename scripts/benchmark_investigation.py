"""Measure fresh-process loading and reconstruction of the actual v2 collection."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
from time import perf_counter

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    p=argparse.ArgumentParser();p.add_argument('--db',type=Path,required=True);p.add_argument('--scope',type=Path,required=True)
    p.add_argument('--worker',action='store_true');p.add_argument('--out',type=Path,default=Path('evidence/advanced/benchmark.json'));args=p.parse_args()
    if args.worker:
        from soclab.investigation import investigate
        from soclab.store import iter_events
        from scripts.benchmark import peak_memory_bytes
        start=perf_counter();result=investigate(list(iter_events(args.db)),json.loads(args.scope.read_text(encoding='utf-8')))
        elapsed=perf_counter()-start
        print(json.dumps({'events':result['raw_events'],'nodes':len(result['nodes']),'chains':len(result['chains']),
                          'load_and_reconstruct_seconds':elapsed,'peak_working_set_bytes':peak_memory_bytes(),'engine_sha256':result['engine_sha256']}));return
    samples=[]
    for _ in range(3):
        run=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--db',str(args.db.resolve()),'--scope',str(args.scope.resolve()),'--worker'],capture_output=True,text=True,encoding='utf-8',check=True)
        samples.append(json.loads(run.stdout))
    result={'python':platform.python_version(),'platform':platform.system(),'runs':samples,
            'db_sha256':hashlib.sha256(args.db.read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256(args.scope.read_bytes()).hexdigest(),
            'median_load_and_reconstruct_seconds':statistics.median(s['load_and_reconstruct_seconds'] for s in samples),
            'max_peak_working_set_mib':round(max(s['peak_working_set_bytes'] for s in samples)/1024**2,2),
            'scope':'Three fresh processes on this Windows host. Includes loading and graph/chain reconstruction of 2511 synthetic events; not browser RAM, total laptop RAM, live latency or production scale.'}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
