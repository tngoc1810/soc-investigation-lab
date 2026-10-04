"""Push actual local evidence to Loki; assert LogQL counts and UID pivots."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.loki import Loki
from soclab.store import iter_events


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--run-id",default="backend-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    parser.add_argument("--out",type=Path,default=Path("output/backend-validation.json"))
    args=parser.parse_args()
    if args.out.exists(): raise ValueError("validation artifact already exists")
    index=json.loads((ROOT/"output/portfolio/index.json").read_text(encoding="utf-8-sig"))
    client=Loki()
    version=client.request("/loki/api/v1/status/buildinfo")
    results=[]
    for case in index["cases"]:
        events=list(iter_events(ROOT/case["db"]))
        replay=client.replay(events,case_id=case["id"],run_id=args.run_id,kind="public" if case["kind"]=="Public EVTX" else "synthetic")
        # Historical filesystem streams need a flush and index resync before
        # every querier path can find the newly uploaded chunks.
        client.request("/flush", {})
        span_seconds=(replay["end_ns"]-replay["start_ns"])//1_000_000_000+2
        selector='{job="soclab",case_id='+json.dumps(case["id"])+',replay_run='+json.dumps(args.run_id)+',mode="historical"}'
        expression=f"sum(count_over_time({selector}[{span_seconds}s]))"
        for attempt in range(40):
            response=client.query(expression,replay["end_ns"]+1000)
            vector=response["data"]["result"]
            actual=int(float(vector[0]["value"][1])) if vector else 0
            if actual==len(events): break
            time.sleep(0.5)
        if actual!=len(events): raise AssertionError(f"{case['id']}: Loki {actual} != SQLite {len(events)}")
        pivot_event=next((e for e in events if e["event_id"]==1),events[0])
        pivot=selector+' | json | event_uid = '+json.dumps(pivot_event["event_uid"])
        matched=client.logs(pivot,replay["start_ns"]-1,replay["end_ns"]+1)
        values=[v for stream in matched["data"]["result"] for v in stream["values"]]
        if len(values)!=1 or json.loads(values[0][1])["source_sha256"]!=pivot_event["source_sha256"]: raise AssertionError("evidence UID pivot failed")
        results.append({"case_id":case["id"],"kind":case["kind"],"replay":replay,"count_query":expression,"count_response":response,"uid_query":pivot,"uid_response":matched,"expected_records":len(events),"observed_records":actual})
    chain_case=next(c for c in index["cases"] if c["id"]=="case-005")
    # Display only the eleven meaningful records; 2,500 inert background events
    # remain in the historical stream and were counted by the assertion above.
    display=[e for e in iter_events(ROOT/chain_case["db"]) if e["host"]!="QUIET-WS-LAB"]
    live=client.replay(display,case_id="case-005",run_id=args.run_id,kind="synthetic",mode="replay_now")
    client.request("/flush", {})
    queries=[]
    for event_id,expected in ((4625,5),(4624,1),(1,3),(3,1),(4698,1)):
        expression='{job="soclab",case_id="case-005",replay_run='+json.dumps(args.run_id)+',mode="replay_now"} | json | event_id = '+str(event_id)
        for attempt in range(40):
            response=client.logs(expression,live["start_ns"]-1_000_000_000,live["end_ns"]+1_000_000_000)
            count=sum(len(stream["values"]) for stream in response["data"]["result"])
            if count==expected: break
            time.sleep(0.5)
        if count!=expected: raise AssertionError(f"live replay event {event_id}: {count} != {expected}")
        queries.append({"event_id":event_id,"query":expression,"expected":expected,"observed":count,"response":response})
    artifact={"schema_version":1,"validated_at":datetime.now(timezone.utc).isoformat(),"run_id":args.run_id,"backend":version,
              "transport_sha256":hashlib.sha256((ROOT/"soclab/loki.py").read_bytes()).hexdigest(),"historical_cases":results,"dashboard_replay":live,"dashboard_queries":queries,
              "scope":"Executed against localhost Loki. Public samples and synthetic records only. Grafana UI verification is a separate artifact."}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(artifact,indent=2,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"backend":version,"historical_records":sum(r["observed_records"] for r in results),"verified_case_counts":{r["case_id"]:r["observed_records"] for r in results},"dashboard_records":len(display),"artifact":str(args.out)},indent=2))


if __name__=="__main__": main()
