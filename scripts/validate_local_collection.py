"""Publish only aggregate validation; never publish real host event content."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.store import ingest, iter_events


if __name__=="__main__":
    source=Path(sys.argv[1]).resolve()
    if not source.is_relative_to(ROOT/"data/local"): raise ValueError("private collector source required")
    db=ROOT/"data/local/collector-validation.sqlite"
    result=ingest(source,db)
    events=[e for e in iter_events(db) if e["source_sha256"]==result["source_sha256"]]
    if not events or len(events)>200 or any(e["channel"]!="System" or json.loads(e["original_json"])["provenance"]["kind"]!="real_host_collection" for e in events): raise AssertionError("collector scope mismatch")
    artifact={"kind":"actual read-only local host collection","channel":"System","event_count":len(events),"source_sha256":result["source_sha256"],"events_by_id":dict(Counter(str(e["event_id"]) for e in events)),"original_xml_retained":all("original_xml" in json.loads(e["original_json"]) for e in events),"collector_sha256":hashlib.sha256((ROOT/"scripts/collect_system.ps1").read_bytes()).hexdigest(),"scope":"Existing operational records only; no attack stimulus. Raw records, hostname, users, paths and messages remain private and are excluded from GitHub and screenshots."}
    target=ROOT/"evidence/operations/local-collector-validation.json"
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(artifact,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps(artifact,indent=2))
