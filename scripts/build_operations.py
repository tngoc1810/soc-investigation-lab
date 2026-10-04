"""Reproduce hunts, static forensics and an explicitly constructed analyst case."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.forensics import reconstruct, decode_command
from soclab.hunting import run_hunts
from soclab.operations import create_case, update_case, get_case, export_case
from soclab.store import ingest, iter_events


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--run-id",default="operations-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S"))
    args=parser.parse_args()
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.run_id): raise ValueError("invalid run ID")
    target=ROOT/"output/operations"/args.run_id
    if target.exists(): raise ValueError("operations run already exists")
    target.mkdir(parents=True)
    index=json.loads((ROOT/"output/portfolio/index.json").read_text(encoding="utf-8-sig"))
    hunts={case["id"]:run_hunts(ROOT/case["db"]) for case in index["cases"]}
    supplement=ROOT/"output/portfolio"/index["run_id"]/"supplement/evidence.sqlite"
    hunts["independent-credential-supplement"]=run_hunts(supplement)
    write(target/"hunts.json",hunts)
    fragment_db=target/"fragments.sqlite"
    ingest(ROOT/"data/fixtures/script-fragments.jsonl",fragment_db)
    fragments=reconstruct(iter_events(fragment_db))
    if sum(block["complete"] for block in fragments["blocks"])!=1: raise AssertionError("fragment reconstruction mismatch")
    public_case=next(c for c in index["cases"] if c["id"]=="case-003")
    public_blocks=reconstruct(iter_events(ROOT/public_case["db"]))
    public_script=next(e["event_data"]["ScriptBlockText"] for e in iter_events(ROOT/public_case["db"]) if e["event_id"]==4104 and "downloadString" in e["event_data"].get("ScriptBlockText",""))
    scripts={"public-quoted":public_script,"fixture-reassembled":next(b["script"] for b in fragments["blocks"] if b["complete"]),"fixture-command":"Write-Output 'inert command AST fixture'"}
    encoded=base64.b64encode(scripts["fixture-command"].encode("utf-16-le")).decode()
    decoded=decode_command("powershell.exe -NoProfile -EncodedCommand "+encoded)
    scripts["fixture-decoded"]=decoded["script"]
    for name,script in scripts.items(): (target/(name+".txt")).write_text(script,encoding="utf-8",newline="\n")
    write(target/"forensics.json",{"fragments":fragments,"public_blocks":public_blocks,"decoded":decoded,"encoded_command":"powershell.exe -NoProfile -EncodedCommand "+encoded})
    source=next(c for c in index["cases"] if c["id"]=="case-005")
    graph=json.loads((ROOT/source["investigation"]).read_text(encoding="utf-8"))
    uids=list(dict.fromkeys(ref["event_uid"] for stage in graph["chains"][0]["stages"] for ref in stage["evidence"]))
    workspace=target/"cases.sqlite"
    case=create_case(workspace,source_case=source["id"],evidence_db=ROOT/source["db"],uids=uids,
                     title="Constructed case: network logon followed by mshta and task creation",actor="demo-analyst",rationale="Portfolio workflow exercise generated from synthetic case 005. Five failed network logons precede a matching success. The process and task sequence needs review; this is not an incident on the host running the project.")
    decisions=[("triaged","High-priority review within the lab: source scope is approved, and account/domain/IP/logon type match. The successful logon alone does not attribute the initiating person or establish malicious intent."),
               ("investigating","Confirmed observed links: a nonzero LogonGuid, host and domain-qualified user connect the logon to mshta; ProcessGuid connects the initiated network record; an observed parent edge reaches schtasks /Create /TR. Destination 198.51.100.20 and payload.example.invalid are lab markers, not threat-intelligence verdicts."),
               ("escalated","Escalation draft: review the registered task XML and request task execution history, process termination, payload file/hash and endpoint/network evidence. The collection includes Security 4698 but does not prove task execution or payload behavior. Proposed containment would require authorization and stronger context; no containment action was performed.")]
    for status,rationale in decisions:
        case=update_case(workspace,case["id"],revision=case["revision"],action="transition",target=status,actor="demo-analyst",rationale=rationale)
    result=get_case(workspace,case["id"])
    export=export_case(workspace,case["id"],target/"exports")
    write(target/"workflow-validation.json",{"case_id":case["id"],"status":case["status"],"revision":case["revision"],"evidence_count":len(uids),"audit_anchor_sha256":result["anchor_sha256"],"export":export,"workspace":str(workspace.relative_to(ROOT)).replace("\\","/"),"scope":"Executed local workflow over synthetic records; no response action performed"})
    # A portable demonstration artifact contains only constructed evidence.
    with zipfile.ZipFile(target/"exports"/export["file"]) as archive:
        bundle=target/"reviewed-bundle"
        bundle.mkdir()
        for name in ("case.json","audit.json","evidence.jsonl","report.md","manifest.json"):
            (bundle/name).write_bytes(archive.read(name))
    print(json.dumps({"run_id":args.run_id,"target":str(target),"hunt_queries_executed":sum(len(v["hunts"]) for v in hunts.values()),"script_groups":len(fragments["blocks"]),"complete_script_groups":1,"case_status":case["status"],"decisions":case["revision"],"anchored_records":len(uids)},indent=2))


if __name__=="__main__":main()
