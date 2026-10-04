"""Publish only the reviewed public/synthetic exercise artifacts, not host logs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.operations import get_case, list_cases


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--run-id",required=True);args=parser.parse_args()
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.run_id): raise ValueError("invalid run ID")
    source=ROOT/"output/operations"/args.run_id
    target=ROOT/"evidence/operations"
    target.mkdir(parents=True,exist_ok=True)
    case=list_cases(source/"cases.sqlite")[0]
    result=get_case(source/"cases.sqlite",case["id"])
    if case["source_case"]!="case-005" or case["status"]!="escalated": raise ValueError("only the reviewed synthetic exercise may be published")
    for record in case["evidence"]:
        if record["original"]["host"]!="WS-CHAIN-LAB" or record["original"].get("provenance",{}).get("kind")!="synthetic": raise ValueError("unexpected evidence scope")
    archive_path=source/"exports"/f"case-{case['id']}-r{case['revision']}.zip"
    with zipfile.ZipFile(archive_path) as archive:
        manifest=json.loads(archive.read("manifest.json"))
        if manifest["audit_anchor_sha256"]!=result["anchor_sha256"]: raise AssertionError("export does not match reviewed state")
        if set(archive.namelist())!={"case.json","audit.json","evidence.jsonl","report.md","manifest.json"}: raise AssertionError("unexpected export files")
        bundle=target/"reviewed-bundle";bundle.mkdir(exist_ok=True)
        for name in archive.namelist():
            raw=archive.read(name)
            if name in manifest["files"] and hashlib.sha256(raw).hexdigest()!=manifest["files"][name]: raise AssertionError("bundle integrity mismatch")
            (bundle/name).write_bytes(raw)
    for name in ("hunts.json","forensics.json"):
        shutil.copyfile(source/name,target/name)
    ast_dir=target/"ast";ast_dir.mkdir(exist_ok=True)
    for path in source.glob("*.ast.json"): shutil.copyfile(path,ast_dir/path.name)
    record={"published_at":datetime.now(timezone.utc).isoformat(),"run_id":args.run_id,"case_id":case["id"],"source_case":case["source_case"],"status":case["status"],"revision":case["revision"],"evidence_count":len(case["evidence"]),"audit_anchor_sha256":result["anchor_sha256"],"zip_sha256":hashlib.sha256(archive_path.read_bytes()).hexdigest(),"scope":"Actual local workflow and browser attachment over constructed case-005 evidence. Published directory is the verified content of the local ZIP; raw private host records are excluded."}
    (target/"workflow-validation.json").write_text(json.dumps(record,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps(record,indent=2))


if __name__=="__main__":main()
