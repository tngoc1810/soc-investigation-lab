"""Reviewed end-to-end expectations for the portable v3 operations exercise."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.operations import get_case


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--run-id",required=True);args=parser.parse_args()
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.run_id): raise ValueError("invalid run ID")
    target=ROOT/"output/operations"/args.run_id
    workflow=json.loads((target/"workflow-validation.json").read_text(encoding="utf-8"))
    result=get_case(target/"cases.sqlite",workflow["case_id"])
    if result["case"]["status"]!="escalated" or result["case"]["revision"]!=4 or len(result["case"]["evidence"])!=9: raise AssertionError("reviewed workflow mismatch")
    archive_path=target/"exports"/workflow["export"]["file"]
    if hashlib.sha256(archive_path.read_bytes()).hexdigest()!=workflow["export"]["sha256"]: raise AssertionError("export digest mismatch")
    with zipfile.ZipFile(archive_path) as archive:
        manifest=json.loads(archive.read("manifest.json"))
        if manifest["audit_anchor_sha256"]!=result["anchor_sha256"]: raise AssertionError("audit anchor mismatch")
        for name,digest in manifest["files"].items():
            if hashlib.sha256(archive.read(name)).hexdigest()!=digest: raise AssertionError("bundle file changed")
    hunts=json.loads((target/"hunts.json").read_text(encoding="utf-8"))
    if sum(len(value["hunts"]) for value in hunts.values())!=48: raise AssertionError("hunt notebook mismatch")
    if sum(row["failures"] for row in hunts["case-002"]["hunts"][2]["rows"])!=3561: raise AssertionError("auth hunt mismatch")
    supplement=hunts["independent-credential-supplement"]
    if not supplement["hunts"][5]["rows"] or not supplement["hunts"][6]["rows"]: raise AssertionError("independent credential/audit-clear observations missing")
    forensics=json.loads((target/"forensics.json").read_text(encoding="utf-8"))
    blocks={b["script_block_id"]:b for b in forensics["fragments"]["blocks"]}
    if not blocks["complete-lab"]["complete"] or blocks["missing-lab"]["missing_parts"]!=[2] or "conflicting fragment content" not in blocks["conflict-lab"]["reasons"]: raise AssertionError("static reconstruction mismatch")
    ast_path=target/"public-quoted.ast.json"
    if ast_path.exists():
        ast=json.loads(ast_path.read_text(encoding="utf-8"))
        if ast["commands"] or ast["member_invocations"] or ast["parse_errors"] or not ast["parsed_only"]: raise AssertionError("public string AST mismatch")
    print("Verified 48 executed hunts, complete/gapped/conflicting fragments, analyst transitions, audit anchor and every export checksum.")


if __name__=="__main__":main()
