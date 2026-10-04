"""Check independently recorded case expectations, queries and reproducible evidence."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from soclab.query import run_query
from soclab import __version__

EXPECTED = {
    "case-001": (8, {"WIN-004":1,"WIN-008":1}),
    "case-002": (3561, {"AUTH-002":1}),
    "case-003": (3, {"WIN-009":1}),
    "case-004": (4, {"WIN-002":3,"WIN-001":1}),
}


def main():
    index=json.loads((ROOT/"output/portfolio/index.json").read_text(encoding="utf-8"))
    records=[]
    if {case["id"] for case in index["cases"]} != set(EXPECTED):raise ValueError("case set differs from reviewed portfolio")
    for case in index["cases"]:
        manifest=json.loads((ROOT/case["analysis"]/"manifest.json").read_text(encoding="utf-8"))
        count,findings=EXPECTED[case["id"]]
        if manifest["event_count"]!=count or manifest["findings_by_rule"]!=findings:raise ValueError(f"case result mismatch: {case['id']}")
        if not (ROOT/case["report"]).is_file():raise ValueError("missing analyst report")
        records.append({"case":case["id"],"dataset_kind":case["kind"],"event_count":count,
                        "rule_counts":findings,"status_counts":manifest["findings_by_status"],
                        "source_jsonl_sha256":[s["sha256"] for s in manifest["sources"]],
                        "rules_sha256":manifest["rules_sha256"],"result":"matched reviewed expectations"})
        db=ROOT/case["db"]
        if case["id"]=="case-001" and len(run_query(db,"mshta_remote"))!=1:raise ValueError("mshta query mismatch")
        if case["id"]=="case-002":
            rows=run_query(db,"auth_summary")
            if sum(r["event_count"] for r in rows)!=3561 or any(r["event_id"]!=4625 for r in rows):raise ValueError("authentication query mismatch")
        if case["id"]=="case-003" and len(run_query(db,"powershell_content"))!=3:raise ValueError("PowerShell query mismatch")
        if case["id"]=="case-004" and manifest["findings_by_status"]!={"context_allowlisted":1,"needs_review":3}:raise ValueError("context status mismatch")
    supplement=ROOT/"output/portfolio"/index["run_id"]/"supplement/analysis/manifest.json"
    m=json.loads(supplement.read_text(encoding="utf-8"))
    if m["event_count"]!=295 or m["findings_by_rule"]!={"WIN-007":1,"AUTH-003":2}:raise ValueError("independent supplement mismatch")
    source_digest=hashlib.sha256()
    for path in sorted((ROOT/"soclab").glob("*.py")):
        source_digest.update(path.name.encode());source_digest.update(path.read_bytes())
    result={"validation_date":"2026-10-04","version":__version__,"run_id":index["run_id"],
            "engine_source_sha256":source_digest.hexdigest(),"cases":records,
            "supplement":{"event_count":295,"rule_counts":m["findings_by_rule"],"scope":"Independent dataset, not joined to the primary authentication case"},
            "primary_events":sum(c["event_count"] for c in records),"public_events_including_supplement":3867,
            "scope":"Exact historical and constructed datasets; no production performance claim"}
    target=ROOT/"evidence/portfolio-validation.json"
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":main()
