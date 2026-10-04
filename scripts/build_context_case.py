"""Construct transparent benign/hostile-lookalike fixtures for a tuning experiment."""

import copy
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    seed = json.loads((root / "data/fixtures/demo.jsonl").read_text(encoding="utf-8").splitlines()[7])
    events = []
    command = "powershell.exe -ExecutionPolicy Bypass -File C:\\Lab\\backup.ps1"
    for index, (user, parent, cmd, expected) in enumerate([
        ("LAB\\backup.svc", "C:\\Windows\\System32\\taskeng.exe", command, "context_allowlisted"),
        ("LAB\\analyst.lab", "C:\\Windows\\explorer.exe", command, "needs_review"),
        ("LAB\\backup.svc", "C:\\Windows\\System32\\taskeng.exe", command + " -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGwAYQBiACcA", "needs_review"),
        ("LAB\\backup.svc", "C:\\Windows\\System32\\taskeng.exe", "powershell.exe -NoProfile -File C:\\Lab\\inventory.ps1", "no_match"),
    ]):
        event = copy.deepcopy(seed)
        event["timestamp"] = f"2026-09-02T09:00:0{index}Z"
        event["host"] = "WS-TUNING-LAB"
        event["record_id"] = 2000 + index
        event["event_data"].update(User=user, ParentImage=parent, CommandLine=cmd, ProcessGuid=f"{{TUNING-{index}}}")
        event.pop("fixture_label", None)
        event["expected_context_status"] = expected
        event["provenance"] = {"kind": "synthetic", "scenario": "context-tuning-v1", "note": "Constructed events, not captured Sysmon records or actual malicious execution"}
        events.append(event)
    target = root / "data/fixtures/context-tuning.jsonl"
    target.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8", newline="\n")
    context = [{
        "id": "CTX-LAB-004", "rule_id": "WIN-002", "reason": "Exact synthetic backup scenario approved by the fixture specification; keep matching evidence visible.",
        "change_reference": "SYNTHETIC-CHANGE-004",
        "equals": {"host": "WS-TUNING-LAB", "event_data.User": "LAB\\backup.svc", "event_data.Image": seed["event_data"]["Image"], "event_data.CommandLine": command, "event_data.ParentImage": "C:\\Windows\\System32\\taskeng.exe"}
    }]
    (root / "rules/context-lab.json").write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Built 4 inert context fixtures and an exact-match laboratory context profile.")


if __name__ == "__main__":
    main()
