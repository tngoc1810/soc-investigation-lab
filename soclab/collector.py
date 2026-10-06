"""Incremental Windows event reader and finite/continuous operations worker."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from . import live

CHANNELS=('System','Security','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')


def native_available():
    return os.name=='nt'


def poll(workspace, *, channel='System', max_events=20):
    if not native_available(): raise ValueError('native collector requires Windows')
    if channel not in CHANNELS or not 1<=max_events<=200: raise ValueError('unsupported channel or batch bound')
    workspace=Path(workspace).resolve()
    if not live.private_path(workspace):
        raise ValueError('native collector workspace must be under data/local or the private live cache')
    scope='windows-'+hashlib.sha256(channel.encode()).hexdigest()[:12]
    state=live.collector_state(workspace,scope); cursor=state['cursor'] if state else {'record_id':0}
    target=workspace/'incoming'/f'{uuid.uuid4().hex}.jsonl'
    command=['powershell.exe','-NoProfile','-NonInteractive','-File',str(live.ROOT/'scripts/poll_windows.ps1'),'-Channel',channel,'-After',str(cursor['record_id']),'-AfterHash',cursor.get('xml_sha256',''),'-MaxEvents',str(max_events),'-OutputPath',str(target)]
    try:
        result=subprocess.run(command,capture_output=True,timeout=60)
    except subprocess.TimeoutExpired:
        live.collector_heartbeat(workspace,scope,cursor,error='native_read_timeout')
        raise ValueError('native reader timed out; committed cursor retained') from None
    if result.returncode:
        # Record failure without advancing the cursor or exposing host details.
        live.collector_heartbeat(workspace,scope,cursor,error='native_channel_read_failed')
        raise ValueError('native channel read failed; check local permissions/channel availability')
    metadata=json.loads(result.stdout.decode('utf-8-sig'))
    next_cursor={'record_id':metadata['cursor'],'xml_sha256':metadata['cursor_hash'],'channel':channel}
    if metadata['count']:
        imported=live.ingest_batch(workspace,target,scope=scope,kind='private_host',cursor=next_cursor,gap=metadata['gap'])
    else:
        live.collector_heartbeat(workspace,scope,next_cursor,gap=metadata['gap'])
        imported={'accepted':0,'duplicates':0}
    # Poll files remain private. The immutable content-addressed archive is retained.
    if target.exists(): target.unlink()
    return {'scope':scope,**metadata,**imported}


def worker(workspace, *, channels=('System',), seconds=0, interval=10, publish_synthetic=True):
    if not 2<=interval<=300 or not 0<=seconds<=86400: raise ValueError('invalid interval/duration')
    started=time.monotonic(); cycles=0
    while True:
        results=[]
        for channel in channels:
            try:
                result=poll(workspace,channel=channel)
                result['detection']=live.run_detection(workspace,scope=result['scope'])
                results.append(result)
            except (ValueError,OSError,subprocess.SubprocessError) as exc:
                results.append({'channel':channel,'error':type(exc).__name__})
        delivery=live.drain(workspace) if publish_synthetic else {'sent':0,'failed':0}
        cycles+=1
        print(json.dumps({'cycle':cycles,'collections':results,'delivery':delivery},ensure_ascii=False),flush=True)
        if not seconds or time.monotonic()-started>=seconds: break
        time.sleep(min(interval,max(0,seconds-(time.monotonic()-started))))
    return {'cycles':cycles,'duration_seconds':round(time.monotonic()-started,3)}
