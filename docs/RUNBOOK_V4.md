# Operate the v4 pilot on Windows

Use Python 3.11+ from a source checkout. The core needs no third-party Python packages. Native Loki is optional; Grafana and the historical casebook can be stopped when RAM is needed. On Windows the default mutable workspace is `%LOCALAPPDATA%/SOCInvestigationLab/live/default`, outside Git and OneDrive. Explicit workspaces under ignored `data/local` are also accepted, but the default cache is preferable for a continuously written SQLite database.

## Collect and monitor existing channels

```powershell
python -m soclab live collect --channel System
python -m soclab live run --channels System Microsoft-Windows-PowerShell/Operational --seconds 3600 --interval 10
```

The second command runs in the foreground for roughly one hour, polling and evaluating each configured channel. Use Ctrl+C to stop, or let the duration end. Restarting with the same workspace resumes committed cursors. `--seconds 0` runs one cycle; duration is bounded to one day per invocation. This release does not install an autostart service.

Security and Sysmon may be added to `--channels` only if present and readable in your session. A read failure retains the cursor and records a collector error. Read channel coverage before interpreting an empty alert queue. PowerShell collection scripts can themselves appear in PowerShell telemetry and trigger a text rule. Treat such matches as review leads; inspect the original XML/text locally. Native raw data is never sent by v4's backend delivery worker.

Open the console in another terminal:

```powershell
python -m soclab live serve --port 8766
```

Visit http://127.0.0.1:8766. Review collection errors/gaps, stored event counts and the private hold count. Use the queue to assign a lead, review its original event, record rationale, transition status and choose a closure verdict. Actor labels are local labels, not authenticated users.

## Reproduce the public operational exercise

This creates a new **synthetic** workspace; it does not generate attack activity on the host:

```powershell
python scripts/validate_live.py --run-id practice-v4 --out output/practice-v4-validation.json
python -m soclab live serve --workspace output/live/practice-v4 --port 8766
```

The validator imports 19 constructed records in two batches, preserves one overlapping observation as a duplicate, produces eight leads and joins AUTH-001 across the batch boundary. A real local test HTTP server returns 503. A fresh Python process confirms the pending queue survived. The validator then exercises analyst escalation, case linkage, audited packet export and verified snapshot/restore. Without `--backend`, successful delivery uses an explicit acceptance test double.

For actual Loki ingestion, first use the [native runtime runbook](RUNBOOK_V3.md), then:

```powershell
python scripts/validate_live.py --backend --run-id practice-v4-loki --out output/practice-v4-loki-validation.json
```

The script queries the real backend and verifies all 19 stored UIDs. Choose a new run ID/output path for every validation. The dashboard's older replay selector does not display `soclab_live` streams; use Loki/LogQL `{job="soclab_live",scope="demo-practice-v4-loki",kind="synthetic"}` for this run.

## Delivery troubleshooting

| Observation | Action |
| --- | --- |
| Pending count grows | Check native Loki status/health; keep evidence and queue intact |
| Sending rows remain after a worker crash | Wait for the 180-second lease expiry; remote acceptance may have occurred |
| Dead-letter count appears | Repair endpoint/configuration, inspect safe error codes locally, then explicitly redrive |
| Held-private count grows | Expected privacy behavior; v4 does not deliver real host records |
| Collector cursor stops with capacity error | Snapshot/retain the workspace, inspect backlog and rotate to a fresh workspace; do not delete evidence to make a demo green |
| Gap/reset counter increases | Record the coverage gap; request the overwritten acquisition if available; recent bootstrap does not recover lost records |
| Revision conflict | Reload the selected alert before applying another decision |
| Existing export differs | Retain the divergent packet for investigation; do not overwrite the reviewed copy |

Explicit redrive records an operator reason:

```powershell
python -m soclab live retry --workspace output/live/practice-v4-loki --actor lab-operator --reason "Local Loki is healthy after repair; resume retained delivery."
python -m soclab live drain --workspace output/live/practice-v4-loki
python -m soclab live status --workspace output/live/practice-v4-loki
```

The status JSON and http://127.0.0.1:8766/metrics expose backlog, duplicates, overdue review targets, database/WAL size and collector/detection state. Review targets do not establish measured response performance.

## Retain, recover and rotate

```powershell
$taskLiveRoot = Join-Path $env:LOCALAPPDATA "SOCInvestigationLab/live"
python -m soclab live snapshot --out (Join-Path $taskLiveRoot "host-backup.zip")
python -m soclab live restore --source (Join-Path $taskLiveRoot "host-backup.zip") --workspace (Join-Path $taskLiveRoot "host-restored")
python -m soclab live status --workspace (Join-Path $taskLiveRoot "host-restored")
```

The ZIP retains SQLite snapshots, original batch archives and a hash inventory. Private backup/restore stays under the private cache or ignored `data/local`. Output paths must be new. Do not run both restored and original copies as active delivery agents. Interrupted restore can leave a partial destination; inspect it and choose a new destination for another verified restore. Keep raw acquisition archives and reviewed packets under the retention policy you decide for the lab.

Source collection has a deliberate bounded bootstrap and event-time detection has a finite window. Restoring or rotating a workspace does not retroactively evaluate all old events. Use the historical CLI for explicit retrospective investigation. No measured recovery-time objective or representative production accuracy is claimed.
