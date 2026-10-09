# Operating procedure

This runbook covers the delivered single-workstation implementation. Commands run from a source checkout; the CLI/web assets and reproducible scripts are repository files. Acquired log/packet contents are treated as data. Recorded command text is never a deployment instruction.

## 1. Prerequisites and workspace

Use Python 3.11+ for the core and Windows PowerShell for native EVTX/channel operations. No third-party Python package is required for normal operation. Public downloads and optional runtime installation need network access to the cataloged official sources.

Keep source under the checkout and mutable native evidence under `%LOCALAPPDATA%/SOCInvestigationLab/live/default`. Use fresh run IDs and output paths for retained analysis. Private snapshots/captures/context remain in the private cache or ignored `data/local`; an ignored file still requires appropriate local access and retention handling.

Preflight from the checkout:

```powershell
python --version
python -m soclab --help
python scripts/verify_checksums.py
```

Channel acquisition reads only existing enabled/readable sources. It does not install Sysmon or enable Security auditing. Missing Security/Sysmon coverage must be recorded before interpreting findings. The delivered real-collection evidence came from System/PowerShell and remains a dated finite run.

## 2. Incremental native collection

Start a finite foreground collector/detector worker:

```powershell
python -m soclab live run --channels System --seconds 3600 --interval 10
```

Include PowerShell only when readable:

```powershell
python -m soclab live run --channels System Microsoft-Windows-PowerShell/Operational --seconds 3600 --interval 10
```

Restarting the same workspace resumes committed cursors. `--seconds 0` performs one cycle; invocation duration is bounded to one day. Ctrl+C stops the foreground process. No installed/autostart service is created.

In a separate terminal:

```powershell
python -m soclab live serve --port 8766
python -m soclab live status
```

The console is at `http://127.0.0.1:8766`; `/metrics` exposes aggregate queue/collector/detection/database state. Inspect last errors, gap counters, channel coverage, stored events and private hold count before reviewing alerts. Native outbox state `held_private` is expected; the implementation does not forward these records to Loki.

## 3. Alert and case procedure

Review original event/source anchors before changing status. Assignment sets a self-declared owner label. Record a rationale, use the current revision and transition through triage/investigation before escalation or closure. A stale revision requires reloading the retained state.

Live alert closure uses `suspicious_activity`, `expected_activity` or `insufficient_evidence`. The separate case workflow uses `confirmed_in_lab`, `expected_activity` or `insufficient_evidence`. A rule's suggested severity is not a confirmed business-impact assessment. Review targets are policy intervals from alert creation, not measured response SLAs.

Promotion creates or recovers an anchored case and records linkage. The linked case remains a separate workflow. Export the reviewed revision and retain its digest independently; exports include original retained objects and audit snapshots but do not replace original EVTX/PCAP acquisition files.

No console action isolates an endpoint, changes an account or blocks a destination. Response proposals remain a documented decision requiring verified scope, authority and business impact.

## 4. Retrospective Windows investigation

Rebuild the pinned public collections and constructed context case on Windows:

```powershell
./scripts/reproduce.ps1 -RunId acquisition-20261009
python scripts/verify_portfolio.py
python scripts/build_advanced.py --run-id reconstruction-20261009
python scripts/verify_advanced.py
python scripts/build_operations.py --run-id investigation-20261009
./scripts/inspect_ast.ps1 -InputPath output/operations/investigation-20261009/public-quoted.txt -OutputPath output/operations/investigation-20261009/public-quoted.ast.json
python scripts/verify_operations.py --run-id investigation-20261009
python -m soclab serve --operations-db output/operations/investigation-20261009/cases.sqlite
```

The historical explorer is at `http://127.0.0.1:8765`. Evidence source objects remain read-only to analyst decisions. `output/portfolio/index.json` identifies the actual database/source paths, including the separate supplement. Different IDs are needed for another run.

`verify_portfolio.py` refreshes `evidence/portfolio-validation.json` by design. That is a local regenerated attestation, not permission to overwrite a reviewed release inventory. Retain the new run separately; review/rebuild the published inventory only when deliberately publishing new evidence. Do not use `--publish-evidence` on historical builders for routine operation.

Useful retrospective pivots for the acquisition above:

```powershell
python -m soclab query auth_summary --db output/portfolio/acquisition-20261009/case-002/evidence.sqlite
python -m soclab search --db output/portfolio/acquisition-20261009/case-002/evidence.sqlite --event-id 4624
python -m soclab query powershell_content --db output/portfolio/acquisition-20261009/case-003/evidence.sqlite
```

The public authentication file contains only failures; zero returned success records is absence in this acquisition. Do not join the independent credential supplement or network captures to fill that gap.

## 5. Optional native backend

Install/start only the pinned runtime components needed:

```powershell
./scripts/runtime.ps1 -Action Install -Component Loki
./scripts/runtime.ps1 -Action Start -Component Loki
./scripts/runtime.ps1 -Action Status
```

For Grafana with Loki, use `-Component All`. [runtime-lock.json](../deployment/runtime-lock.json) defines official versions/hashes; the mutable runtime and local credentials reside outside Git. Bindings remain loopback: Loki 3100, Grafana 3000. [RUNBOOK_V3.md](RUNBOOK_V3.md) retains the detailed dashboard/bootstrap configuration.

Verify historical records with an independently named replay:

```powershell
python scripts/validate_backend.py --run-id backend-20261009 --out output/backend-20261009-validation.json
```

Historical queries retain original time. Dashboard replay uses a separate `replay_now` stream and preserves original timestamps in JSON. A dashboard time window is not original incident chronology.

The operational delivery acceptance scenario uses constructed records and an actual local HTTP outage:

```powershell
python scripts/validate_live.py --backend --run-id reliability-20261009 --out output/reliability-20261009-validation.json
python -m soclab live serve --workspace output/live/reliability-20261009 --port 8766
```

This asserts 19 unique UIDs returned from actual Loki after restart/recovery. Without `--backend`, successful delivery uses an explicit acceptance test double. The real HTTP 503 and fresh-process queue checks still run; the two modes must not be reported as equivalent backend evidence.

Stop owned backend processes when no longer needed:

```powershell
./scripts/runtime.ps1 -Action Stop
```

## 6. Queue maintenance and failures

| Observation | Required handling |
| --- | --- |
| Channel read fails | Retain cursor/error; record missing coverage; resolve permission/source availability |
| Gap/reset increases | Preserve acquisition/cursor diagnostics; record possible loss; recent bootstrap does not restore overwritten history |
| Pending count/age grows | Check backend health and retained errors; keep persisted evidence/payload |
| Sending rows survive crash | Allow lease expiry; remote acceptance may already have happened |
| Dead letter appears | Diagnose endpoint/error first; explicit actor/reason redrive after repair |
| Held-private count grows | Expected native-data protection; do not relabel telemetry to make delivery green |
| Capacity rejection | Snapshot/retain workspace; plan a fresh workspace/retention action; cursor must not be advanced manually |
| Revision/audit/export mismatch | Retain divergent state; reload or investigate; do not rewrite a packet to match a preferred verdict |

Explicit synthetic-workspace redrive after backend repair:

```powershell
python -m soclab live retry --workspace output/live/reliability-20261009 --actor operator --reason "Backend repaired; resume retained synthetic delivery."
python -m soclab live drain --workspace output/live/reliability-20261009
python -m soclab live status --workspace output/live/reliability-20261009
```

At-least-once semantics remain after repair. Stored data outside the detection window requires explicit retrospective analysis; restoring a workspace does not retroactively evaluate every old event.

## 7. Packet acquisition and analysis

Retain the acquired PCAP, its hash, acquisition reason, capture time/vantage and coverage notes before analysis. The parser accepts the documented classic-PCAP/IPv4 subset; unsupported formats/protocols and reconstruction gaps do not establish clean traffic.

Analyze a locally approved capture into a fresh bundle:

```powershell
python -m soclab network --capture data/local/acquisition.pcap --out output/network/acquisition-20261009
```

Add verified context and explicitly approved endpoint sources when available:

```powershell
python -m soclab network --capture data/local/acquisition.pcap --endpoint-db data/local/endpoint.sqlite --scope data/local/network-scope.json --context data/local/asset-context.json --out output/network/context-20261009
```

Scope fields are `capture_sha256`, `endpoint_source_sha256` (the complete approved imported-source hash set) and `collection_reason`. Context fields are `capture_sha256`, `kind` and `assets`; each asset requires `ip`, `name`, `owner`, `business_service`, `criticality`, `data_classification`. Use `kind: private_host` for acquired private host data, not the fictional inventory from the validation fixture.

A hash-bound manifest declares operator approval, not authenticated custody. Two matching candidates remain two candidates. Priority derived from inventory does not settle incident severity or authorization.

Serve only a selected local bundle on loopback:

```powershell
python -m http.server 8767 --bind 127.0.0.1 --directory output/network/acquisition-20261009
```

The report is at `http://127.0.0.1:8767/index.html`. Stop with Ctrl+C. This is a static local viewer without authentication; private captures/reports are not public artifacts.

## 8. Independent protocol acceptance

Reproduce both pinned public protocol captures and the inert constructed scenario:

```powershell
python scripts/validate_network.py --public --run-id protocol-20261009 --out output/protocol-20261009-validation.json
```

Optional independent decoder installation is hash-pinned and separate from core dependencies:

```powershell
python -m pip install --target output/validation-deps --require-hashes -r requirements-network-validation.txt
python scripts/validate_network.py --public --independent --dependencies-dir output/validation-deps --run-id independent-protocol-20261009 --out output/independent-protocol-20261009-validation.json
```

Expected public counts: HTTP 43 packets/3 flows/2 DNS messages/2 requests; DNS 38 packets/8 flows/38 DNS messages. The constructed scope retains 17 packets, three review leads, two endpoint candidates and `unassessed`. No attack traffic or backup command is generated.

Original frame extraction from a cataloged acquisition:

```powershell
python -m soclab network --capture data/raw/network/http.cap --packet 4 --source-sha256 25a72bdf10339f2c29916920c8b9501d294923108de8f29b19aba7cc001ab60d --out output/http-packet-4-20261009.json
```

The JSON contains original references and hex bytes. Retain it beside the unchanged original capture. Do not visit historical observed domains or treat a request body as executable content.

## 9. Snapshot and recovery

For the default native workspace:

```powershell
$taskLiveRoot = Join-Path $env:LOCALAPPDATA "SOCInvestigationLab/live"
python -m soclab live snapshot --out (Join-Path $taskLiveRoot "snapshot-20261009.zip")
python -m soclab live restore --source (Join-Path $taskLiveRoot "snapshot-20261009.zip") --workspace (Join-Path $taskLiveRoot "restored-20261009")
python -m soclab live status --workspace (Join-Path $taskLiveRoot "restored-20261009")
```

Snapshot/restore require new destinations and verified inventory/hashes/database integrity. Retain the original workspace during validation. Do not operate original/restored delivery agents simultaneously. An interrupted restore can leave a partial destination; inspect it and choose a new destination for a new restore rather than declaring success.

Release/checksum inventories cover deliberately published evidence only. Private backups, original captures and host XML are retained under a separate local retention decision. No measured RTO/RPO, automatic retention or enterprise recovery claim is part of the runbook.
