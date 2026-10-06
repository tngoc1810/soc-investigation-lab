# Windows runbook: complete lab and recovery

Use a repository checkout, Python 3.11+ and Windows PowerShell or PowerShell 7. The core needs no Python packages, Docker, VM, administrator install or endpoint configuration changes. The native backend is optional and downloads larger official archives; keep enough local disk space for the archive and extracted files.

## 1. Rebuild the evidence and operations exercise

Run from the repository root. Choose new run IDs when repeating a rebuild.

```powershell
python -m unittest discover -s tests -v
./scripts/reproduce.ps1 -RunId practice-base
python scripts/verify_portfolio.py
python scripts/build_advanced.py --run-id practice-graph
python scripts/verify_advanced.py
python scripts/build_operations.py --run-id practice-operations
./scripts/inspect_ast.ps1 -InputPath output/operations/practice-operations/public-quoted.txt -OutputPath output/operations/practice-operations/public-quoted.ast.json
python scripts/verify_operations.py --run-id practice-operations
python -m soclab serve --operations-db output/operations/practice-operations/cases.sqlite
```

Open [the workspace](http://127.0.0.1:8765/). The last command stays running; use another terminal for backend commands. Ctrl+C stops only this viewer. Without `--operations-db`, it remains read-only. Generated analyst decisions are labeled `demo-analyst`; they are an exercise, not your past incident-handling experience.

`output/portfolio/index.json` records each current case database. The advanced builder updates graph paths but keeps the primary and supplemental collections independent. Historical checked-in v2 evidence is not refreshed unless explicitly requested with `--publish-evidence`.

## 2. Install and start the native backend

```powershell
./scripts/runtime.ps1 -Action Install
./scripts/runtime.ps1 -Action Start
./scripts/runtime.ps1 -Action Status
python scripts/validate_backend.py --run-id practice-backend --out output/practice-backend.json
```

The installer verifies Loki/Grafana archives against `deployment/runtime-lock.json`. Cache, logs, PID state, data and generated credentials live under `%LOCALAPPDATA%\SOCInvestigationLab\runtime`. They are outside Git and OneDrive. A failed range transfer retains partial segments for a later resumed install. A digest mismatch aborts; do not bypass it.

Read your local `local-credentials.json` to sign in at [Grafana](http://127.0.0.1:3000/). Keep this file private. The generated password is not a GitHub token and does not get printed by the launcher. Open the provisioned **SOC Operations Lab — replayed evidence** dashboard. Enter `practice-backend` in **Replay run** and use the time range containing your replay. The default dashboard window is the last 30 minutes.

Expected case-005 replay counts: five failed logons, three process creations, one task-registration record. The process/network log panel has four records and the auth panel six. Original event timestamps remain inside each JSON record. These values describe an eleven-record constructed replay, not a live attack.

The validator also checks all 6,087 historical primary records with case-specific LogQL and source-UID pivots. Its JSON artifact includes the exact replay bounds. To review an older replay, choose its absolute time range rather than sending new data merely to make a chart look active.

## 3. Work a case through the interface

1. Select a collection. Read the report and reconstruction before choosing a verdict.
2. Use **Event timeline** to search relevant records and select their checkboxes. Search selections stay within this collection. Up to 30 records can be attached to a case.
3. Open **Case operations**, write a short title and explain why the selected evidence needs review. If no timeline records are selected, the first complete chain can supply its anchors.
4. Move the case through triage and investigation. Every action requires reasoning. Save a note when the status should stay unchanged.
5. Select later evidence in the same collection, choose **Attach selected timeline records**, and explain what the new observation changes.
6. Escalate with a clear handoff: confirmed observations, competing explanations, missing evidence and proposed next actions. Do not describe proposed containment as executed.
7. Export the reviewed revision. Keep its ZIP digest and audit anchor independently. Exporting the same revision again fails instead of overwriting the reviewed file; save a new decision only when there is an actual new review step.
8. Close only with an explicit verdict and rationale. An incomplete collection can justify **Insufficient evidence**. Absence of a full chain is not automatically expected activity.

The operations board is separate from the source casebook. Switching source collections does not change a case's fixed source ownership. Actor labels do not authenticate a person. Reload when a revision conflict reports that another update has already committed.

## 4. Hunt and inspect static script text

Use the selected database path from the index:

```powershell
python -m soclab hunt --db output/portfolio/practice-base/case-003/evidence.sqlite --out output/hunt-003.json
python -m soclab forensics --db output/portfolio/practice-base/case-003/evidence.sqlite --out output/blocks-003.json
python -m soclab decode --command-file YOUR_SAVED_COMMAND_TEXT.txt --out output/decoded-review.json
```

The last command decodes supported PowerShell host arguments as text. It never runs the decoded script. `inspect_ast.ps1` parses a saved text file and reports command/method/literal nodes; it does not dot-source it or invoke its contents. AST presence is syntax evidence, not proof that a branch or function executed.

The constructed fragment exercise and its complete/gapped/conflicting outcomes are under `output/operations/practice-operations/forensics.json`. `hunts.json` contains 48 executed queries, including an independently scoped credential supplement. No supplemental event is causally joined to the primary authentication file.

## 5. Optional private collection proof

```powershell
./scripts/collect_system.ps1 -MaxEvents 20 -OutputPath "$PWD/data/local/system-practice.jsonl"
python scripts/validate_local_collection.py data/local/system-practice.jsonl
```

This reads existing System records. It does not enable audit policies or install Sysmon. Raw JSON/XML stays under ignored `data/local`; only an aggregate collection-validation file is suitable for publishing. Review that aggregate before adding it to Git. Do not add the private source file or database.

## 6. Stop services and recover

```powershell
./scripts/runtime.ps1 -Action Stop
./scripts/runtime.ps1 -Action Start -Component Loki
./scripts/runtime.ps1 -Action Status
```

Loki alone is enough for backend validation. Stop it before starting the full pair; the launcher refuses duplicate managed processes. The core workspace works with both backend services stopped, and its Grafana link requires Grafana to be running.

| Failure | Action |
| --- | --- |
| Port conflict | Leave the existing process alone; identify it and choose whether to stop your earlier lab instance |
| Readiness failure | Newly launched processes are stopped; inspect `*.stderr.log` and `*.stdout.log` in the managed cache |
| Download interrupted | Retry Install; pinned segments resume and the final archive must still pass SHA-256 |
| Empty historical queries | Confirm the shipped config, actual source bounds and flush/index resync; run the validator rather than assuming POST success proves ingestion |
| Dashboard says no data | Match the Replay run and time range to the backend artifact; historical source time differs from replay-now display time |
| Export already exists | Keep the earlier revision intact; open its downloaded file or make a justified new review revision |
| Revision conflict | Reload the case and reassess the other saved decision |
| Audit check fails | Preserve the workspace and independently retained export; do not reseal or silently replace the chain |

The launcher checks PID and executable path before stopping a process. It does not install a service, change the firewall or register automatic startup. Source SQLite and original acquisition files remain the investigation anchors if a backend instance needs to be rebuilt.

## Reviewed export recovery in v3.0.1

Reloading a case restores its existing download link after full payload validation against the audited revision. Exporting the same revision still refuses to overwrite an existing packet. Failed writes leave no partial final ZIP. The export directory must support hard links (NTFS on the local Windows run). Follow the source-checkout workflow above; installation of a wheel alone does not supply the repository fixtures or web assets.
