# SOC Investigation & Detection Validation Lab

An evidence-first Windows investigation portfolio built for a SOC internship and an 8 GB laptop. The initial release processes logs offline with Python's standard library and SQLite. No VM, Docker stack or SIEM server is required for the quickstart.

**Status: working foundation, not a completed internship portfolio.** One public EVTX case has been investigated, and four learning milestones remain. Rule matches are review leads; incident verdicts are written by an analyst.

## Start here

- [Vietnamese first lesson](docs/START_HERE_VI.md)
- [Public case: mshta and scheduled-task activity](cases/001-mshta-scheduled-task/report.md)
- [Validation results and limitations](docs/VALIDATION.md)
- [Learning roadmap](docs/ROADMAP_VI.md)

## What this demonstrates

- Preserve original JSON/XML, input SHA-256 and per-event evidence references.
- Search all collected events, including events that produced no alert.
- Separate raw-event timelines, detection findings and analyst decisions.
- Correlate failed and successful logons within a bounded window and scenario scope.
- Inspect process GUID relationships and recognize missing telemetry.
- Test suspicious patterns, legitimate activity and misleading lookalikes.
- Improve a detection after finding a concrete gap in public evidence.

## Architecture

~~~mermaid
flowchart LR
    A[Public EVTX / exported evidence] --> B[Read-only PowerShell exporter]
    B --> C[JSONL with original XML and EVTX hash]
    D[Inert synthetic fixtures] --> E[Validated SQLite ingestion]
    C --> E
    E --> F[Raw event search]
    E --> G[Custom JSON rules and auth correlation]
    G --> H[Findings requiring review]
    E --> I[All-event timeline and process inventory]
    F --> J[Analyst report and escalation decision]
    H --> J
    I --> J
    J --> K[Detection tuning and regression tests]
~~~

## Quickstart

Run from the repository root with Python 3.11 or newer. No pip installation is needed.

~~~powershell
python -m unittest discover -s tests -v
python -m soclab ingest data/fixtures/demo.jsonl --db output/demo/evidence.sqlite
python -m soclab analyze --db output/demo/evidence.sqlite --out output/demo/run-01
python -m soclab search --db output/demo/evidence.sqlite --event-id 4104
~~~

Expected: **19 synthetic events and 8 review findings**. One intentionally legitimate backup command alerts, demonstrating why context review matters. The demo is a software fixture, not a captured attack or proof of operational detection quality. To reanalyze, choose another output directory; existing report bundles are not silently overwritten.

Outputs: findings.jsonl, timeline.csv, processes.csv, manifest.json and an unfinished case-notes.md. Complete the analyst notes yourself; the generator does not decide compromise.

## Reproduce the public EVTX case on Windows

~~~powershell
./scripts/fetch_sample.ps1
./scripts/export_evtx.ps1 -InputPath data/raw/public/mshta-scheduledtask.evtx -OutputPath data/raw/public/mshta-scheduledtask.jsonl
python -m soclab ingest data/raw/public/mshta-scheduledtask.jsonl --db output/public-mshta/evidence.sqlite
python -m soclab analyze --db output/public-mshta/evidence.sqlite --out output/public-mshta/run-01
~~~

Expected: **8 events; WIN-004 once and WIN-008 once**. The catalog pins the source commit, size and EVTX SHA-256. Files already exported need a new output filename. Run these PowerShell scripts directly; if local policy prevents execution, inspect the script and resolve that policy deliberately rather than disabling protections globally.

Read the [case report](cases/001-mshta-scheduled-task/report.md) for process links, a detection gap, timestamp discrepancies and limits of the conclusion. Raw third-party logs are fetched locally rather than redistributed in this repository.

## Investigate, do not just count alerts

~~~powershell
python -m soclab search --db output/public-mshta/evidence.sqlite --term schtasks
python -m soclab search --db output/public-mshta/evidence.sqlite --event-id 3
python -m soclab search --db output/demo/evidence.sqlite --user analyst.lab --event-id 4625
~~~

Authentication correlation defaults to at least five failures and a following success within 600 seconds. Matching requires the same source file, host, account, domain, source IP and logon type. Cross-file correlation is opt-in and appropriate only after verifying the files belong to the same scenario; duplicated exports may inflate counts.

## Detection catalog

| Rule | Behavior / required telemetry |
| --- | --- |
| WIN-001 | PowerShell encoded-command switch / Sysmon 1 |
| WIN-002 | PowerShell execution-policy bypass switch / Sysmon 1 |
| WIN-003 | Certutil file decoding / Sysmon 1 |
| WIN-004 | Mshta remote URL or inline script / Sysmon 1 |
| WIN-005 | Script interpreter in new task XML / Security 4698 |
| WIN-006 | Script interpreter in Run/RunOnce value / Sysmon 13 |
| WIN-007 | Security audit log cleared / Security 1102 |
| WIN-008 | Schtasks creation targeting a script interpreter / Sysmon 1 |
| AUTH-001 | Repeated failed logons then success / Security 4625 and 4624 |

These are custom JSON rules, **not Sigma rules**. Sigma/Hayabusa comparison and SIEM query practice are planned extensions. ATT&CK labels describe intended behavioral relevance, not verified coverage of an entire technique.

## Scope and data handling

This is offline evidence analysis, with no automatic containment. Processing duration is not live detection latency, operational MTTD or analyst experience in a production SOC. The pipeline streams events; exact RAM use has not been benchmarked. Authentication state is bounded by active keys/window, and text searches can scan the database.

Local evidence and generated output are ignored by Git. CSV formula-like values receive an apostrophe; exact raw values remain in SQLite/JSONL. Review case content and attribution before publishing. Never commit credentials or personal-machine logs.

See [data schema](docs/DATA_SCHEMA.md), [triage playbook](playbooks/windows-triage.md) and [contribution notes](CONTRIBUTING.md).
