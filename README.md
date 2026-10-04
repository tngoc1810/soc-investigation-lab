# SOC Investigation & Detection Validation Lab

A Windows security investigation portfolio that runs on a small laptop. The lab turns public EVTX evidence into searchable events, detection leads and analyst decisions. It uses Python and SQLite locally, with a read-only browser interface for reviewing the work.

**Version 1.0 — complete offline casebook.** Four case studies, 12 detection hypotheses, portable rule/query references and reproducible evidence. Live SIEM backend validation is outside this release.

![Case explorer](evidence/screenshots/01-mshta-findings.jpg)

## What is in the casebook?

| Case | Evidence | Main decision |
| --- | --- | --- |
| [001 — Mshta and scheduled task](cases/001-mshta-scheduled-task/report.md) | 8 public Sysmon records: process, network and file activity | Escalate the execution/persistence pattern; task execution is not established |
| [002 — Authentication burst](cases/002-authentication/report.md) | 3,561 public failed-logon records; independent 295-record credential-use supplement | Investigate the concentration; do not invent a successful logon or join unrelated incidents |
| [003 — PowerShell code or data?](cases/003-powershell-string/report.md) | 3 public script/module records | The expression appears quoted and printed; hold the execution verdict |
| [004 — Context tuning](cases/004-context-tuning/report.md) | 4 labeled, inert synthetic records | Keep one expected-context match visible while preserving review of changed-context variants |

The primary four cases contain 3,576 events. Including the independent supplement, 3,867 public records and four synthetic records were processed. Counts describe separate datasets, not a single attack.

## Run it on Windows

Python 3.11+ and Windows PowerShell are sufficient. The core has no third-party Python dependencies. Run from the repository root:

~~~powershell
python -m unittest discover -s tests -v
./scripts/reproduce.ps1
python scripts/verify_portfolio.py
python -m soclab serve
~~~

Open http://127.0.0.1:8765. The explorer binds only to localhost and offers findings, raw-event search and analyst reports. It does not perform endpoint actions. The replay downloads four small pinned public EVTX files, checks their SHA-256, exports each source and builds fresh independent analysis bundles. Choose a new RunId for another explicit replay; evidence/report files are never silently overwritten.

A quick synthetic-only demo also works on Linux/macOS:

~~~sh
python -m soclab ingest data/fixtures/demo.jsonl --db output/demo/evidence.sqlite
python -m soclab analyze --db output/demo/evidence.sqlite --out output/demo/run-01
~~~

Expected: 19 synthetic events and eight review findings. Attack-looking commands are inert strings. The legitimate backup example intentionally alerts.

## Follow an investigation

Each finding contains source SHA-256, physical line, original record ID and event fields. The database preserves the complete input object, including original XML. All-event timelines include records that did not alert. Process inventories retain GUID relationships; the reports explain which links the evidence actually supports.

Use a case database printed by the replay script:

~~~powershell
python -m soclab search --db output/portfolio/RUN_ID/case-002/evidence.sqlite --event-id 4624
python -m soclab query auth_summary --db output/portfolio/RUN_ID/case-002/evidence.sqlite
python -m soclab query powershell_content --db output/portfolio/RUN_ID/case-003/evidence.sqlite
~~~

Replace RUN_ID with the value in output/portfolio/index.json. Searching zero 4624 records only establishes absence in that collection. Read the report before making an incident decision.

## Detection and tuning

Nine event rules cover selected PowerShell, mshta, certutil, task, registry and audit-log-clear observables. Three bounded authentication hypotheses cover failures followed by success, failure-only bursts, and multi-account explicit credential use. Conditions, telemetry requirements, false positives and blind spots live next to the rule logic.

Authentication grouping is source-scoped by default. Host, account/domain, source IP and logon type are kept separate where required; overlapping exports are not silently deduplicated. The new credential rules use ten records/accounts in five minutes with a cooldown. A 4648 event does not mean authentication failed.

Context tuning annotates an exact match rather than deleting it. The case-004 baseline has four findings; the context profile retains all four and leaves three in the review queue. A matching path/command cannot verify the script's current content, which remains an explicit blind spot.

The executable format is custom JSON. [Three separate Sigma rules and SIEM query references](queries/README.md) show portability. SQLite queries were executed, and Sigma conditions were parsed with pySigma. KQL/SPL have not been run on a live backend.

## Evidence and checks

- [Evidence gallery](evidence/README.md): genuine browser captures, query results and checksums.
- [Validation record](docs/VALIDATION.md): 36 regression tests, public EVTX replay and known limits.
- [Benchmark](evidence/benchmark.json): three isolated Windows worker runs on the 3,561-event file; maximum measured process peak working set 21.86 MiB. This is not total laptop RAM or a large-scale capacity claim.
- [Data schema](docs/DATA_SCHEMA.md): source integrity, timestamp handling and field conventions.
- [Triage playbook](playbooks/windows-triage.md) and [six-minute demo outline](docs/DEMO_SCRIPT.md).

The GitHub workflow runs tests/demo on Windows and Ubuntu with Python 3.11/3.12, replays public EVTX on the Windows runners, and parses Sigma in a separate job.

## Learn and present it

Start with [the Vietnamese first lesson](docs/START_HERE_VI.md), continue with [the teaching guide](docs/TEACHING_VI.md), and use [interview questions](docs/INTERVIEW.md) to test your understanding. [Portfolio notes](docs/PORTFOLIO_NOTES.md) explain how to describe the work accurately.

Development and analysis used Codex assistance. Dataset authors are credited in the catalog and reports. The casebook documents lab evidence; it does not claim employment, production incidents or experience operating a live commercial SIEM. Raw third-party logs, local evidence and credentials remain outside Git. Read [contribution notes](CONTRIBUTING.md) before publishing new collections.
