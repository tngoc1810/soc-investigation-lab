# SOC Investigation & Detection Validation Lab

A Windows SOC portfolio built around evidence, investigation and analyst decisions. Python and SQLite preserve the source records; a local case workspace records the review; a real Loki backend supports LogQL queries. Native Grafana provides a separate replay dashboard. The core runs without Docker or virtual machines.

**Version 3.0 — evidence-to-case operations.** Five case studies, 13 detection hypotheses, a 20-scenario evaluation corpus, 48 executed hunt queries, PowerShell fragment reconstruction and native AST inspection, a revisioned analyst workflow, immutable evidence exports, and actual localhost Loki validation. This is a portfolio lab, not a commercial SIEM or a production SOC deployment.

![Native Grafana dashboard over a verified synthetic replay](evidence/operations/screenshots/03-grafana-backend.jpg)

## What can a reviewer verify?

| Skill | Concrete work | Evidence |
| --- | --- | --- |
| Log engineering | Pinned EVTX acquisition, native export, atomic ingest, source and record anchors | [Replay validation](evidence/portfolio-validation.json) |
| Backend investigation | 6,087 historical records counted on Loki; exact UID pivots; eleven synthetic records replayed for the dashboard | [Actual API responses](evidence/operations/backend-validation.json) |
| Threat hunting | Eight hypotheses executed across five cases and an independent credential supplement | [Hunt notebook](docs/HUNT_NOTEBOOK.md) and [results](evidence/operations/hunts.json) |
| Windows forensics | Session/process GUID joins; complete/gapped/conflicting 4104 reconstruction; bounded Base64 decoding; parse-only native AST | [Forensics case study](docs/POWERSHELL_FORENSICS.md) |
| Detection engineering | Transparent false positives, false negatives, context exceptions and an explicit source-scope policy | [Evaluation](evidence/advanced/evaluation.json) |
| Case handling | Triage, investigation, escalation, later evidence attachment, audit chain and checked export | [Reviewed packet](evidence/operations/reviewed-bundle/report.md) |
| Software engineering | Regression tests, local HTTP write protection, optimistic revisions, CI backend checks | [Validation record](docs/VALIDATION.md) |
| Performance analysis | Released v2 versus indexed v3, six fresh processes, identical result digest | [Measured benchmark](evidence/operations/indexing-benchmark.json) |

[The current evidence gallery](evidence/operations/README.md) includes the case-workflow screenshots, audit/export packet, actual backend responses and measured resource scope.

The important part is explaining a defensible decision from original evidence. The reports distinguish task creation, task registration and task execution; failed authentication and successful access; suspicious text and an executed operation.

## Start the complete lab

Follow the [Windows runbook](docs/RUNBOOK_V3.md) for the complete replay, case workspace and native Loki/Grafana setup. Backend runtimes are pinned to official downloads and checked by SHA-256. They run on loopback, outside OneDrive and the repository, and can be stopped independently of the core investigation tools.

The [v3 design](docs/ENGINEERING_V3.md) explains the transport, decision/audit model, resource choices and failure modes. The [Vietnamese learning path](docs/MASTERCLASS_VI.md) turns the project into exercises and an interview demonstration.

## What changed in v2?

The reconstruction and evaluation work below remains part of v3. The [v2 evidence gallery](evidence/advanced/README.md) is a historical release snapshot; current operations evidence lives in `evidence/operations`.

The new engine asks whether authentication and process activity actually belong together. A collection manifest approves exact source hashes. Nonzero logon GUIDs bind a selected process to a successful session; process GUIDs bind its activity and observed ancestry. Contradictory creation records, unavailable parents and missing telemetry remain visible rather than becoming guessed relationships.

The case explorer lets a reviewer select a process or investigation stage and open its complete original event with source hash and line. Public case 001 now has an observed four-process graph. The new constructed case has three explicitly related sources, three process nodes and one five-stage lead among 2,511 events.

Evaluation publishes all 20 scenarios, labels, confusion matrices, false positives and false negatives. On the eight held-out synthetic variants, identity reconstruction yields precision 66.7% and recall 50.0%. It avoids several username/time-only false joins but misses incomplete collections; the temporal baseline has a higher held-out F1. The project documents that trade-off instead of presenting specificity as universal superiority. These tiny related fixtures are not production accuracy measurements.

Read the [engineering design](docs/ENGINEERING_V2.md), [multi-source investigation](cases/005-multisource-chain/report.md) and [v2 evidence gallery](evidence/advanced/README.md).

## What is in the casebook?

| Case | Evidence | Main decision |
| --- | --- | --- |
| [001 — Mshta and scheduled task](cases/001-mshta-scheduled-task/report.md) | 8 public Sysmon records: process, network and file activity | Escalate the execution/persistence pattern; task execution is not established |
| [002 — Authentication burst](cases/002-authentication/report.md) | 3,561 public failed-logon records; independent 295-record credential-use supplement | Investigate the concentration; do not invent a successful logon or join unrelated incidents |
| [003 — PowerShell code or data?](cases/003-powershell-string/report.md) | 3 public script/module records | The expression appears quoted and printed; hold the execution verdict |
| [004 — Context tuning](cases/004-context-tuning/report.md) | 4 labeled, inert synthetic records | Keep one expected-context match visible while preserving review of changed-context variants |
| [005 — Session-to-process reconstruction](cases/005-multisource-chain/report.md) | 2,511 constructed events across three explicitly related sources | Escalate the five-stage lead; preserve missing-link and authorized-admin counterexamples |

The five primary cases contain 6,087 events. Including the independent supplement, the lab processes 3,867 public records and 2,515 constructed records. Counts describe separate datasets, not a single attack. The 2,500 background fixture records are search noise, not a scale benchmark.

## Run it on Windows

Python 3.11+ and Windows PowerShell are sufficient for the core. The core has no third-party Python dependencies. Run from the repository root:

~~~powershell
python -m unittest discover -s tests -v
./scripts/reproduce.ps1
python scripts/verify_portfolio.py
python scripts/build_advanced.py
python scripts/verify_advanced.py
python scripts/build_operations.py --run-id practice-01
python scripts/verify_operations.py --run-id practice-01
python -m soclab serve --operations-db output/operations/practice-01/cases.sqlite
~~~

Open http://127.0.0.1:8765. The explorer offers findings, raw-event search, process reconstruction, evaluation, a hunt notebook and case operations. Source evidence stays read-only; analyst decisions use a separate database. Omit `--operations-db` for a read-only viewer. The replay downloads four small pinned public EVTX files, checks their SHA-256 and builds fresh independent analysis bundles. Choose new run IDs for another explicit replay; exports do not silently replace reviewed evidence.

A quick synthetic-only demo also works on Linux/macOS:

~~~sh
python -m soclab ingest data/fixtures/demo.jsonl --db output/demo/evidence.sqlite
python -m soclab analyze --db output/demo/evidence.sqlite --out output/demo/run-01
~~~

Expected: 19 synthetic events and eight review findings. Attack-looking commands are inert strings. The legitimate backup example intentionally alerts.

The synthetic evaluation is portable too:

~~~sh
python -m soclab evaluate --out output/evaluation.json
~~~

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

CHAIN-001 is the thirteenth hypothesis, implemented in investigation.py. It requires matching failure/success identity, a session-linked risky process, initiated process-linked network activity and an observed descendant task-creation command. Its source scope is explicit. A chain remains a review lead; a missing chain is not a benign verdict. Use `python -m soclab investigate --db DB --scope data/scenarios/chain-collection.json --out NEW_FILE` for a standalone reconstruction.

Authentication grouping is source-scoped by default. Host, account/domain, source IP and logon type are kept separate where required; overlapping exports are not silently deduplicated. The new credential rules use ten records/accounts in five minutes with a cooldown. A 4648 event does not mean authentication failed.

Context tuning annotates an exact match rather than deleting it. The case-004 baseline has four findings; the context profile retains all four and leaves three in the review queue. A matching path/command cannot verify the script's current content, which remains an explicit blind spot.

The executable format is custom JSON. [Three separate Sigma rules and SIEM query references](queries/README.md) show portability. SQLite queries were executed, and Sigma conditions were parsed with pySigma. KQL/SPL have not been run on a live backend.

## Evidence and checks

- [Evidence gallery](evidence/README.md): genuine browser captures, query results and checksums.
- [Validation record](docs/VALIDATION.md): regression tests, actual backend queries, static inspection, workflow exports and known limits.
- [Benchmark](evidence/benchmark.json): three isolated Windows worker runs on the 3,561-event file; maximum measured process peak working set 21.86 MiB. This is not total laptop RAM or a large-scale capacity claim.
- [Data schema](docs/DATA_SCHEMA.md): source integrity, timestamp handling and field conventions.
- [V2 reconstruction benchmark](evidence/advanced/benchmark.json): fresh-process loading and reconstruction, with input and engine hashes; separate from the v1 ingest/analyze workload.
- [Triage playbook](playbooks/windows-triage.md) and [six-minute demo outline](docs/DEMO_SCRIPT.md).

The GitHub workflow runs tests/demo and the corpus evaluator on Windows/Ubuntu with Python 3.11/3.12. Windows jobs also replay public EVTX, verify graph/corpus expectations, execute the operations exercise and parse the public PowerShell text. Separate jobs parse Sigma and install a pinned native Loki binary to execute the backend assertions. Grafana browser QA and the private local System collection are recorded as local checks.

## Learn and present it

Start with [the Vietnamese first lesson](docs/START_HERE_VI.md), continue with [the teaching guide](docs/TEACHING_VI.md), and use [interview questions](docs/INTERVIEW.md) to test your understanding. [Portfolio notes](docs/PORTFOLIO_NOTES.md) explain how to describe the work accurately.

Development and analysis used Codex assistance. Dataset authors are credited in the catalog and reports. The casebook documents lab evidence; it does not claim employment, production incidents or experience operating a live commercial SIEM. Raw third-party logs, local evidence and credentials remain outside Git. Read [contribution notes](CONTRIBUTING.md) before publishing new collections.
