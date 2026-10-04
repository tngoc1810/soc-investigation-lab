# Validation record — 2026-10-04

Version 1.0 is an offline investigation casebook. These results describe the checked datasets and this implementation; they are not measurements of a production SOC. Development and initial analysis used Codex assistance.

## Executed locally

- Python 3.11.5 and 3.12.11: all 36 regression tests passed on each interpreter. Captured output is in evidence/test-results.txt.
- Synthetic demo: 19 events and 8 findings.
- Four portfolio cases: 3,576 events and 8 findings. After context annotation, 7 findings need review and 1 retains an explicit synthetic context annotation.
- Public EVTX collections, including the separate explicit-credentials supplement: 3,867 events. Every original download matched its pinned size and SHA-256 before native Windows export.
- Executed SQLite pivots: one remote-mshta process, 3,561 failed logons with no 4624 in that collection, and three PowerShell records.
- Three Sigma references parsed with pySigma 1.5.1, including their detection conditions. No SIEM backend conversion or live execution is claimed.
- A safe native PowerShell experiment produced a string-expression AST and printed inert text. It did not download or execute a payload.
- The local browser displayed all four cases, original event fields and reports. Five genuine screenshots are published in evidence/screenshots.
- Three isolated benchmark workers processed the 3,561-event authentication export. Median ingest was 1.266 seconds, median analysis 0.346 seconds, and maximum measured worker peak working set 21.86 MiB. See evidence/benchmark.json for interpreter, input hash and all runs. This is one small workload, not total laptop RAM or a scale test.

Tests cover atomic import rollback, original-event retention, physical line references, timezone and encoding behavior, source separation, provider checks, CSV formula neutralization, correlation boundaries, distinct-target counting, context constraints and finding retention. They also check read-only queries, atomic report output, HTTP host validation and unsupported request limits. Fixtures are inert. Assertions distinguish quoted PowerShell text from an executable-looking sample while admitting that a substring detector can alert on both.

Run `./scripts/reproduce.ps1 -RunId your-run` on Windows, then `python scripts/verify_portfolio.py`. The verifier checks reviewed counts, source hashes, context statuses and executed query expectations. Export byte hashes can differ across PowerShell serializer versions; pinned original EVTX checksums are the download anchors.

## GitHub validation

The bootstrap commit 01496ca5db33026badea001e6dd0485b4707d1ad passed four matrix jobs in [run 37200425663](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37200425663), when the suite contained 21 tests.

Version 1.0 commit 8f5161f176a9407feb2b02be2c10babb1d5d6851 passed all five jobs in [run 37203029300](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37203029300): 36-test runs on Windows/Ubuntu with Python 3.11/3.12, published-evidence checksums, actual public-EVTX replay on both Windows jobs, and a separate Sigma parser job. Job and step results are captured in evidence/ci-validation.json.

## Limits that remain

Precision and recall on a representative labeled population, live SIEM ingestion/latency, backend KQL/SPL behavior, arbitrary command-line obfuscation and collection authenticity are unmeasured. A task-creation lead does not prove task execution. A failure-only export does not prove that no success occurred elsewhere. Exact context matching does not verify a script's contents.

Case reports preserve these distinctions. Blank learning-log and incident templates are exercises for the learner, not missing investigation reports.
