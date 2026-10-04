# Validation record â€” 2026-10-04

## Version 3: current local validation

Python 3.11.5 and 3.12.11 each passed 75 tests. Captured output is in [test-results.txt](../evidence/operations/test-results.txt). Tests include static fragment/decode boundaries, evidence-preserving read-only access, bounded Windows publish retry, stale revisions, illegal closure, unknown evidence, modified audit/tail state, exclusive export checksums and real HTTP cross-origin/CSRF/body-limit handling.

A fresh native Windows replay (`release-v3-final-base` plus `release-v3-final-graph`) matched all reviewed public and synthetic counts. The five primary collections contain 6,087 events; the independent 295-record credential supplement stays separate. The fresh operations verifier matched 48 executed hunts, three fragment groups, one complete reconstruction, four initial decisions/nine anchors and every export checksum. The browser exercise then independently demonstrated a later 4698 attachment: revision 5, ten anchors, retained audit anchor and a new export.

Loki 3.7.8 actually ingested all five historical primary collections and returned their exact counts, a UID/source-hash pivot and reviewed event-type counts for eleven replay-now records. Grafana 13.2.3 returned healthy database/datasource checks and displayed 5 failed logons, 3 process creations and 1 registration on the selected synthetic replay. [Actual responses and screenshots](../evidence/operations/README.md) preserve those observations. Native parse-only inspection on PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9444 found zero command/member-invocation nodes and zero errors in the public quoted expression. Reconstructed and decoded inert fixtures each contain one command AST.

The private collector read/imported 20 existing System records and retained their original XML. Only aggregate counts and hashes are published; these records do not establish attack detection. A backend working-set snapshot includes Loki, Grafana and its Loki helper at 151.41 MiB combined. It excludes browser/OS memory and does not establish a peak or ceiling. The indexed-correlation comparison uses 1,200 constructed auth records and 200 candidates, three fresh workers per version, identical result digests: median v2 1.534 s, v3 0.046 s. This improvement is specific to that workload.

Version 3 code commit `22f1e932515c5d06172acd22bf6a9d7cd17bc02e` passed all six jobs in [run 37216927897](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37216927897): four Windows/Ubuntu Python 3.11/3.12 jobs, separate Sigma parsing and independent pinned native Loki replay. Both Windows matrix jobs also rebuilt/verified public EVTX, graph and operations artifacts. [Captured step results](../evidence/operations/ci-validation.json) and [the downloaded backend-artifact checks](../evidence/operations/ci-backend-validation.json) preserve those outcomes. The release tag points to this tested code commit; the subsequent main-branch documentation commit records CI attestations. The synthetic reviewed ZIP uploaded with the release was downloaded again and matched its recorded SHA-256. The v2 and v1 results remain historical snapshots. The held-out v2 errors and higher baseline F1 remain visible; new engineering features do not turn that small corpus into production accuracy.

## Version 2 reconstruction and evaluation

The historical v2 local suite had 55 passing regression tests, including GUID/session isolation, ambiguous process records, duplicate exports, missing telemetry, cycles, corpus-integrity validation and full original-event lookup. The new explicit-scope collection has 2,511 synthetic events, three process nodes, two parent edges, four event/auth findings and one complete five-stage review lead. Public case 001 reconstructs four observed processes and three parent edges without inventing authentication context.

Twenty checked-in scenarios separate 12 development variants from eight held-out variants. The latter produce TP=2, FP=1, TN=3 and FN=2 for the graph policy. Precision is 66.7%, recall 50.0% and F1 57.1%. The username/time ablation yields TP=4, FP=3, TN=1, FN=0 and a higher F1 of 72.7%. All outcomes are published. This is a small synthetic regression corpus, not production accuracy.

The browser was checked for stage-to-original-record lookup, process selection, public graph reconstruction and evaluation results. Three fresh Python 3.11 workers measured loading/reconstruction of the actual 2,511-event collection; details and input hashes are in evidence/advanced/benchmark.json. No large-scale throughput or live SOC latency is claimed. Version 2 code commit c213b0734507c4c391baa32c8cc0827f26a6ebfd passed all five jobs in [run 37208393024](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37208393024): 55 tests, evidence checksums and corpus evaluation on Windows/Ubuntu with Python 3.11/3.12; public-EVTX plus advanced replay on both Windows jobs; separate Sigma parsing. Captured step results are in evidence/advanced/ci-validation.json.

The v1 measurements below remain historical snapshots. They use another input and measure ingest/analyze rather than v2 graph reconstruction.

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

Precision and recall on a representative labeled population, continuous endpoint-to-backend latency, KQL/SPL behavior, arbitrary command-line obfuscation and collection authenticity remain unmeasured. V3 validates bounded replay ingestion and actual Loki/LogQL responses, not continuous endpoint monitoring. A task-creation lead does not prove task execution. A failure-only export does not prove that no success occurred elsewhere. Exact context matching does not verify a script's contents.

Case reports preserve these distinctions. Blank learning-log and incident templates are exercises for the learner, not missing investigation reports.
