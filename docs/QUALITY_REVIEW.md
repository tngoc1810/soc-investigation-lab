# Quality review — v3.0.1, 6 October 2026

The review found real faults in the v3.0.0 implementation. A passing normal replay had not exercised a committed update between two reads, a failed ZIP write, misleading event channels or an HTTP redirect. The first six adversarial tests produced five failures and one error against unchanged commit `3a5d742837cbe7694e05fd04c2d74509fb33c579`. The fixes and nine regression tests are included in v3.0.1. Development and review used Codex assistance.

## Findings and repairs

| Trigger | Observed weakness | Repair and verification |
| --- | --- | --- |
| Another SQLite connection commits between case and audit reads | A revision-1 case could accompany revision-2 audit history | Explicit read transaction; a WAL test commits the competing update at the exact boundary and verifies one coherent snapshot |
| ZIP writing fails after the final filename is opened | A partial packet occupies the reviewed revision's filename | Build and close in a temporary directory, then publish with an exclusive hard link; injected write failure leaves no final file and a retry succeeds |
| Event ID/provider match but the channel differs | Hunt queries could accept unrelated telemetry | Require the exact provider/channel pair, including Eventlog/Security for 1102; wrong-channel fixtures return no hunt rows |
| More than 100,000 graph events arrive through an iterable | Sorting/materialization consumed the entire input before enforcing the cap | Read at most the cap plus one overflow record before sorting; a generator test fails if consumption goes beyond that boundary |
| Non-ASCII CSRF header or duplicate Host headers | CSRF comparison could raise an uncaught error; ambiguous Host was accepted | Byte comparison and single exact Host/Origin/CSRF checks; real HTTP tests verify graceful 403 responses |
| Local backend responds with a redirect | The localhost origin check did not constrain the subsequent request | Disable redirects; a real second HTTP server receives no redirected request |
| Case table is changed outside the audit | The board displayed unverified state | Validate each case against its audit within one read transaction; altered state is rejected |
| Reload after exporting a reviewed case | The download link disappeared; the only visible action tried to recreate the occupied revision | Restore the existing link only after checking all five filenames and every byte against the audited snapshot; a changed report is rejected |
| A new artifact is added without updating the checksum list | Listed hashes passed while the new artifact remained unchecked | Compare the complete evidence file set to the inventory; an unlisted fixture fails verification |
| Grafana launch fails after Loki starts | A component-launch failure could leave the earlier process running | Catch launch failures, stop only newly owned matching processes and clear PID state; a native injected second-component failure confirmed cleanup |

The browser also guards case-detail requests against an older response replacing a newer selection. Selecting a case clears stale decision/export state until its detail arrives. This guard was inspected and ordinary reload/download behavior was exercised; no slow-network browser stress result is claimed.

Atomic ZIP publication requires a filesystem supporting hard links in the export directory. The local run uses NTFS. A retained checksum or audit anchor detects divergence relative to that retained copy; it does not authenticate the analyst, sign an acquisition or prevent a filesystem owner from rewriting and resealing history.

## Executed validation

Both local Python 3.11.5 and 3.12.11 passed **84 tests**, including the nine new adversarial tests. [Captured output](../evidence/quality-review/test-results.txt) and [baseline/final metadata](../evidence/quality-review/validation.json) retain the outcomes.

A fresh Windows replay rebuilt the five primary collections: **6,087 events**. The **295-record credential supplement** remained independent. Graph verification and all **48 hunt executions** passed with their reviewed counts. Fragment reconstruction, bounded decoding, native parse-only AST inspection and the operations verifier passed. The new operations exercise retained four initial decisions and nine anchors; it did not rewrite the earlier reviewed revision-5 packet.

Pinned native Loki accepted and returned the exact historical counts, UID/source-hash pivots and eleven meaningful replay-now events. The actual Grafana page showed **5 failed logons, 3 process creations and 1 task registration** within the selected replay window. [Responses and screenshots](../evidence/quality-review/README.md) document the actual run. The task-registration count does not establish task execution.

The old synthetic reviewed packet was downloaded through the browser after reloading the new viewer. Its SHA-256 remained `e6c20807292b07761bd6f220cc16d3ed9844d4c7e6ccce8a86301e41166e6bb3`. Existing decisions, ten original anchors and the independently retained audit anchor remained intact.

The repeated indexing comparison ran three fresh workers per version with 1,200 constructed authentication records and 200 candidates. Every result digest matched. Median released-v2 time was **0.332 s** and current-v3 time **0.0137 s**, approximately **24.2×** on this workload. This is a new dated measurement; the older 33.7× observation remains historical. Neither number is a general performance guarantee.

All six jobs passed in [GitHub run 37477812718](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37477812718) for code commit `7953a845e53229d3a4f447814f3f982a35e9a40e`: the four OS/interpreter combinations, Sigma parsing and independent pinned Loki replay. The downloaded backend artifact also matched the released transport hash and reviewed counts. The [v3.0.1 release](https://github.com/tngoc1810/soc-investigation-lab/releases/tag/v3.0.1) points to this tested commit.

## Reproduce the review

Run from a source checkout; the website assets and replay fixtures live in the repository:

```powershell
python -m unittest discover -s tests -p test_quality_review.py -v
python -m unittest discover -s tests -v
python scripts/verify_checksums.py
./scripts/reproduce.ps1 -RunId your-quality-base
python scripts/verify_portfolio.py
python scripts/build_advanced.py --run-id your-quality-graph
python scripts/verify_advanced.py
python scripts/build_operations.py --run-id your-quality-operations
./scripts/inspect_ast.ps1 -InputPath output/operations/your-quality-operations/public-quoted.txt -OutputPath output/operations/your-quality-operations/public-quoted.ast.json
python scripts/verify_operations.py --run-id your-quality-operations
```

For the optional backend, follow the [runbook](RUNBOOK_V3.md), then run `python scripts/validate_backend.py --run-id your-backend-check --out output/backend-validation.json`. Use fresh IDs and retain existing reviewed exports. Native runtime failure injection is documented by its aggregate [execution artifact](../evidence/quality-review/runtime-failure.json); it is not a production fault-injection framework.

## What makes this portfolio worth discussing?

The strongest part is a traceable investigation: original records, explicit collection boundaries, identity/process joins, competing explanations, executed hunts, static PowerShell analysis and an analyst decision packet. The review adds evidence that the implementation handles several failure paths, rather than relying only on a successful demo.

The public cases are small historical excerpts. The full multi-stage chain is constructed, and the 20-scenario evaluation corpus is related and tiny. Held-out graph precision remains 66.7%, recall 50%, and its F1 is lower than the temporal baseline. There is no continuous endpoint ingestion, representative alert-volume study, authenticated multi-user workflow, packet investigation or demonstrated containment. These are substantive limits, not features to imply through a screenshot.

For an internship interview, the owner should be able to reproduce one case, explain each supported link, challenge one false positive and one missed case, and say which evidence would change the verdict. The Vietnamese [learning path](MASTERCLASS_VI.md) provides those exercises. A large feature list cannot substitute for understanding those decisions.
