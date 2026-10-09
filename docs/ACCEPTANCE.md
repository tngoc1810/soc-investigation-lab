# Delivery and acceptance record

The delivered scope is the v5.0.0 single-workstation implementation: Windows evidence collection/investigation, durable synthetic backend delivery, analyst decisions/exports/recovery and offline network investigation. This record consolidates existing executed evidence. Documentation dated 9 October 2026 does not imply that historical collection, resource measurements or backend validation were rerun that day.

## Release identity

| Item | Verified reference |
| --- | --- |
| Tested code | `0032c43420d97e6bb71177aaebb76e1e89f0427d` |
| Engine fingerprint | `48eaa078592ffbeb4f70e8d8e7780a27e26484a8183f62f6f6935c69d1786837` |
| Passing CI | [37617174984](https://github.com/tngoc1810/soc-investigation-lab/actions/runs/37617174984), seven jobs |
| Release | [v5.0.0](https://github.com/tngoc1810/soc-investigation-lab/releases/tag/v5.0.0), tag target checked |
| Exercise asset | 21-file ZIP, 83,591 bytes; downloaded again and checked against internal manifest |
| Asset SHA-256 | `0100e91335609a304035fdb137f169915d1453ccc1734ab3f78f8c15f0131688` |

Later documentation/attestation commits retain the release's tested code identity. The source ZIP and exercise ZIP are different deliverables: the latter contains derived reports and inert constructed source, not original third-party captures or private host telemetry.

## Functional acceptance

| Requirement | Acceptance condition | Recorded result and evidence |
| --- | --- | --- |
| Acquisition provenance | Cataloged original files match size/hash; original objects/XML retained | Pinned EVTX replay passed; [catalog](../data/catalog.json), [replay proof](../evidence/portfolio-validation.json) |
| Native collector | Finite real channel reads retain cursors and original XML | 60 records retained privately; 21 System/39 PowerShell; [aggregates](../evidence/live/private-collection-proof.json) |
| Scope/identity | Independent sources stay independent; GUID conflicts/missing links remain visible | Public/constructed reconstruction and negative variants; [graph evaluation](../evidence/advanced/evaluation.json) |
| Event/auth detection | Fixed policy produces reviewed expected results; context annotations retain anchors | Case manifests and full regression suite; [rules](../rules/windows.json), [context case](../cases/004-context-tuning/report.md) |
| Live cross-batch detection | Failures in one batch and success in the next form a scoped AUTH-001 lead | Six authentication anchors, eight total leads; [live response](../evidence/network/ci-live-responses.json) |
| Queue durability | Actual HTTP failure retains all pending rows; a new process observes them | 19 pending after HTTP 503 and restart; [CI live response](../evidence/network/ci-live-responses.json) |
| Backend recovery | Actual Loki returns the exact persisted observation set after recovery | 19 unique UIDs and preserved payload/timestamps; [artifact verification](../evidence/network/ci-artifact-validation.json) |
| Historical backend | Counts and UID/source references match acquired evidence | Five case counts totaling 6,087; eleven selected replay records; [actual responses](../evidence/network/ci-backend-responses.json) |
| Hunting | Queries retain source/grouping boundaries and recorded outputs | Eight hunts across six separate collections; [48 executions](../evidence/operations/hunts.json) |
| Static forensics | Missing/conflicting fragments remain visible; parsing does not execute payloads | Native AST/fragment/decoded-data checks; [forensics study](POWERSHELL_FORENSICS.md) |
| Analyst workflow | Valid transitions/revisions/rationale; original evidence retained separately | Reviewed case/alert audit and browser checks; [case packet](../evidence/operations/reviewed-bundle/report.md), [browser record](../evidence/live/browser-validation.json) |
| Export/recovery | Fresh staged export, inventory/hash and audited payload checks; restored state checked | Full regression, reviewed packets and operational snapshot/restore; [live response](../evidence/network/ci-live-responses.json) |
| Packet reconstruction | Accepted format anchors match original bytes; reorder/retransmission handled; gaps not inferred through | 17-frame input, 70 repeated bytes and packet extraction; [network validation](../evidence/network/validation.json) |
| Independent protocol fields | A second decoder agrees on the selected tuple/DNS/request fields | 81 public tuples, 40 DNS messages, two complete HTTP requests; [dpkt result](../evidence/network/ci-network-responses.json) |
| Endpoint candidates | Exact approved sources required; multiple matches retained | Two candidates retained under approved scope; protocol/time/scope regressions |
| Context and response | Context bound to capture; priority distinct from verdict; proposed action has authority/impact/rollback | Three review leads, `review_first` with `unassessed`; [context case](../cases/007-network-context/report.md) |
| Publication integrity | Exact evidence file set/checksum inventory; downloaded CI/release artifacts match | [CI artifact proof](../evidence/network/ci-artifact-validation.json), [release proof](../evidence/network/release-validation.json) |

The native collector's six WIN-009 text matches remain unreviewed. Security/Sysmon were unavailable in that collection session. The acceptance result is functioning finite acquisition, not evidence of incident handling or continuous coverage on those missing channels.

## Regression and independent checks

The local suites passed 127 tests on Python 3.11.5 and 3.12.14. All four CI Windows/Linux interpreter jobs also ran 127 tests, confirmed from downloaded logs. The 27 network tests include format/precision/link variants, truncation, TCP ordering/wrap/reuse/gaps/conflicts, DNS cycles/ambiguity, HTTP framing, TLS gaps, exact scope, context validation, inert rendering/publication and download rejection.

The remaining tests cover evidence import/rollback, detector/graph/context behavior, audit/revision/state validation, localhost write controls, delivery/recovery and reviewed export integrity. [Full local output](../evidence/network/test-results.txt) and [CI steps](../evidence/network/ci-validation.json) identify the executed suites; passing counts are not an independent accuracy benchmark.

Separate CI jobs execute Sigma condition parsing, pinned native Loki and public-network/dpkt validation. Both downloaded artifact ZIPs match GitHub's digests and exact inventories. Python source hashes match tested Git blobs. The five historical UID/source-line references were additionally compared with local rebuilt evidence.

dpkt checks selected public packet tuples, DNS messages and complete single-packet HTTP requests. It verifies all constructed IPv4/transport checksums. This does not establish full TCP/application parser equivalence, acquisition authenticity or correct checksum handling for every accepted third-party packet.

## Failure acceptance

| Trigger | Required behavior | Check boundary |
| --- | --- | --- |
| Malformed event input/capacity rejection | Roll back; do not advance committed cursor | Automated regression |
| Repeated collection or record-ID reuse | Deduplicate the defined observation; retain changed content | Automated regression |
| Channel reset/retention gap | Record coverage loss; recent bootstrap does not claim historical recovery | Collector design/tests and dated native proof |
| HTTP outage/worker restart | Retain persisted payloads, queue and retries | Actual localhost HTTP 503 and fresh process |
| Uncertain delivery acknowledgment | Preserve at-least-once semantics and lease ownership | Automated regression; no exactly-once claim |
| Stale decision/audit tampering | Reject invalid write/read divergence | Automated regression and retained audited snapshots |
| Failure between case creation/linkage | Reuse verified deterministic case on retry | Injected two-database failure regression |
| Failed/occupied export | No partially published final packet; no overwrite | Regression, retained revisioned export and browser reload |
| Oversized/malformed PCAP/context | Explicit rejection before successful bundle publication | Network regression |
| TCP gap/conflicting overlap | Suppress unsupported application interpretation | Network regression |
| Wrong endpoint source/time/protocol | Do not infer an approved origin | Network regression |
| Unexpected public download redirect/content/cache | Refuse, retaining size/hash requirements | Two download regressions and fresh cataloged acquisitions |

The first v5 CI run passed six jobs and failed the network job because the official Wiki-to-GitLab upload redirect was rejected. The repair allows only the exact corresponding HTTPS upload path at each redirect, with original size/hash gates retained. [Fresh download proof](../evidence/network/download-validation.json) and the passing run preserve this history rather than hiding the failed run.

## Evaluation and resource acceptance

| Measurement | Result | Interpretation |
| --- | --- | --- |
| Graph held-out scenario evaluation | TP 2, FP 1, TN 3, FN 2; precision 66.7%, recall 50%, F1 57.1% | Eight related constructed variants; not field accuracy |
| Temporal baseline on the same holdout | F1 72.7% | Higher F1 than stricter graph policy; missing telemetry loses graph recall |
| Latest indexing comparison | Median 0.33161 s versus 0.013706 s; 24.2×; all six result digests identical | 1,200 auth records/200 incomplete candidates; not general throughput |
| Historical native-process snapshot | 145.51 MiB combined current working set | Selected idle backend/viewer processes; excludes OS/browser/collector and simultaneous peak |

These records support targeted behavior/performance statements only. No network malicious/benign accuracy score, production EPS, endurance duration, measured RTO/RPO or total-machine RAM ceiling is accepted as a delivered result.

## Acceptance exclusions

Enterprise HA/fleet ingestion, authenticated multi-user casework, RBAC, independent signing/custody, automatic retention, external threat intelligence, continuous packet capture, IPv6/PCAPNG/full application coverage and automated containment are not implemented delivery claims. KQL/SPL translations are unexecuted on their target platforms. Private native telemetry is not sent by the delivered worker.

Completeness means that the defined single-workstation scope has executable paths, explicit failure behavior, operating procedures and retained evidence. It does not mean every feature expected of a commercial SOC/EDR/SIEM product is present.

## Reverification and document changes

For a source checkout, `python -m unittest discover -s tests -v` verifies engine regressions and `python scripts/verify_checksums.py` verifies the published evidence inventory. [OPERATIONS.md](OPERATIONS.md) defines fresh paths for historical, live-backend and independent network acceptance. Reproduction changes local output/attestations and must not silently replace reviewed evidence.

The 9 October documentation consolidation replaces the historical version-by-version landing page with the integrated report, architecture, runbook and acceptance record. It does not add detections, change policy thresholds, relabel datasets, rerun old private collection or alter existing release assets. The code/source fingerprint and dated evidence remain the implementation reference.
