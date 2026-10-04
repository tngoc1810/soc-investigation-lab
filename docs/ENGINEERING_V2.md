# Reconstruction and evaluation design

This document preserves the v2 design and measurements. [Version 3](ENGINEERING_V3.md) adds backend replay, static forensics, case operations and indexed correlation; historical v2 evidence remains unchanged.

The v2 engine addresses two mistakes: merging unrelated evidence because names are similar, and treating a detection demonstration as proof of general accuracy. It reconstructs selected relationships and publishes failures against a reviewed corpus.

## Collection boundary

Each investigation supplies a scenario ID, collection reason and exact approved JSONL source hashes. The observed set must equal that scope. Public cases remain independent. The three generated case-005 sources may join only because their common construction is declared explicitly. Sources outside that set fail the run.

SQLite preserves every imported row. The investigation layer deduplicates exact semantic observations inside its scope using timestamp, host, provider/channel, event ID, record ID and fields. All duplicate source references remain on graph nodes. This does not establish universal event identity, repair tampering or authenticate collection. Changed fields remain separate observations.

## Graph invariants

- A process node requires Sysmon Operational event 1 and a valid nonzero ProcessGuid.
- A host/GUID with conflicting creation records is ambiguous and excluded from causal joins.
- An edge requires a parent observed on the same host, an exact parent GUID and nondecreasing creation times. Cycles are rejected. PID/name proximity is insufficient.
- Process activity requires the same host/GUID and a timestamp no earlier than the observed process creation. Older/orphaned activity becomes a diagnostic.
- A missing parent is retained as a diagnostic; the graph does not invent its executable.

The UI displays up to 100 process nodes and 40 diagnostics to keep interaction manageable. The complete artifact retains all entries. Analysis rejects scopes above 100,000 events; this is an explicit guard, not a capacity claim. Event time is System/TimeCreated; original field timestamps remain available. Clock skew can prevent valid relationships and needs analyst treatment.

## CHAIN-001 policy

Five failures in 600 seconds followed by success must share host, target account/domain, source IP and logon type. Success must be type 3 or 10. A risky Sysmon process within 900 seconds must share host, nonzero LogonGuid and domain-qualified user. LogonId is checked when present in both records, using exact case-insensitive text; alternate hex representations can therefore cause misses.

The risky process must have an initiated Sysmon 3 connection and an observed descendant schtasks creation command inside that 900-second window. The process marker recognizes selected mshta remote/inline arguments and PowerShell encoded-command host arguments. PowerShell inspection stops at -File/-Command; this is conservative token handling, not a complete Windows or PowerShell parser. Abbreviations and obfuscation outside the supported markers can evade it.

A complete chain is a review lead. Partial authentication candidates list collection requirements rather than receiving a benign verdict. 4698 presence appears in telemetry coverage, but task registration/execution is not part of the automated chain proof. The descendant command does not require the same security token: ancestry establishes parent/child creation, not permission inheritance.

## Evaluation protocol

The checked-in manifest covers 20 inert scenarios with fixed intent labels, source construction and SHA-256. Twelve are development variants, eight are held-out variants. The evaluator verifies those files, checks split/identity consistency and sends only their events to the engine. Thresholds are fixed; no score maximization or holdout tuning is performed.

Labels describe constructed need for review, including attack intent whose required telemetry has been omitted. Thus missing-telemetry scenarios are honest false negatives for complete-chain detection. They are not reclassified as benign to improve recall. Approved administrative scenarios are known benign to the experiment author, but their approval is not a feature supplied to the detector.

The baseline is a deliberately weak username/time-only ablation, not the released v1 authentication engine. It omits identity and ancestry checks. Both confusion matrices, all rows and missing-stage explanations are published. Related fixture templates, eight holdout samples and public labels make this an engineering regression corpus, not an independent research benchmark or production-quality estimate. The held-out baseline has higher F1 than the graph policy; specificity alone does not improve every metric.

Evaluation normalizes virtual channel arrays from each checked-in scenario. Its source hashes cover their canonical sorted-key JSON serialization, and source-line values are positions within those virtual channels. They are not EVTX hashes or physical lines in the pretty-printed scenario file. The corpus inventory separately hashes the actual scenario-file bytes. The investigated SQLite cases use physical JSONL line references and imported-file hashes as before.

Some variants intentionally reuse observable events: approved-admin intent ambiguity and reordered/duplicate metamorphic tests. Split separation therefore does not imply feature-level independence. The current implementation also scans the collection for each successful authentication candidate; success-heavy workloads can approach quadratic work. Only the published small collection was timed. Indexing session/candidate lookups and evaluating independent collections are concrete follow-on engineering tasks.

## API and UI boundary

The explorer remains localhost-only and read-only. Original-record lookup uses a parameterized query on a SQLite mode=ro connection that is explicitly closed after each request. The case ID selects a configured database; a record UID cannot request another case's event. Commands/XML are rendered as text. No IOC is resolved and no historical command is executed.

The added regressions cover incorrect GUID joins, missing fields, duplicate inflation, contradictory creation records, cycle/order checks, corpus integrity and the original-event API. Windows testing caught a connection-lifetime issue that left database handles open after lookup; explicit connection closing corrected it.

## Sources

[Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) describes process GUIDs and process-associated activity. [4624 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) documents successful logon fields and correlation context. These explain field meanings; they do not certify this engine's accuracy.
