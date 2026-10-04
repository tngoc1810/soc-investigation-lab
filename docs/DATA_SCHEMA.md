# Evidence schema and reproducibility

Each UTF-8 JSONL line is one event object. Required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| timestamp | string | ISO timestamp with Z or explicit offset; System/TimeCreated for EVTX exports |
| host | nonempty string | Event Computer field, not the analyst laptop |
| channel | nonempty string | Original channel; e.g. Security or Microsoft-Windows-Sysmon/Operational |
| provider | nonempty string | Event provider; required to disambiguate overlapping IDs |
| event_id | nonnegative integer | Provider-specific event type |
| record_id | nonnegative integer | Original event record ID, not globally unique |
| event_data | object of strings | Original named EventData/UserData fields; missing values remain missing |

Optional original_xml and provenance objects survive in original_json. No commands in log text are executed. Nested UserData leaf fields are exported; duplicate field names abort export rather than silently lose evidence. Export does not resolve event message DLLs or need the source computer's software.

Ingestion computes source_sha256 over received JSONL bytes and event_uid over source_sha256 plus the physical line number. It stores the complete input object, converts the timeline timestamp to UTC microsecond precision and retains original precision in original_json/XML. Sysmon EventData.UtcTime is preserved independently; it is not silently substituted for System/TimeCreated.

Malformed nonblank lines roll back the complete import. Blank lines are skipped without renumbering evidence references. Byte-identical imports are idempotent. Record IDs shared across hosts/channels/files are preserved. Different files with overlapping evidence are retained; this is not event-level deduplication. Events at equal normalized timestamps are ordered by source hash and line; that order is not proof of causal order.

## Rule format

rules/windows.json contains a list of rules. Each has an ID, title, suggested severity, ATT&CK labels, rationale, false positives, limitations and conditions. All conditions must match. Supported operators:

- equals: exact value, case-insensitive for strings.
- contains_any: case-insensitive substring match against a list.
- endswith_any: case-insensitive suffix match against a list.

Fields are top-level schema names or event_data.NAME. Missing fields fail that condition. This deliberately small format is not Sigma, and substring matching is not a full command-line parser. Rationale and limitations must be read during triage.

AUTH-001 is implemented separately in detections.py; its full metadata and numeric parameters are recorded in each analysis manifest. It retains the latest threshold failures per active key, not every failure in the source. Evidence proves at least that threshold, not an exact total attempt count.

AUTH-002 counts failed network logons in a bounded window using host, target identity/domain, source IP, logon type and source-file scope. AUTH-003 counts distinct targets in explicit-credential events, grouped by subject identity, target domain/server, host, IP and source. Event 4648 is credential use, not proof of failed authentication or password reuse. Repeated windows use a per-key cooldown; see correlation.py and the recorded parameters.

Context annotations use the separate exact-match profile in rules/context-lab.json. Every constrained field must match. The annotation records its reason and change reference while retaining the finding and evidence. It is a queue-priority hint, not a benign verdict or script-integrity check.

Report bundles are built in a temporary sibling directory and renamed into a new destination only after every output succeeds. An existing destination is rejected. Failed analysis does not publish a partial bundle.

## Reproducibility boundary

manifest.json records tool version, rule file hash, source hashes, event count, rule counts and correlation parameters. Record the Git commit alongside results after committing your analysis. Processing duration and absolute local paths vary across runs. JSONL byte hashes may vary across PowerShell serializer versions even when the original EVTX is identical; the pinned original EVTX SHA-256 is the stable download check.

Checksums detect changes relative to an expected file. They do not independently prove the authenticity or completeness of host collection.
