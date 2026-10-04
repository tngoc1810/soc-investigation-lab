# CASE-005 — Does the authentication activity belong to the process chain?

This case is a constructed multi-source experiment. The Security and Sysmon records were generated together; the commands were never executed. Its purpose is to test identity joins, source boundaries and collection gaps that the independent public case studies cannot establish.

The reviewed collection contains 2,511 events: seven Security records on WS-CHAIN-LAB, four Sysmon records on that host and 2,500 inert logoff records on QUIET-WS-LAB. The background records provide search noise, not evidence of additional compromises or a large-scale performance test. Domains use example.invalid and addresses use documentation ranges.

## The question

A nearby failed-logon burst and a suspicious command are not enough to establish a shared session. I first ask whether the success matches the failed attempts, then whether the process carries the same session identity. Only after those checks do I follow process activity and ancestry.

The scope manifest explicitly approves three exact source hashes. The engine rejects an unknown source, an absent declared source or an unexplained collection scope. This approval describes how the fixture was collected; it is not authorization to execute the commands or a verdict about maliciousness.

## Evidence reconstruction

| UTC on 2026-09-03 | Source / record / line | Observation and join |
| --- | --- | --- |
| 10:00:00–04 | chain-security / 100–104 / 1–5 | Five 4625 records share host, target account/domain, source IP and network logon type |
| 10:00:05 | chain-security / 105 / 6 | 4624 matches that authentication context; nonzero LogonGuid and TargetLogonId retained |
| 10:00:06 | chain-sysmon / 106 / 1 | cmd creation carries the same domain-qualified user, LogonGuid and LogonId |
| 10:00:07 | chain-sysmon / 107 / 2 | mshta uses a remote URL; its parent GUID matches the observed cmd GUID |
| 10:00:08 | chain-sysmon / 108 / 3 | Initiated network connection carries the mshta ProcessGuid |
| 10:00:09 | chain-sysmon / 109 / 4 | schtasks /Create is an observed descendant of mshta and contains a /TR argument |
| 10:00:10 | chain-security / 110 / 7 | 4698 records a LabUpdater task; the subject logon ID matches the success context |

Every table entry can be opened as original JSON in the explorer. Source hashes and physical lines remain available after graph construction. The five-stage CHAIN-001 lead uses failures, success, risky process, initiated connection and descendant task command. The final 4698 observation is additional analyst evidence; this engine does not parse task XML or automatically bind the registered task to its later execution.

The Security and Sysmon identity checks follow the meanings documented by [Microsoft for 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Missing or zero GUIDs remain missing. Matching account names or PIDs cannot replace the stronger joins.

## What I would do with this lead

Escalate the constructed sequence for account and host verification. It combines a matching failure-to-success pattern, a session-linked risky process, initiated communication and task creation. Preserve the raw collection, scope manifest, process graph and stage references before making changes.

Ask for the source host's authentication context, account ownership, task XML and task execution telemetry, downloaded script contents and network transaction details. Verify change approval and expected administrator activity. A TCP event cannot establish what a URL returned or whether a payload ran. The fixture gives no production business impact, credential theft, lateral movement or exfiltration evidence.

## Alternative explanations and deliberate failures

Authorized testing can generate the same sequence. D12 and H05 in the corpus have known approved intent but still produce a full chain: the engine has no trusted approval context to tell them apart. These remain false positives in the published evaluation.

H03 omits the nonzero success GUID. H04 omits the descendant task process. Both have constructed attack intent, but the engine does not produce a complete chain. It retains an incomplete candidate with the missing requirements; it does not declare either host safe. The missing records are collection requests, not proof that the underlying behavior never occurred.

Overlapping exports are another problem. Exact semantic observations are counted once within this explicit scenario, while their multiple source references remain available. Changed content at the same record ID is retained separately. Conflicting process-creation records for one host/GUID prevent that node from supplying a causal join.

## Evaluation result and trade-off

The eight held-out fixture variants yield TP=2, FP=1, TN=3 and FN=2: precision 66.7%, recall 50.0%, F1 57.1%. The username/time-only baseline catches more labeled positive scenarios but makes more false joins; its held-out F1 is actually higher at 72.7%. The graph policy is therefore not a universal performance improvement. It answers a narrower, better-supported reconstruction question and pays for that specificity with missing-telemetry sensitivity.

These are scenario-level labels on a tiny, related synthetic family, not field precision/recall. The policy was fixed before measurement; development and holdout variants are public and versioned. The evaluator checks the corpus inventory and passes only event records plus source scope to the engine. It does not pass the expected label or rationale.

## Reproduce and inspect

Run the four-case replay, then scripts/build_advanced.py with a new run ID. Open case 005 and choose Reconstruction. Select a process, inspect its linked activity and open the original event. Choose Evaluation to see every success and failure rather than a success-only demo.

The expected result is three process nodes, two observed parent edges, one complete chain and four separate event/auth findings. The count of detections is not the count of incidents. The response actions above are proposals; the lab has not disabled an account or isolated a host.
