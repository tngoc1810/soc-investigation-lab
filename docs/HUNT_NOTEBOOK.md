# Hunt notebook: observations, counterexamples and collection gaps

I started each hunt with a question rather than an alert name. The checked-in results contain the executed SQL, query hash, source hashes and returned rows. There are eight fixed hunts across five primary cases and a separate credential-use supplement: 48 executions. Every query opens SQLite read-only and caps returned rows at 100. A count of returned groups is not a count of raw events.

The casebook's public records are historical samples. Constructed records are explicitly labeled. These hunts do not establish a prevalence baseline across an organization.

## HUNT-01: which parent/child combinations need review?

The query groups Sysmon process creations by ParentImage and Image within the selected collection. Case 001 returns four combinations; case 005 returns three. I inspect each command and pivot into the process graph before treating an unusual pair as causal evidence. A path alone can be copied or renamed, and a rare pair in an eight-record sample is not an enterprise anomaly.

The review question is practical: does the observed parent GUID support the relationship, and does the command explain why that child process appeared? In the public case, the mshta/schtasks sequence warrants escalation. That does not supply missing authentication context or prove that the task ran.

## HUNT-02: do process GUIDs connect creations to network records?

The SQL joins same-host process GUIDs, requires a creation no later than the connection, and excludes an all-zero GUID. Case 001 returns three process/network pivots; case 005 returns one. Each row includes both creation and network UIDs.

This is a hunting pivot, not the complete graph policy. The graph separately validates UUID syntax and excludes conflicting creation observations. I inspect `Initiated`, destination and time before describing the direction. No URL or payload referenced by a public log was fetched for reputation or execution testing.

## HUNT-03: which identity/IP/failure-reason groups dominate?

Case 002 has four aggregate rows whose counts sum to 3,561. The dominant row contains 3,558 failures for the same host, domain, account, source IP and SubStatus. The three other records differ in account/domain or reason. Keeping these fields separate prevents a dramatic total from concealing a different failure condition.

I would request the successful-logon and endpoint context for a live investigation. This particular primary file contains only 4625 records. The independent 4648 supplement is not used to invent a successful login in it. A failed-authentication burst is an observable; attribution and malicious intent need additional evidence.

## HUNT-04: is task registration actually collected?

Only the constructed case 005 returns a Security 4698 record. The public scheduled-task case has a process command but no 4698 in its eight records. I keep that difference explicit.

The operations exercise starts with nine chain anchors. A later browser review attaches the registration record as a tenth anchor, with its original object and source reference. This adds support for registration as recorded within the synthetic scenario. The export still does not contain proof of task execution or payload behavior.

## HUNT-05: what does the PowerShell source actually say?

Case 003 returns two 4104 records. The download-looking expression is quoted; the other block is `prompt`. Native static parsing of the first returns no command AST or member-invocation AST. The separate 4103 module record supports output of the expression as text.

I hold the download/execution verdict. Static syntax is useful, but the three-event sample does not settle the whole runspace. The [forensics study](POWERSHELL_FORENSICS.md) handles complete, missing and conflicting message parts and explains the limit of parsing an isolated block.

## HUNT-06: does explicit credential use span distinct targets?

The independent supplement has one subject/domain/server aggregate: 294 explicit-credential observations and 41 distinct domain-qualified target accounts. The query keeps source collection, subject domain and target server boundaries intact. Case 002's primary 4625 file returns no rows for this hunt.

The appropriate follow-up is to review authorization, tooling, run time and related authentication results for this supplemental collection. A 4648 record is not an authentication failure. I do not label all 294 events as failed password attempts.

## HUNT-07: is an audit-clear observation present?

The supplement contains one Security 1102 record. I retain its source and record UID and request maintenance context. This could warrant review, but the event alone is not a narrative of successful evasion. The five primary collections return no 1102 rows here; that only describes their narrow collected files.

## HUNT-08: is registry-write telemetry present?

All six collections return no event-13 rows for this hunt. I record a telemetry gap rather than a clean bill of health for registry persistence. A process-creation-only collection cannot answer whether every relevant registry value was untouched.

## Escalation standard

A useful handoff states the collection boundary, the observation, the competing explanation and the missing evidence. My constructed case handoff asks for task execution history, payload/hash and endpoint/network context. It records proposed response steps separately from actions actually performed. No endpoint containment was performed in this project.

The raw results are in [hunts.json](../evidence/operations/hunts.json). The custom interface executes the eight hunts for the selected primary case; the supplemental collection remains separately visible in the exported notebook. Threshold-based rules and these exploratory aggregates serve different purposes, so a hunt hit is not automatically another detector true positive.
