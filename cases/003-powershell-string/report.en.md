# CASE-003 — Download-and-execute text that may only be a string

The first event looks alarming in a keyword search: it contains IEX, Net.WebClient and downloadString. Reading the whole ScriptBlockText changes the assessment. The expression is enclosed in double quotes, and the accompanying module log shows Out-Default receiving that text as its input object.

The supported conclusion is that suspicious-looking text was logged, with evidence pointing toward a literal being printed. This file does not establish a network download or execution of downloaded content. I would hold a live incident determination pending the full runspace and endpoint/network context rather than classify this as a confirmed downloader.

## Collection

Source: [pinned EVTX-to-MITRE-Attack sample](https://github.com/Yamato-Security/hayabusa-sample-evtx/tree/0845333ecb4afcf64c55c6e10946383f168f308c/EVTX-to-MITRE-Attack/TA0002-Execution/T1059.001-PowerShell). Original credit: [JPCERT/CC EVTX-to-MITRE-Attack](https://github.com/JPCERTCC/EVTX-to-MITRE-Attack).

- File: ID4103-4104-Payload download via PowerShell.evtx.
- EVTX SHA-256: 76da739520ecfb51c0bc93a5856ff45c0cd5e038114826fee30790f92fce0fca.
- Host: fs03vuln.offsec.lan.
- Three records share System time 2022-01-24 20:11:11.361955 UTC: two 4104 script-block records and one 4103 module record.
- ContextInfo reports ConsoleHost, Windows PowerShell 4.0 and OFFSEC\admmig. This is supplied historical context, not the account running this portfolio.

PowerShell script-block logging records script text in 4104 when configured. Content may include string literals, so a matching token is not proof that the corresponding operation was invoked. [Microsoft logging documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)

## Evidence review

| Source line / record | Content | Assessment |
| --- | --- | --- |
| 1 / 83421, 4104 | A double-quoted string containing IEX(New-Object Net.WebClient).downloadString(...) | WIN-009 correctly finds the text pattern; the outer quoting matters |
| 2 / 83422, 4103 | CommandInvocation(Out-Default) and InputObject equal to the same quoted expression | Supports output of text, rather than evidence of a download invocation |
| 3 / 83423, 4104 | ScriptBlockText is prompt | No download behavior shown by this record |

The URL inside the string references a PNG on a public image host. That is an observation, not a reputation decision. The historical URL was not visited or downloaded. All three records share a System timestamp; their record order is collection order, not proof of precise execution timing.

The script-block IDs differ between the two 4104 records. The 4103 ContextInfo provides a runspace and user, but the exporter does not magically associate every nearby 4104 with that identity. Full runspace/session context would make that attribution stronger.

## Detection and a safe semantic check

WIN-009 looks for download text and evaluate text in a 4104 ScriptBlockText. One record matches. This is intentionally a review lead, not an AST-aware determination of execution. Quoted examples, tutorials and authorized workflows can all match.

For a local semantic check, scripts/check_literal.ps1 parses an inert equivalent with the reserved example.invalid domain and reports its AST node types. It also prints the literal. No network expression is evaluated. The resulting transcript demonstrates why the same words can exist as data, but it does not retroactively prove every operation in the historical sample.

The safe check and detection tests retain both an executable-text fixture and the quoted-data fixture. Both still generate a lead: a regex or substring rule alone cannot settle their intent. Fragmented 4104 blocks are another limitation; a download and evaluation split across messages may evade this single-record rule.

## Decision

Hold the live incident verdict and request additional context. The evidence favors literal output, but the three-record sample is too narrow to establish the whole session was benign. Request the original script, complete 4104 message parts, relevant runspace/session logs, process creation and network telemetry. In a real ticket, explicitly state that no download or payload execution has been confirmed.

No containment is justified solely by the keyword match in this collection. If additional evidence establishes execution or another malicious action, reassess severity and scope. The main lesson is to read syntax and neighboring evidence before turning an alert name into an incident narrative.
