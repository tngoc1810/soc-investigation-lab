# Questions to defend the project

1. Why does an encoded PowerShell command need investigation rather than automatic conviction?
2. What differentiates an event, an alert, an incident and an analyst verdict?
3. How do provider and channel prevent misuse of an Event ID?
4. Why use ProcessGuid instead of PID alone? What if the parent event is absent?
5. What does a task-creation command prove? What additional evidence confirms registration and execution?
6. How did the public sample reveal a telemetry gap in WIN-005?
7. Why are the network payload timestamps in case 001 a problem? Which time did you use and what uncertainty remains?
8. Why must authentication correlation include host, account, domain, source IP and logon type?
9. How can NAT, stale credentials and duplicated exports mislead correlation?
10. What happens if one line of evidence is malformed? What is the tradeoff of atomic import?
11. Which legitimate commands still match your rules, and how would you verify their context?
12. Which variants evade these substring-based detections?
13. How would you measure precision, recall and latency, and why have you not claimed those production metrics?
14. What can your offline lab demonstrate, and which skills require SIEM/live SOC practice?
15. Which parts did you independently investigate or implement, and which used Codex/community assistance?
16. Why did the failure-only collection trigger AUTH-002 but not AUTH-001?
17. Why do 41 target accounts in 4648 records suggest a lead rather than prove password spraying?
18. What changed your interpretation of the quoted PowerShell expression, and what is still unknown?
19. How can an attacker fit the exact backup context without changing the command line?
20. What does the worker peak working set measure, and why is it not a guarantee about total RAM or a live SOC workload?
21. What specifically authorizes two source files to participate in the same investigation?
22. How do zero logon GUIDs, repeated process GUIDs and missing parents affect your joins?
23. Why does your held-out graph detector have lower F1 than the temporal baseline?
24. Why are scenario-level synthetic labels insufficient to claim production precision/recall?
25. How do exact overlapping observations differ from changed content at the same record ID?

26. Why did an accepted historical Loki push initially return no query results? How did you verify the fix?
27. Why keep GUIDs, account names and command lines out of stream labels?
28. What is at-least-once delivery, and which failures would require a durable queue?
29. How do replay timestamps differ from original timestamps? Why filter one replay run?
30. What does a failed revision check protect? Does the actor field authenticate anyone?
31. Which audit edits are detected, and what can a database owner still rewrite?
32. Why export a reviewed revision exclusively and retain its anchor independently?
33. Why leave missing/conflicting script fragments incomplete? Does a command AST establish execution?
34. How does the source database remain unchanged during reads? What does the Windows rename retry preserve?
35. What exactly was included in the backend RAM snapshot, and why is it not a ceiling?
