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
