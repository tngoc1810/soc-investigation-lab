# Presenting the project

Use the project to discuss decisions and evidence, not a list of tools. A concise description after reviewing the work:

> Developed a Windows evidence-reconstruction lab with Python and SQLite, combining public EVTX case studies with explicitly scoped synthetic collections. Implemented GUID-based process/session joins, an interactive evidence graph and 13 detection hypotheses; evaluated false joins and missing-telemetry failures across 20 versioned scenarios.

The development used Codex assistance. Say which parts you subsequently reviewed, changed and can explain independently; do not turn the project into a claim of employment or production incident handling. Before using the description, run the lab and understand the decisions.

Useful interview examples:

- A failure-only collection exposed the limits of a failure-to-success rule.
- Quoted PowerShell text showed why token matching is not execution proof.
- A task-creation command and artifact supported a persistence hypothesis without confirming execution.
- An exact context match reduced queue priority while retaining the evidence and admitting a script-content blind spot.
- A stricter graph policy reduced false joins but lost recall when required telemetry was missing; the published holdout baseline had higher F1.
- Overlapping evidence retained provenance without inflating the unique failure threshold, while conflicting process records blocked causal joins.

The reference KQL/SPL queries are not live-SIEM experience. If asked, explain that SQLite pivots were executed, Sigma rules were parsed, and backend validation remains a separate step requiring access to that platform.
