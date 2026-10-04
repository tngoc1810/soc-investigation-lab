# Presenting the project

Use the project to discuss decisions and evidence, not a list of tools. A concise description after reviewing the work:

> Developed an offline Windows security investigation lab with Python and SQLite, using public EVTX evidence and labeled synthetic tests. Documented four case studies, implemented 12 detection/correlation hypotheses, retained source references, and tested context tuning without discarding findings.

The development used Codex assistance. Say which parts you subsequently reviewed, changed and can explain independently; do not turn the project into a claim of employment or production incident handling. Before using the description, run the lab and understand the decisions.

Useful interview examples:

- A failure-only collection exposed the limits of a failure-to-success rule.
- Quoted PowerShell text showed why token matching is not execution proof.
- A task-creation command and artifact supported a persistence hypothesis without confirming execution.
- An exact context match reduced queue priority while retaining the evidence and admitting a script-content blind spot.

The reference KQL/SPL queries are not live-SIEM experience. If asked, explain that SQLite pivots were executed, Sigma rules were parsed, and backend validation remains a separate step requiring access to that platform.
