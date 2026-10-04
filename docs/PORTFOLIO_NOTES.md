# Presenting the project

Use the project to discuss decisions and evidence, not a list of tools. A concise description after reviewing the work:

> Built an evidence-to-case SOC lab using Python, SQLite and native Loki/Grafana. Reproduced five source-scoped investigations, ran 48 hunt queries, inspected PowerShell fragments and ASTs, and implemented revisioned analyst decisions with verifiable evidence exports. Validated real LogQL results and documented detection errors across 20 constructed scenarios.

The development used Codex assistance. Say which parts you subsequently reviewed, changed and can explain independently; do not turn the project into a claim of employment or production incident handling. Before using the description, run the lab and understand the decisions.

Useful interview examples:

- A failure-only collection exposed the limits of a failure-to-success rule.
- Quoted PowerShell text showed why token matching is not execution proof.
- A task-creation command and artifact supported a persistence hypothesis without confirming execution.
- An exact context match reduced queue priority while retaining the evidence and admitting a script-content blind spot.
- A stricter graph policy reduced false joins but lost recall when required telemetry was missing; the published holdout baseline had higher F1.
- Overlapping evidence retained provenance without inflating the unique failure threshold, while conflicting process records blocked causal joins.

The reference KQL/SPL queries remain unexecuted on their target platforms. SQLite hunts and native Loki/LogQL were executed; Grafana rendered the verified replay. This demonstrates a local backend workflow, not production incident handling. Explain the difference between replay-time and original timestamps, and why the baseline still has higher held-out F1.
