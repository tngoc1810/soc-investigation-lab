# Project scope and authorship

SOC Investigation & Operations is a single-workstation implementation covering Windows acquisition, durable evidence/delivery, scoped detection and reconstruction, static PowerShell forensics, local analyst decisions, audited exports/recovery and offline packet investigation.

The integrated specification is the [project report](PROJECT_REPORT_VI.md), supported by [architecture](ARCHITECTURE.md), [operating procedure](OPERATIONS.md) and [acceptance record](ACCEPTANCE.md). Seven case reports retain original observations, competing explanations, assessments and missing evidence.

Development and initial analysis used Codex assistance. Public acquisition authors are credited in the catalogs and reports. Constructed inputs are labeled; native collection is a dated finite execution with private raw data. This authorship statement does not imply employment, independent manual implementation of every module or handling of a live commercial SOC incident.

Executed query paths are SQLite and native Loki/LogQL. Sigma conditions were parsed independently. KQL/SPL translations were not executed on their target platforms. Backend replay, selected resource snapshots and the small constructed evaluation corpus retain their measured scope.

The delivered scope is complete as a local system with documented operating and failure paths. Enterprise deployment, fleet coverage, authenticated multi-user workflow, containment and field detection accuracy are not represented as delivered results. Release/source identities and detailed acceptance evidence are recorded separately from later documentation changes.
