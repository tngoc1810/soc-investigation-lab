# Windows alert triage and escalation

## Intake

Identify rule, event provider/channel, host, account, source, alert time and collected time range. Check collection gaps before assuming an absent event means absent behavior. Verify original evidence and hashes; preserve the original collection.

## Investigate

1. Read the original event fields; do not rely solely on the alert title/severity.
2. Pivot by host/account/time and inspect surrounding events that did not alert.
3. For process execution, inspect Image, CommandLine, User, parent and ProcessGuid. Establish relationships within the same scenario/host. Missing parents are a gap, not proof of an untrusted origin.
4. For script activity, inspect available 4104 content. Avoid associating nearby events without process/session evidence.
5. For authentication, inspect logon type, domain, source IP and failure codes. Consider user mistakes, service credentials and shared source addresses.
6. For persistence, distinguish creation command, object registration/artifact and actual execution. Request task XML, task operational logs, service configuration or registry artifacts as appropriate.
7. Check competing legitimate explanations against inventory/change approvals where available. A lab has no production change records unless the scenario supplies them.

## Decide

- Escalate when evidence supports suspicious execution/persistence or another impactful behavior that requires additional investigation or containment authority.
- Close as benign only with adequate context and a documented reason.
- Hold/request evidence when the available events cannot support a decision; record the exact request and why it matters.
- Severity reflects asset/account/business context, not just a tool's default label.

## Escalation ticket

Include a concise assessment, affected host/account, UTC range, evidence references, process/network context, missing evidence, impact hypothesis and recommended next actions. State confidence and alternatives. Separate observed behavior from a presumed attacker objective.

## Response proposal

Recommend evidence preservation and scoped containment consistent with authority and business impact. Describe what would be isolated/disabled, why, approval/ownership, rollback and recovery verification. This repo performs none of those response actions automatically.
