# Constructed case: network logon followed by mshta and task creation

Status: escalated | severity: high | revision: 5

Source collection: case-005

This is a local portfolio investigation. Actor labels are self-declared; no response action was executed.

## Analyst decisions

### 1. create / new

2026-10-04T15:26:09.502182+00:00 · demo-analyst

Portfolio workflow exercise generated from synthetic case 005. Five failed network logons precede a matching success. The process and task sequence needs review; this is not an incident on the host running the project.

### 2. transition / triaged

2026-10-04T15:26:09.555637+00:00 · demo-analyst

High-priority review within the lab: source scope is approved, and account/domain/IP/logon type match. The successful logon alone does not attribute the initiating person or establish malicious intent.

### 3. transition / investigating

2026-10-04T15:26:09.573287+00:00 · demo-analyst

Confirmed observed links: a nonzero LogonGuid, host and domain-qualified user connect the logon to mshta; ProcessGuid connects the initiated network record; an observed parent edge reaches schtasks /Create /TR. Destination 198.51.100.20 and payload.example.invalid are lab markers, not threat-intelligence verdicts.

### 4. transition / escalated

2026-10-04T15:26:09.594817+00:00 · demo-analyst

Escalation draft: review the registered task XML and request task execution history, process termination, payload file/hash and endpoint/network evidence. The collection includes Security 4698 but does not prove task execution or payload behavior. Proposed containment would require authorization and stronger context; no containment action was performed.

### 5. attach / escalated

2026-10-04T15:29:43.709552+00:00 · demo-ui-validator

Additional evidence attached through the local workspace: Security 4698 record 110 supports task registration as recorded in the synthetic collection. This closes the registration evidence gap in the exported packet. Task execution and payload behavior remain unproven; request task execution history and endpoint evidence before a live incident verdict.

