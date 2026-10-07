# CASE-007: an upload, long DNS label and periodic SYNs

## The constructed evidence

This exercise contains 17 inert packet records, two fictional endpoint events and a fictional inventory. All addresses use documentation ranges. The generator does not make network connections or execute a backup. Its declared backup/monitoring intention is known to the exercise author, not discovered from the packet data.

| Observation | Supported interpretation | Unsupported conclusion |
| --- | --- | --- |
| Long varied label under `telemetry.example` | NET-001 needs context | Confirmed DNS tunnel or data theft |
| POST `/backup`, declared complete 2,480-byte body | NET-002 observes request framing and retained inert-body hash | Server accepted the upload; confidential files were stolen |
| Six TCP SYN starts every 30 seconds | NET-003 observes regular attempts | Six successful C2 sessions |
| Reordered TCP segments plus one exact retransmission | Sequence reconstruction preserves one request and records 70 repeated bytes | Retransmissions are additional distinct uploads |
| TLS ClientHello SNI `telemetry.example` | The client supplied a name in a supported hello | Authenticated server identity or decrypted application content |
| Two Sysmon event-3 candidates with the same tuple/time | Endpoint attribution is ambiguous | Select the convenient backup executable and discard the other candidate |

The body is repeated inert text. An identically named real executable or destination would need independent content/hash/ownership validation. The case deliberately supplies both `backup.exe` and `unverified.exe` candidate metadata without process-creation evidence, so neither becomes a proven origin.

## Triage

Declared context marks the client as a high-criticality finance exercise workstation. All three leads receive `review_first`. Priority is not confidence: the inventory is fictional and the observables support competing explanations. The analyzer's verdict remains `unassessed` even though the generator describes an approved backup exercise.

Preserve the capture, source hashes, frame references, endpoint events and exact context supplied at review. Request the capture vantage/time synchronization, process creation/GUID evidence, actual executable/hash/signature, file-access context, destination owner and change approval. A proxy/NAT boundary or different clock may invalidate the tuple/time association.

## Proposed response and tradeoffs

| Proposal | Owner/authority | Impact and rollback | Verification |
| --- | --- | --- | --- |
| Preserve capture and endpoint logs | Analyst/custodian; follow approved retention/data handling | Storage/privacy obligations; preserve originals | Reopen files, compare hashes and verify time coverage |
| Validate backup/monitoring authorization | Application/asset owner; obtain approval record | Review effort; correct unsupported assumptions without rewriting prior evidence | Match approved executable/content/destination and schedule |
| Consider narrow restriction if evidence/authorization warrants it | Incident lead and network owner; named approval before execution | Backup or monitoring may stop; retain prior configuration and tested restoration procedure | Confirm approved restriction, continued telemetry and service recovery |

No restriction, host isolation or account change was executed. Do not recommend blocking a shared destination solely from an entropy or periodicity threshold. Escalation should communicate the observed behavior, competing explanations, business impact, missing evidence and requested decision.

## Demonstration and counterexample

Run the validator, open the interactive report and show the three leads. Open the POST's connection to verify body hash and retransmission count. Show the two endpoint candidates and explain why approved source scope does not remove ambiguity. Change the endpoint protocol or timestamp in a fresh experiment; the pivot must disappear. Remove part of a TCP request or create a conflicting overlap; application inference must be suppressed. The original exercise stays retained rather than overwritten.
