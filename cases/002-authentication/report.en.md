# CASE-002 — A failure burst without evidence of successful access

The useful finding here is the concentration of failed network logons, not a proven account takeover. The primary collection contains 3,561 Security 4625 records over about 163 seconds, with 3,560 targeting Administrator and one targeting a different account. Every record reports the same source address. There are no successful-logon records in this file.

I would escalate the source/account pattern for investigation, while keeping the outcome open. An account compromise claim would go beyond the collection. In a live environment, the next step would be to request successful authentication and endpoint activity around this time, including evidence outside the exported window.

## Evidence and scope

The primary dataset is DeepBlueCLI/smb-password-guessing-security.evtx, fetched from the [pinned Yamato sample collection](https://github.com/Yamato-Security/hayabusa-sample-evtx/tree/0845333ecb4afcf64c55c6e10946383f168f308c/DeepBlueCLI). Original collection credit belongs to [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI).

- EVTX SHA-256: 19202585fe053e7b0acf43458dec26957c16a2ddb6f87a21f5f85e6cba98b89c.
- Host: DESKTOP-M5SN04R. Source address: 192.168.198.149. Logon type: 3, network logon.
- System time range: 2016-09-19 16:50:06.477878–16:52:49.399674 UTC.
- Event record range: 2455–6016. All 3,561 records have Event ID 4625.
- Status/substatus distribution: 0xc0000064 once, 0xc000006a 3,558 times, 0xc0000072 twice.

Microsoft documents 4625 as failed logon activity, with the target account, source address, logon type and failure codes providing investigation context. The substatus values here distinguish an unknown user, bad passwords and disabled-account failures. [Microsoft 4625 reference](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625)

## What changed during analysis

The initial AUTH-001 rule only looked for failures followed by success. It produced no finding on this file. That result was correct for its narrow hypothesis but unhelpful for the failure-only behavior in front of me.

AUTH-002 adds a separate lead: at least ten failed network logons sharing source file, host, target account/domain, source IP and logon type within five minutes. It generates one finding for that key, then uses a five-minute cooldown to avoid one alert per attempt. The ten evidence records establish the threshold; the all-event query supplies the full counts.

| Time UTC | Record / source line | Observation |
| --- | --- | --- |
| 16:50:06.477878 | 2455 / 1 | Unknown-user failure for a different account |
| 16:50:06.513129 | 2456 / 2 | First Administrator failure in the threshold evidence |
| 16:50:06.977120 | 2465 / 11 | Tenth Administrator failure; AUTH-002 triggers |
| 16:52:49.399674 | 6016 / 3561 | Last failure in the exported collection |

The rate and target concentration are consistent with automated guessing. They do not reveal password values, the attacker's identity or whether this historical lab activity was authorized. Stale credentials or a broken client are alternatives to examine using source process information and change context.

## Independent supplement: explicit credentials across accounts

A separate file, DeepBlueCLI/password-spray.evtx, contains one Security 1102 record and 294 Security 4648 records on DESKTOP-JR78RLP in April 2019. It is not the same incident, host or date as the primary dataset.

The 4648 records cover 41 distinct target usernames in domain DOMAIN, report the same address 172.16.144.128, and span about 315 seconds. AUTH-003 generates two leads under a ten-distinct-account/five-minute threshold and cooldown. WIN-007 flags the preceding audit-log clear separately.

4648 means explicit credentials were used; it is not a failed authentication result. Calling all 294 events failed logons, or claiming the same password was sprayed, would misread this source. The rule deliberately describes a multi-account credential-use pattern and leaves the outcome unproven. [Microsoft 4648 reference](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4648)

## Decision and response proposal

Escalate the primary burst as suspicious authentication activity. In a live setting, verify the source asset and owner, ask whether any client/service was misconfigured, review lockout/disabled-account context and request 4624 plus endpoint events before and after the burst. Scope any containment to verified sources and affected assets; do not disable Administrator merely because a rule fired.

For the supplement, investigate the explicit-credential origin and audit-log clear with approved-change context. Keep its ticket/evidence separate from the 2016 burst. No addresses were blocked and no accounts were changed during this offline project.

## Reproduction

Run scripts/reproduce.ps1, then execute the auth_summary query against the primary case database. The query preserves account/domain/source/logon-type/substatus groups rather than reporting an ambiguous total.

The validation JSON records original hashes, export hashes and exact rule counts. Its measured behavior applies to these files and fixed thresholds. Distributed guessing, missing identity fields, NAT and duplicated exports remain blind spots or sources of ambiguity.
