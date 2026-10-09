# CASE-001 — Mshta execution followed by scheduled-task activity

**Assessment:** suspicious behavior in a public historical attack-sample dataset; escalate for further investigation in a live setting. Confidence is high in the observed process relationships and moderate in a persistence-attempt interpretation. Successful payload execution, actual recurring task execution and business impact are not established by this file.

This investigation report was prepared with Codex assistance. Its conclusions refer to the cataloged historical collection and retained analysis artifacts, not a production incident handled by the project owner.

## Scope and provenance

- Source: [Yamato Security sample repository](https://github.com/Yamato-Security/hayabusa-sample-evtx), containing samples from [SBousseaden EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).
- [Pinned original file](https://github.com/Yamato-Security/hayabusa-sample-evtx/blob/0845333ecb4afcf64c55c6e10946383f168f308c/EVTX-ATTACK-SAMPLES/Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx).
- Original EVTX SHA-256: fb5679aec77dc45a35902f705b513811dfea0f2f93c9c8503464a20270c3222f.
- Local exported JSONL SHA-256 at analysis: ed4ca4495a28b76afca39aa837dae4cfb8524e019714b494b5160d4fec7421b4. Serializer/platform changes can produce a different export byte hash; record your own manifest.
- Host: IEWIN7. Process user: IEWIN7\IEUser.
- Eight Microsoft-Windows-Sysmon events: four process creations (1), three network connections (3), one file creation (11).
- System/TimeCreated range: 2019-05-21 15:32:57.286254 UTC through 15:33:01.141798 UTC, shown at the pipeline's microsecond precision. Original 100-nanosecond strings remain in XML.
- No Security 4698, task operational logs, task XML, file content or approved-change context in this collection.

The source name describes an attack sample, but conclusions below are based on fields and artifacts, not the filename alone. This is neither the analyst's personal-machine data nor a newly observed production incident.

## Timeline and evidence

Line references below identify the JSONL export named mshta-scheduledtask.jsonl with the hash above. Record IDs belong to this provider/channel and are not global identifiers.

| System time UTC | Line / record ID | Observed evidence | Interpretation |
| --- | --- | --- | --- |
| 15:32:57.286254 | 1 / 4125 | cmd.exe command includes rundll32, JavaScript and a call to mshta with a remote URL | Script-mediated execution deserves investigation; command text alone does not prove every operation succeeded |
| 15:32:57.286254 | 2 / 4126 | rundll32.exe uses the cmd process GUID as its ParentProcessGuid | Direct parent-child evidence, despite identical displayed timestamps |
| 15:32:57.867089 | 3 / 4127 | mshta.exe targets hxxps://hotelesms[.]com/talsk.txt and has the rundll32 parent GUID | Remote content execution lead; WIN-004 matches |
| 15:32:59.389278 | 4 / 4128 | mshta process GUID is associated with TCP destination 108[.]179[.]232[.]58:443 | Network activity observed; this does not prove HTTP response content or payload execution |
| 15:32:59.769825 | 5 / 4129 | schtasks.exe, parented by mshta, requests /Create /sc MINUTE /MO 60 /TN MSOFFICE_ with an mshta remote-URL action | Attempt to establish a recurring task; WIN-008 matches after the detection improvement |
| 15:32:59.809883 | 6 / 4130 | svchost.exe creates C:\Windows\System32\Tasks\MSOFFICE_ | Artifact supports task-registration activity; content/validity/execution remain unverified |
| 15:33:00.140358 | 7 / 4131 | Same mshta process GUID connects to 105[.]73[.]6[.]112:80 | Further network activity, payload time inconsistent with System time |
| 15:33:01.141798 | 8 / 4132 | Same mshta process GUID connects to 105[.]73[.]6[.]105:80 | Further network activity, with the same timing limitation |

Historical indicators are defanged. They were not visited, executed or assigned current reputation in this analysis.

## Process relationships

All links below are on IEWIN7 within this single file:

~~~text
cmd.exe      {365abb72-1a29-5ce4-0000-001054e32101}  record 4125
  rundll32   {365abb72-1a29-5ce4-0000-00107be42101}  record 4126
    mshta    {365abb72-1a29-5ce4-0000-001079f92101}  record 4127
      schtasks {365abb72-1a2b-5ce4-0000-00102f502201} record 4129
~~~

Each child records its parent's GUID. The network events share mshta's GUID, which is stronger evidence of association than merely occurring nearby. The svchost task-file event has a different GUID; its filename and temporal proximity support an artifact relationship, but not a direct parent-child link to schtasks.

## Timestamp discrepancy

Process/file events have broadly consistent System/TimeCreated and payload UtcTime. However, network record 4128 has System time 15:32:59.3892786Z and EventData.UtcTime 06:58:39.888 on the same date. Records 4131/4132 have similar multi-hour differences. The cause is unknown from this evidence.

The pipeline uses System/TimeCreated consistently and preserves payload time separately. Process GUIDs associate the network activity with mshta, but these records cannot support precise network chronology or elapsed-time claims without clarification from the dataset author or additional evidence. Do not report this as a timezone correction, a known clock skew or measured attack duration.

## Competing hypotheses and decision

Suspicious explanation: script-mediated execution through rundll32 launches mshta to fetch remote content, then requests recurring execution via a scheduled task. Relevant ATT&CK behaviors include T1218.005 and T1053.005; the rundll32 evidence is a hunting lead for T1218.011, not a tested detection in this release.

Legitimate explanation: authorized legacy HTA automation or a security exercise could produce parts of this pattern. The remote action, script-mediated process chain and recurring task justify escalation, but legitimate-versus-unauthorized use needs approved changes, user context and artifact content. Public sample provenance establishes a training context, not a real victim compromise.

Recommended live-SOC decision: escalate with the observed chain, artifact and collection gaps. Suggested severity: high pending asset/account and business context. Request task XML and task operational history; process/script/AV telemetry; downloaded content where safely collected; change records; and network logs with trustworthy timestamps. Do not infer credential theft, exfiltration or a malware family from these eight events.

## Response proposal, not performed actions

Preserve evidence and collect the task definition, relevant file hashes, process/network state and related logs. If unauthorized execution is confirmed, recommend scoped host isolation and task removal through the responsible team, considering business impact and evidence preservation. Record rollback/recovery steps and monitor for recurrence. No endpoint response was performed by this project.

## Detection gap and improvement

Initial analysis used seven single-event rules and the authentication correlation rule. WIN-004 found mshta once, but task activity produced no alert: WIN-005 requires Security 4698 and TaskContent, absent here.

WIN-008 adds a Sysmon 1 check for schtasks.exe, a /Create argument and script-interpreter text. Reanalysis finds record 4129. This adds coverage of the observed task-creation command; it does not establish registration success and cannot cover task creation through APIs/COM.

| Check | Initial rules | After WIN-008 |
| --- | --- | --- |
| Remote mshta in this public file | 1 finding | 1 finding |
| Scripted schtasks creation in this public file | 0 findings | 1 finding |
| Synthetic schtasks /Query with script text | Not applicable | 0 findings |
| Synthetic legitimate scripted backup task creation | Not applicable | 1 review finding; context still required |

These tiny checks validate specific rule behavior, not production false-positive rate or technique-wide recall. A future tuning exercise should use a broader labeled set and retain positive regression tests.

## Reproduction and analyst pivots

Follow README's pinned download/export/ingest steps, then:

~~~powershell
python -m soclab search --db output/public-mshta/evidence.sqlite --term schtasks
python -m soclab search --db output/public-mshta/evidence.sqlite --event-id 3
python -m soclab search --db output/public-mshta/evidence.sqlite --term "{365abb72-1a29-5ce4-0000-001079f92101}"
~~~

The original_json/original_xml and analysis manifest retain the source references used for these conclusions. This historical collection remains separate from the constructed validation inputs.
