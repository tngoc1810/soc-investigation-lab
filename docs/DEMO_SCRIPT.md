# Six-minute reviewer walkthrough

This script accompanies the working local explorer and captured evidence gallery. It is a walkthrough outline, not a claim that a video has already been recorded by the applicant.

## 0:00–0:40 — Goal and architecture

Explain that this is an offline Windows SOC investigation lab designed for a small laptop. The pipeline preserves original events, hashes inputs, stores them in SQLite and separates detections from analyst decisions. Identify public versus synthetic sources and the assistance used.

## 0:40–1:50 — Case 001

Open mshta findings, then the event timeline. Show the cmd/rundll32/mshta/schtasks process GUID relationships and the task-file artifact. Explain why the task command plus artifact does not confirm task execution. Show why a Security 4698 rule could not operate on a Sysmon-only file, and how WIN-008 fills the observable gap.

## 1:50–2:50 — Case 002

Show the 3,561 failed logons and the ten-record threshold evidence. Search Event ID 4624; distinguish no success in the export from no success anywhere. Explain burst versus failure-to-success detection. Mention that the 4648 supplement is another dataset and does not contain authentication outcomes.

## 2:50–3:50 — Case 003

Show the outer quoting in ScriptBlockText and the Out-Default input object. A keyword match found the text, but the evidence supports a more cautious conclusion. Explain the safe AST experiment and what extra telemetry would resolve the session's behavior.

## 3:50–4:50 — Case 004

Show the exact expected backup context and the changed user/command variants. Compare four baseline findings to three review findings plus one retained context match. Discuss the script-content blind spot and why the system never deletes the original detection.

## 4:50–6:00 — Validation and limits

Open regression results, Sigma parser results, SQLite query outputs and benchmark measurements. Explain the limited datasets, lack of live SIEM/backend validation and why processing duration is not MTTD. Close with one concrete improvement: fragment-aware script-block handling, trustworthy script-content checks or actual SIEM field mapping validation.
