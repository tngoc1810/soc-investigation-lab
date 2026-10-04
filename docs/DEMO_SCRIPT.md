# Six-minute reviewer walkthrough: version 3

This is a walkthrough outline for the working lab, not a claim that the applicant has already recorded a video. Use the actual source labels and acknowledge Codex assistance. Keep the backend replay run and absolute time range visible.

## 0:00–0:40 — Scope and design

Show the evidence-to-case diagram. Explain public EVTX versus constructed case 005, SQLite source anchors, separate analyst decisions and bounded Loki replay. The native services run on loopback without a VM; the measured resource snapshot excludes the browser and Windows.

## 0:40–1:50 — Reconstruct and challenge a chain

Open case 005 Reconstruction. Trace failed logons, a matching success, session-linked mshta, its initiated connection and the observed descendant task command. Open an original event and explain its UID/source hash/physical line. Compare public case 001, which has a real observed process graph but no supplied authentication session. Distinguish task creation, registration and execution.

## 1:50–2:40 — Query the actual backend

Open the Grafana replay dashboard with the reviewed run and absolute UTC bounds. Show 5 failed logons, 3 process creations and 1 registration. Original timestamps remain in the JSON fields. Open backend-validation.json: a successful POST was insufficient, so the validator checked actual LogQL results for all five historical counts and a source-UID pivot. Explain the historical index/lookback failure and fix.

## 2:40–3:30 — Hunt and inspect a counterexample

Show the hunt notebook's four failed-logon groups totaling 3,561. The independent 4648 supplement has 294 records and 41 distinct targets but does not establish outcomes. For case 003, show the quoted script and the actual AST with no command/member-invocation nodes. Use the constructed fragment results to explain why missing/conflicting blocks remain incomplete; parsing and decoding never execute the text.

## 3:30–4:40 — Make a reviewable decision

Open Case operations. Show the triage/investigation/escalation rationale, then the later Security 4698 attachment and its narrower claim: registration observed, execution still unproven. Inspect revision 5, ten anchors, the audit anchor and reviewed packet. Explain stale-revision protection, exclusive export and why a hash chain does not authenticate an actor or stop a database owner from resealing history. Demonstrate only a meaningful new decision; do not add filler notes merely to get another export.

## 4:40–6:00 — Defend validation and limits

Show the 75-test logs, real backend responses, CI run and workload-specific indexing benchmark. Finish on Evaluation: the graph policy misses incomplete telemetry, and the weak temporal baseline has higher held-out F1. Twenty related constructed scenarios are a regression corpus, not production accuracy. Explain one wrong join, one missed chain and the next evidence you would request. Proposals to contain a host are not executed response actions.

The case reports support deeper discussion. Use INTERVIEW.md to rehearse without memorizing a tool list, and MASTERCLASS_VI.md to build your own understanding before presenting the work.
