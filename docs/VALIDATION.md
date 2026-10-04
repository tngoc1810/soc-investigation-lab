# Validation record — 2026-10-04

This document reports local checks, not production SOC performance. The code and initial analysis were prepared with Codex assistance; the learner's independent investigation work remains a separate deliverable.

## Executed locally

- Python 3.12.11 and Python 3.11.5: all 21 unittest regression tests passed on each interpreter.
- Synthetic demo: 19 events, 8 findings, analyst verdict unassessed.
- Public EVTX: original SHA-256 matched data/catalog.json; native Windows exporter read 8 events.
- Public sample with the initial seven single-event rules: WIN-004 matched once.
- Public sample after adding WIN-008: WIN-004 and WIN-008 matched once each.
- Existing report bundles were rejected instead of overwritten.

Tests cover atomic rollback, original-evidence preservation, byte-identical reimport, timezone normalization, UTF-8/BOM handling, physical line references, record-ID collisions, provider/channel checks, CSV formula neutralization, legitimate commands that still alert, raw-event search, rule validation, correlation-window boundaries and separation of host/user/IP/domain/logon type/source. They use inert, generated records. A passing test does not mean arbitrary public EVTX data or every command-line variant is supported.

The initial rules lacked a Sysmon schtasks creation check. WIN-005 required Security 4698, which this dataset does not contain. WIN-008 adds a different observable; it does not make WIN-005 work without its required telemetry. Legitimate scripted task creation also matches and remains subject to context review.

## Not yet measured or verified

- GitHub Actions: configured for Windows/Linux with Python 3.11/3.12, not yet run remotely.
- Peak RAM and throughput on the user's laptop.
- Precision/recall against a representative labeled dataset.
- SIEM ingestion, search and live detection latency.
- Completeness of an attack chain or successful payload/task execution.
- Robustness to obfuscation, Unicode/whitespace variants and log tampering.

Do not put production metrics or a completed four-case portfolio claim on a CV based on this bootstrap release.
