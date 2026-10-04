"""Export raw-event timelines separately from findings and analyst conclusions."""

import csv
import json
from pathlib import Path
from time import perf_counter

from . import __version__
from .detections import AUTH_RULE, detect, load_rules
from .correlation import BURST_RULE, EXPLICIT_RULE, credential_leads
from .context import annotate, load_context
from .store import iter_events, sources


def write_json(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def csv_cell(value):
    # Spreadsheet viewers can execute leading formula characters in evidence.
    # Raw values remain available in the DB/original_json and finding JSONL.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _analyze_into(db: Path, rules_path: Path, output: Path, *, threshold=5, window_seconds=600, cross_source=False, credential_threshold=10, credential_window=300, context_path=None) -> dict:
    started = perf_counter()
    rules = load_rules(rules_path)
    context = load_context(context_path)
    if threshold < 1 or window_seconds < 1 or credential_threshold < 2 or credential_window < 1:
        raise ValueError("threshold and window_seconds must be positive")
    if not Path(db).is_file():
        raise ValueError("database does not exist; ingest evidence first")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    # Deliberately refuse silent replacement of an earlier evidence/report bundle.
    targets = [output / name for name in ("findings.jsonl", "timeline.csv", "processes.csv", "manifest.json", "case-notes.md")]
    if any(path.exists() for path in targets):
        raise ValueError("output bundle already exists; choose a new output directory")
    counts = {}
    findings_count = 0
    status_counts = {}
    with (output / "findings.jsonl").open("w", encoding="utf-8") as stream:
        from itertools import chain
        alerts = chain(detect(iter_events(db), rules, threshold=threshold, window_seconds=window_seconds, cross_source=cross_source), credential_leads(iter_events(db), threshold=credential_threshold, window_seconds=credential_window, cross_source=cross_source))
        for alert in alerts:
            alert = annotate(alert, context)
            stream.write(json.dumps(alert, ensure_ascii=False) + "\n")
            counts[alert["rule_id"]] = counts.get(alert["rule_id"], 0) + 1
            findings_count += 1
            status_counts[alert["status"]] = status_counts.get(alert["status"], 0) + 1
    total = 0
    with (output / "timeline.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["timestamp_utc", "host", "channel", "provider", "event_id", "record_id", "event_uid", "source_sha256", "source_line", "event_data_json"])
        for event in iter_events(db):
            writer.writerow([csv_cell(event[k]) for k in ("timestamp", "host", "channel", "provider", "event_id", "record_id", "event_uid", "source_sha256", "source_line")] + [json.dumps(event["event_data"], ensure_ascii=False, sort_keys=True)])
            total += 1
    with (output / "processes.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["timestamp_utc", "host", "process_guid", "parent_process_guid", "image", "parent_image", "command_line", "event_uid", "source_sha256"])
        for event in iter_events(db, event_id=1):
            if event["channel"].casefold() != "microsoft-windows-sysmon/operational" or event["provider"].casefold() != "microsoft-windows-sysmon":
                continue
            data = event["event_data"]
            row = [event["timestamp"], event["host"], *(data.get(k, "") for k in ("ProcessGuid", "ParentProcessGuid", "Image", "ParentImage", "CommandLine")), event["event_uid"], event["source_sha256"]]
            writer.writerow([csv_cell(value) for value in row])
    # Hash actual rule bytes, and include engine configuration for reproducibility.
    import hashlib
    manifest = {
        "tool_version": __version__,
        "rules_sha256": hashlib.sha256(Path(rules_path).read_bytes()).hexdigest(),
        "sources": sources(db),
        "event_count": total,
        "finding_count": findings_count,
        "findings_by_rule": counts,
        "findings_by_status": status_counts,
        "context_sha256": hashlib.sha256(Path(context_path).read_bytes()).hexdigest() if context_path else None,
        "auth_rule": AUTH_RULE,
        "auth_threshold": threshold,
        "auth_window_seconds": window_seconds,
        "cross_source_auth_correlation": cross_source,
        "credential_rules": [BURST_RULE, EXPLICIT_RULE],
        "credential_threshold": credential_threshold,
        "credential_window_seconds": credential_window,
        "processing_seconds": round(perf_counter() - started, 6),
        "verdict": "unassessed",
        "limitations": [
            "Offline event analysis; processing duration is not live detection latency or operational MTTD.",
            "Rule matches are investigation leads and do not establish compromise.",
            "Sample counts do not establish production precision, recall or ATT&CK coverage.",
            "Input hashes identify received JSONL, not the authenticity of original host evidence.",
            "Formula-like CSV cells receive a leading apostrophe; exact raw values remain in SQLite and JSONL.",
            "Duplicate events across differently hashed sources are retained and can inflate counts when explicitly combined.",
        ],
    }
    write_json(output / "manifest.json", manifest)
    rule_lines = "\n".join(f"- {rule}: {count}" for rule, count in sorted(counts.items())) or "- No rule matches. This does not establish that activity was safe."
    review_count = status_counts.get("needs_review", 0)
    notes = f"""# Analyst case notes — DRAFT / UNASSESSED

## Intake

- Case ID: TODO
- Dataset origin and scenario: TODO
- Scope and collection gaps: TODO
- Events: {total}; total retained findings: {findings_count}; findings requiring review: {review_count}
- All timeline timestamps are UTC.

## Rule matches

{rule_lines}

## Evidence and timeline

Consult timeline.csv for all events and findings.jsonl for rule evidence.
Record event_uid, source_sha256, source_line and original record_id for each claim.
Use processes.csv to inspect GUID relationships on the same host and in the same scenario.
Do not treat a parent GUID in another unrelated source as a verified parent.

| UTC time | Evidence reference | Observed fact | Interpretation / alternative explanation |
| --- | --- | --- | --- |
| TODO | TODO | TODO | TODO |

## Competing hypotheses

- Suspicious explanation: TODO
- Legitimate explanation: TODO
- Evidence that would distinguish them: TODO

## Decision

- Verdict (suspicious / confirmed in dataset / benign / insufficient evidence): TODO
- Confidence and rationale: TODO
- Suggested severity and business context: TODO
- Escalate or close, with reason: TODO
- Missing information to request: TODO

## Response proposal

Specify actions to recommend, authority needed, evidence to preserve and recovery checks.
This offline tool has not isolated hosts, blocked IPs or changed accounts.

## Detection improvement

Describe tuning, positive and benign regression tests, and residual blind spots.

## Limitations

Distinguish observations from assumptions. Do not infer a complete attack chain from isolated samples.
"""
    (output / "case-notes.md").write_text(notes, encoding="utf-8")
    return manifest


def analyze(db: Path, rules_path: Path, output: Path, **settings) -> dict:
    """Publish an entire bundle atomically; failures leave no partial final bundle."""
    import os
    from tempfile import TemporaryDirectory
    output = Path(output)
    if output.exists():
        raise ValueError("output bundle already exists; choose a new output directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".soclab-build-", dir=output.parent) as temporary:
        staged = Path(temporary) / "bundle"
        manifest = _analyze_into(db, rules_path, staged, **settings)
        os.rename(staged, output)
    return manifest
