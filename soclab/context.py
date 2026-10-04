"""Context allowlists annotate findings; they never delete the original evidence."""

import json
from pathlib import Path

from .events import field_value


def load_context(path: Path | None) -> list[dict]:
    if path is None:
        return []
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("context file must be a list")
    for entry in entries:
        if not all(isinstance(entry.get(k), str) and entry[k].strip() for k in ("id", "rule_id", "reason", "change_reference")):
            raise ValueError("context entries require id, rule_id, reason and change_reference")
        fields = entry.get("equals")
        if not isinstance(fields, dict) or any(not isinstance(v, str) or not v for v in fields.values()):
            raise ValueError("context equals must contain exact string fields")
        if not all(key in fields for key in ("host", "event_data.User", "event_data.Image", "event_data.CommandLine", "event_data.ParentImage")):
            raise ValueError("context must constrain host, user, image, command and parent")
    return entries


def annotate(alert: dict, entries: list[dict]) -> dict:
    for entry in entries:
        if alert["rule_id"] != entry["rule_id"] or len(alert["evidence"]) != 1:
            continue
        event = alert["evidence"][0]
        if all(isinstance(field_value(event, field), str) and field_value(event, field).casefold() == value.casefold() for field, value in entry["equals"].items()):
            alert["status"] = "context_allowlisted"
            alert["context"] = {key: entry[key] for key in ("id", "reason", "change_reference")}
            alert["context"]["caution"] = "Exact context match is not verification of script content or an incident verdict."
            break
    return alert
