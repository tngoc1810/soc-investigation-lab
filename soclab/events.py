"""Validate a small, documented interchange schema without discarding evidence."""

from datetime import datetime, timezone
import hashlib
import json


def utc_timestamp(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string with an explicit timezone")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone (Z or an offset)")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def normalize_event(event: dict, source_sha256: str, line_number: int) -> dict:
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")
    for key in ("host", "channel", "provider"):
        if not isinstance(event.get(key), str) or not event[key].strip():
            raise ValueError(f"{key} must be a nonempty string")
    for key in ("event_id", "record_id"):
        if type(event.get(key)) is not int or event[key] < 0:
            raise ValueError(f"{key} must be a nonnegative integer")
    data = event.get("event_data")
    if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in data.items()):
        raise ValueError("event_data must map string names to string values")
    result = {key: event[key] for key in ("host", "channel", "provider", "event_id", "record_id")}
    result["timestamp"] = utc_timestamp(event.get("timestamp"))
    result["event_data"] = data
    result["source_sha256"] = source_sha256
    result["source_line"] = line_number
    result["event_uid"] = hashlib.sha256(f"{source_sha256}:{line_number}".encode()).hexdigest()
    # Preserve the complete input object, including optional XML and provenance.
    result["original_json"] = json.dumps(event, ensure_ascii=False, sort_keys=True)
    return result


def field_value(event: dict, field: str):
    if field.startswith("event_data."):
        return event["event_data"].get(field.split(".", 1)[1])
    return event.get(field)
